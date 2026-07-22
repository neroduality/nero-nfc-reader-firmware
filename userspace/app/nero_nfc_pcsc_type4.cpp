// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2026 Nero Duality, LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "nero_nfc_null.h"
#include "nero_nfc_pcsc_internal.hpp"
#include "nero_nfc_ndef.hpp"
#include "nero_nfc_pcsc_tag_details.hpp"
#include "nfc_pcsc_contactless.h"
#include "nfc_tag_geometry_limits.h"
#include "nfc_tag_info.h"

#include <algorithm>
#include <iterator>
#include <limits>
#include <string_view>
#include <utility>

namespace nero_nfc::pcsc_internal {

bool Type4NdefLenFitsShortBinary(std::size_t ndef_len) {
  return ndef_len <=
         (static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()) -
          1u);
}
#ifdef NERO_USERSPACE_HAVE_PCSC

bool SelectNdefApp(PcscCard& card, std::string& err) {
  for (std::uint8_t i = 0u; i < NFC_PCSC_NDEF_APP_SELECT_VARIANT_COUNT; ++i) {
    nfc_pcsc_ndef_app_select_variant_t variant{};
    std::vector<std::uint8_t> capdu(
        static_cast<std::size_t>(NFC_ISO7816_SELECT_AID_MAX));
    std::vector<std::uint8_t> response;
    std::uint16_t apdu_len = 0u;

    if (!nfc_pcsc_ndef_app_select_variant(i, &variant)) {
      break;
    }
    if (!nfc_pcsc_build_select_aid_apdu(
            variant.aid, variant.aid_len, variant.p2, variant.add_le_00,
            capdu.data(), static_cast<std::uint16_t>(capdu.size()),
            &apdu_len)) {
      continue;
    }
    capdu.resize(apdu_len);
    if (TransmitOk(card, capdu, response, err)) {
      return true;
    }
  }
  if (err.empty()) {
    err = "NDEF application select failed";
  }
  return false;
}

static bool ReadBinaryExact(PcscCard& card, std::uint16_t offset,
                            std::uint8_t len, std::vector<std::uint8_t>& data,
                            std::string& err) {
  std::vector<std::uint8_t> rapdu;

  data.clear();
  if (!card.Transmit(
          {static_cast<std::uint8_t>(NFC_ISO7816_CLA_ISO),
           static_cast<std::uint8_t>(NFC_ISO7816_INS_READ_BINARY),
           static_cast<std::uint8_t>(offset >>
                                     NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES),
           static_cast<std::uint8_t>(offset & NFC_BYTE_VALUE_MAX), len},
          rapdu, err)) {
    return false;
  }
  if (!StatusOk(rapdu)) {
    err = "Type 4 READ BINARY returned non-success status";
    return false;
  }
  data = WithoutStatus(rapdu);
  if (data.size() != static_cast<std::size_t>(len)) {
    err =
        "Type 4 READ BINARY length mismatch: expected=" + std::to_string(len) +
        " actual=" + std::to_string(data.size()) + " RAPDU=" + HexBytes(rapdu);
    return false;
  }
  err.clear();
  return true;
}

bool ReadNdefFile(PcscCard& card, PcscTagSnapshot& tag,
                  std::vector<std::uint8_t>* cc_out, std::string& err) {
  if (!SelectNdefApp(card, err) ||
      !SelectFile(card,
                  static_cast<std::uint8_t>(NFC_PCSC_T4_CC_FILE_ID >>
                                            NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES),
                  static_cast<std::uint8_t>(NFC_PCSC_T4_CC_FILE_ID &
                                            NFC_BYTE_VALUE_MAX),
                  err)) {
    return false;
  }
  std::vector<std::uint8_t> cc;
  if (!ReadBinaryExact(card, 0u,
                       static_cast<std::uint8_t>(NFC_PCSC_T4_CC_FILE_LEN), cc,
                       err)) {
    return false;
  }
  auto cc_len = static_cast<std::uint16_t>(
      (static_cast<unsigned>(cc[0]) << NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES) |
      cc[1]);
  if (cc_len < static_cast<std::uint16_t>(NFC_PCSC_T4_CC_FILE_LEN)) {
    err = "invalid Type 4 CC length";
    return false;
  }
  if (cc_len > cc.size()) {
    if (cc_len > static_cast<std::uint16_t>(NFC_BYTE_VALUE_MAX)) {
      err = "Type 4 CC file too large for short READ BINARY";
      return false;
    }
    if (!ReadBinaryExact(card, 0u, static_cast<std::uint8_t>(cc_len), cc,
                         err)) {
      return false;
    }
  }
  if (cc_out != NERO_NFC_NULL) {
    *cc_out = cc;
  }
  nfc_tag_type4_info_t type4_info{};
  if (!nfc_tag_type4_apply_cc(&type4_info, cc.data(),
                              static_cast<std::uint8_t>(cc.size()))) {
    err = "invalid Type 4 CC file";
    return false;
  }
  if (!nfc_pcsc_type4_max_message_size(type4_info.max_ndef_size,
                                       &tag.max_ndef_size_)) {
    err = "Type 4 Max NDEF file size is too small for NLEN";
    return false;
  }
  tag.read_access_open_ = type4_info.read_access_open;
  tag.write_access_open_ = type4_info.write_access_open;
  if (tag.tag_type_.empty()) {
    tag.tag_type_ = "NFC Forum Type 4-compatible NDEF file";
  }
  if (!type4_info.read_access_open) {
    err = "Type 4 tag reports read access restricted";
    return false;
  }
  if (!SelectFile(card, type4_info.ndef_file_id[0], type4_info.ndef_file_id[1],
                  err)) {
    return false;
  }
  if (type4_info.mle < static_cast<std::uint16_t>(NFC_PCSC_T4_NLEN_LEN)) {
    err = "Type 4 tag MLe is too small for NDEF length read";
    return false;
  }
  std::vector<std::uint8_t> len_bytes;
  if (!ReadBinaryExact(card, 0u,
                       static_cast<std::uint8_t>(NFC_PCSC_T4_NLEN_LEN),
                       len_bytes, err)) {
    return false;
  }
  auto ndef_len =
      static_cast<std::uint16_t>((static_cast<unsigned>(len_bytes[0])
                                  << NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES) |
                                 len_bytes[1]);
  if (ndef_len > tag.max_ndef_size_) {
    err = "Type 4 NDEF length exceeds CC Max NDEF message size";
    return false;
  }
  if (!Type4NdefLenFitsShortBinary(ndef_len)) {
    err = "Type 4 NDEF length exceeds short READ BINARY address range";
    return false;
  }
  tag.ndef_message_.clear();
  const std::uint16_t kMleCap = type4_info.mle;
  const std::uint16_t kChunkMax = std::min<std::uint16_t>(
      kMleCap, static_cast<std::uint16_t>(NFC_PCSC_T4_READ_BINARY_DATA_MAX));
  for (std::uint16_t done = 0; done < ndef_len;) {
    auto remaining = static_cast<std::uint16_t>(ndef_len - done);
    auto chunk = static_cast<std::uint8_t>(
        std::min<std::uint16_t>(remaining, kChunkMax));
    std::vector<std::uint8_t> data;
    if (!ReadBinaryExact(
            card, static_cast<std::uint16_t>(NFC_PCSC_T4_NLEN_LEN + done),
            chunk, data, err)) {
      return false;
    }
    tag.ndef_message_.insert(tag.ndef_message_.end(), data.begin(), data.end());
    done = static_cast<std::uint16_t>(done + data.size());
  }
  tag.records_ = ParseNdefRecords(tag.ndef_message_);
  return true;
}

bool ShouldAttemptType4NdefIo(const PcscTagSnapshot& tag,
                              const std::vector<std::uint8_t>& type4_cc) {
  return !type4_cc.empty() ||
         (!HasPcscStorageHint(tag) && IsType4Compatible(tag));
}

void NotePassiveType4Probe(PcscTagSnapshot& tag) {
  if (tag.tag_type_.find("Type 4") == std::string::npos) {
    return;
  }
  AppendDetailLine(
      tag, "Application probing: no NFC Forum Type 4 NDEF app/file found");
}

namespace {

enum class NdefTransactionStep {
  kInspect,
  kPrepare,
  kWrite,
  kFinalize,
  kVerify,
};

constexpr std::string_view NdefTransactionStepName(NdefTransactionStep step) {
  switch (step) {
    case NdefTransactionStep::kInspect:
      return "inspect";
    case NdefTransactionStep::kPrepare:
      return "prepare";
    case NdefTransactionStep::kWrite:
      return "write";
    case NdefTransactionStep::kFinalize:
      return "finalize";
    case NdefTransactionStep::kVerify:
      return "verify";
  }
  return "unknown";
}

std::string Type4TransactionError(NdefTransactionStep step,
                                  std::string_view detail) {
  return std::string("Type 4 ") + std::string(NdefTransactionStepName(step)) +
         ": " + std::string(detail);
}

struct PcscWriteContext {
  PcscTagSnapshot tag_;
  std::vector<std::uint8_t> uid_;
};

struct PcscWritePlan {
  bool (*matches_)(const PcscWriteContext& ctx);
  bool (*write_)(PcscCard& card, const PcscWriteContext& ctx,
                 const std::vector<std::uint8_t>& ndef, std::string& err);
};

void CollectPcscWriteContext(PcscCard& card, PcscWriteContext& ctx,
                             std::string& err) {
  std::vector<std::uint8_t> atr;

  ctx = {};
  if (card.Status(atr, err)) {
    ctx.tag_.atr_hex_ = HexBytes(atr);
    ApplyStorageAtrHint(ctx.tag_);
  } else {
    err.clear();
  }
  if (IsPcscStorageType5(ctx.tag_)) {
    ctx.uid_ = NormalizeType5Uid(TryGetDataBytes(
        card, static_cast<std::uint8_t>(NFC_PCSC_GET_DATA_UID),
        static_cast<std::uint8_t>(NFC_ISO7816_GET_DATA_P2_DEFAULT)));
  }
  err.clear();
}

bool MatchesType2Storage(const PcscWriteContext& ctx) {
  return IsPcscStorageType2(ctx.tag_);
}

bool MatchesType5Storage(const PcscWriteContext& ctx) {
  return IsPcscStorageType5(ctx.tag_);
}

bool MatchesType4File(const PcscWriteContext& ctx) {
  return !HasPcscStorageHint(ctx.tag_);
}

bool WriteType2StoragePlan(PcscCard& card, const PcscWriteContext& ctx,
                           const std::vector<std::uint8_t>& ndef,
                           std::string& err) {
  (void)ctx;
  if (!WriteType2StorageNdef(card, ndef, err)) {
    err = "cannot write Type 2 storage NDEF TLV: " + err;
    return false;
  }
  return true;
}

bool WriteType5StoragePlan(PcscCard& card, const PcscWriteContext& ctx,
                           const std::vector<std::uint8_t>& ndef,
                           std::string& err) {
  if (!WriteType5StorageNdef(card, ctx.uid_, ndef, err)) {
    err = "cannot write Type 5 storage NDEF TLV: " + err;
    return false;
  }
  return true;
}

}  // namespace

static bool WriteType4NdefFile(PcscCard& card,
                               const std::vector<std::uint8_t>& ndef,
                               std::string& err) {
  PcscTagSnapshot tag;
  std::vector<std::uint8_t> cc;
  if (!ReadNdefFile(card, tag, &cc, err)) {
    err = Type4TransactionError(
        NdefTransactionStep::kInspect,
        std::string("cannot select/read writable NDEF file: ") + err);
    return false;
  }
  nfc_tag_type4_info_t type4_info{};
  if (!nfc_tag_type4_apply_cc(&type4_info, cc.data(),
                              static_cast<std::uint8_t>(cc.size()))) {
    err = Type4TransactionError(NdefTransactionStep::kInspect,
                                "invalid Type 4 CC file");
    return false;
  }
  std::uint16_t mlc = NFC_PCSC_T4_UPDATE_BINARY_DATA_MAX;
  if (type4_info.mlc < static_cast<std::uint16_t>(NFC_PCSC_T4_NLEN_LEN)) {
    err = "Type 4 tag MLc is too small for NDEF writes";
    return false;
  }
  mlc = std::min<std::uint16_t>(type4_info.mlc,
                                NFC_PCSC_T4_UPDATE_BINARY_DATA_MAX);
  if (!tag.write_access_open_) {
    err = "tag reports write access restricted";
    return false;
  }
  if (ndef.size() > tag.max_ndef_size_) {
    err = "NDEF payload exceeds tag Max NDEF message size";
    return false;
  }
  if (!Type4NdefLenFitsShortBinary(ndef.size())) {
    err = "NDEF payload exceeds short UPDATE BINARY address range";
    return false;
  }
  if (!UpdateBinary(card, 0u,
                    {static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS),
                     static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS)},
                    err)) {
    err = Type4TransactionError(NdefTransactionStep::kPrepare,
                                std::string("cannot clear NLEN: ") + err);
    return false;
  }
  for (std::uint16_t done = 0; done < ndef.size();) {
    auto remaining = static_cast<std::uint16_t>(ndef.size() - done);
    std::uint16_t chunk_len = std::min<std::uint16_t>(remaining, mlc);
    std::vector<std::uint8_t> chunk(ndef.begin() + done,
                                    ndef.begin() + done + chunk_len);
    if (!UpdateBinary(card,
                      static_cast<std::uint16_t>(NFC_PCSC_T4_NLEN_LEN + done),
                      chunk, err)) {
      err = Type4TransactionError(
          NdefTransactionStep::kWrite,
          std::string("cannot write NDEF file chunk: ").append(err));
      return false;
    }
    done = static_cast<std::uint16_t>(done + chunk_len);
  }
  if (!UpdateBinary(
          card, 0u,
          {static_cast<std::uint8_t>(
               (ndef.size() >> NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES) &
               static_cast<std::size_t>(NFC_BYTE_VALUE_MAX)),
           static_cast<std::uint8_t>(
               ndef.size() & static_cast<std::size_t>(NFC_BYTE_VALUE_MAX))},
          err)) {
    err = Type4TransactionError(NdefTransactionStep::kFinalize,
                                std::string("cannot restore NLEN: ") + err);
    return false;
  }
  {
    PcscTagSnapshot verify;
    std::vector<std::uint8_t> verify_cc;
    if (!ReadNdefFile(card, verify, &verify_cc, err)) {
      err = Type4TransactionError(
          NdefTransactionStep::kVerify,
          std::string("cannot verify NDEF write: ") + err);
      return false;
    }
    if (verify.ndef_message_ != ndef) {
      err = Type4TransactionError(NdefTransactionStep::kVerify,
                                  "NDEF write verification failed");
      return false;
    }
  }
  return true;
}

static bool WriteType4FilePlan(PcscCard& card, const PcscWriteContext& ctx,
                               const std::vector<std::uint8_t>& ndef,
                               std::string& err) {
  (void)ctx;
  return WriteType4NdefFile(card, ndef, err);
}

bool WriteNdefFile(PcscCard& card, const std::vector<std::uint8_t>& ndef,
                   std::string& err) {
  PcscWriteContext ctx;
  const PcscWritePlan kPlans[] = {
      {.matches_ = MatchesType2Storage, .write_ = WriteType2StoragePlan},
      {.matches_ = MatchesType5Storage, .write_ = WriteType5StoragePlan},
      {.matches_ = MatchesType4File, .write_ = WriteType4FilePlan},
  };

  CollectPcscWriteContext(card, ctx, err);
  const auto* const kSelected = std::ranges::find_if(
      kPlans, [&](const PcscWritePlan& plan) { return plan.matches_(ctx); });
  if (kSelected != std::end(kPlans)) {
    return kSelected->write_(card, ctx, ndef, err);
  }
  err = "unsupported PC/SC tag type for NDEF write";
  return false;
}

#endif  // NERO_USERSPACE_HAVE_PCSC

}  // namespace nero_nfc::pcsc_internal
