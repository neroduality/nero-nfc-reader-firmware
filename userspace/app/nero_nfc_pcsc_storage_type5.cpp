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

#include "nero_nfc_hex.hpp"
#include "nero_nfc_limits.h"
#include "nero_nfc_ndef.hpp"
#include "nero_nfc_null.h"
#include "nero_nfc_pcsc_internal.hpp"
#include "nfc_pcsc_contactless.h"
#include "nfc_storage_ndef.h"
#include "nfc_tag_geometry_limits.h"
#include "nfc_tag_info.h"

#include <algorithm>
#include <iterator>
#include <limits>
#include <ranges>
#include <sstream>
#include <utility>

namespace nero_nfc::pcsc_internal {

namespace {

constexpr std::size_t kType5TransparentFlagsBytes = 1u;
constexpr std::size_t kType5TransparentFlagsAndBlockBytes =
    kType5TransparentFlagsBytes +
    static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT);

}  // namespace

std::vector<std::uint8_t> Type5AddressedCommand(
    std::uint8_t command, const std::vector<std::uint8_t>& uid_lsb) {
  std::vector<std::uint8_t> cmd;
  cmd.reserve(NFC_TAG_T5T_ISO15693_CMD_BUF_MAX);
  cmd.push_back(NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED);
  cmd.push_back(command);
  cmd.insert(cmd.end(), uid_lsb.begin(), uid_lsb.end());
  return cmd;
}

std::vector<std::uint8_t> Type5AddressedBlockCommand(
    std::uint8_t short_command, std::uint8_t extended_command,
    const std::vector<std::uint8_t>& uid_lsb, std::uint16_t block) {
  std::vector<std::uint8_t> cmd = Type5AddressedCommand(
      block > NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX ? extended_command
                                                        : short_command,
      uid_lsb);
  if (block > NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX) {
    cmd[0] = static_cast<std::uint8_t>(
        cmd[0] | NFC_TAG_T5T_ISO15693_FLAG_PROTOCOL_EXTENSION);
    cmd.push_back(static_cast<std::uint8_t>(
        block & NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX));
    cmd.push_back(static_cast<std::uint8_t>(
        block >> static_cast<unsigned>(NFC_ISO7816_U16_HIGH_BYTE_SHIFT)));
  } else {
    cmd.push_back(static_cast<std::uint8_t>(block));
  }
  return cmd;
}

std::vector<std::uint8_t> Type5AddressedReadMultipleCommand(
    const std::vector<std::uint8_t>& uid_lsb, std::uint16_t first_block,
    std::uint16_t block_count) {
  const auto kCountField = static_cast<std::uint16_t>(block_count - 1u);
  const bool kExtended =
      (first_block > NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX) ||
      (kCountField > NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX);
  std::vector<std::uint8_t> cmd = Type5AddressedCommand(
      kExtended
          ? static_cast<std::uint8_t>(
                NFC_TAG_T5T_ISO15693_CMD_EXT_READ_MULTIPLE)
          : static_cast<std::uint8_t>(NFC_TAG_T5T_ISO15693_CMD_READ_MULTIPLE),
      uid_lsb);
  if (kExtended) {
    cmd[0] = static_cast<std::uint8_t>(
        cmd[0] | NFC_TAG_T5T_ISO15693_FLAG_PROTOCOL_EXTENSION);
    cmd.push_back(static_cast<std::uint8_t>(
        first_block & NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX));
    cmd.push_back(static_cast<std::uint8_t>(
        first_block >> static_cast<unsigned>(NFC_ISO7816_U16_HIGH_BYTE_SHIFT)));
    cmd.push_back(static_cast<std::uint8_t>(
        kCountField & NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX));
    cmd.push_back(static_cast<std::uint8_t>(
        kCountField >> static_cast<unsigned>(NFC_ISO7816_U16_HIGH_BYTE_SHIFT)));
  } else {
    cmd.push_back(static_cast<std::uint8_t>(first_block));
    cmd.push_back(static_cast<std::uint8_t>(kCountField));
  }
  return cmd;
}

std::vector<std::uint8_t> Type5AddressedSystemInfoExtCommand(
    const std::vector<std::uint8_t>& uid_lsb) {
  std::vector<std::uint8_t> cmd;
  cmd.reserve(
      static_cast<std::size_t>(NFC_TAG_ST25DV_EXT_SYS_INFO_CMD_HEADER_LEN) +
      uid_lsb.size());
  cmd.push_back(
      static_cast<std::uint8_t>(NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED |
                                NFC_TAG_T5T_ISO15693_FLAG_PROTOCOL_EXTENSION));
  cmd.push_back(
      static_cast<std::uint8_t>(NFC_TAG_T5T_ISO15693_CMD_EXT_GET_SYS_INFO));
  cmd.push_back(
      static_cast<std::uint8_t>(NFC_TAG_ST25DV_EXT_SYS_INFO_REQUEST_FIELDS));
  cmd.insert(cmd.end(), uid_lsb.begin(), uid_lsb.end());
  return cmd;
}

#ifdef NERO_USERSPACE_HAVE_PCSC

bool ParseType5Cc(const std::vector<std::uint8_t>& cc,
                  nfc_tag_type5_info_t& info, std::string& err) {
  info = {};
  if (cc.size() < static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT)) {
    err = "Type 5 CC read returned fewer than 4 bytes";
    return false;
  }
  nfc_tag_type5_apply_cc(&info, cc.data(),
                         static_cast<std::uint8_t>(std::min<std::size_t>(
                             cc.size(), NFC_TAG_T5T_CC_LEN_EXTENDED)));
  if (!info.cc_valid || info.data_area_size_bytes == 0u) {
    err = "invalid Type 5 capability container";
    return false;
  }
  err.clear();
  return true;
}

std::uint16_t Type5CcLenOrDefault(const nfc_tag_type5_info_t& info,
                                  const std::vector<std::uint8_t>& cc) {
  return nfc_storage_type5_cc_len_or_default(
      info.cc_len, cc.empty() ? NERO_NFC_NULL : cc.data(),
      static_cast<std::uint16_t>(cc.size()));
}
bool ReadType5CcStorage(PcscCard& card, std::vector<std::uint8_t>& cc,
                        std::string& err) {
  std::vector<std::uint8_t> first_block;
  if (cc.size() >= static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT)) {
    first_block.assign(cc.begin(), cc.begin() + static_cast<std::ptrdiff_t>(
                                                    NFC_TAG_T5T_CC_LEN_SHORT));
  } else if (!Type5StorageReadBinary(card, 0u, first_block, err)) {
    return false;
  }
  if (first_block.size() < static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT)) {
    err = "short Type 5 CC READ BINARY response";
    return false;
  }
  const std::uint16_t kCcLen =
      nfc_storage_type5_declared_cc_len_from_first_block(
          first_block.data(), static_cast<std::uint16_t>(first_block.size()));
  if (kCcLen == 0u) {
    err = "invalid Type 5 CC first block";
    return false;
  }
  if (cc.size() >= kCcLen) {
    cc.resize(kCcLen);
    err.clear();
    return true;
  }
  cc = first_block;
  if (kCcLen == static_cast<std::uint16_t>(NFC_TAG_T5T_CC_LEN_EXTENDED)) {
    std::vector<std::uint8_t> second_block;
    if (!Type5StorageReadBinary(card, 1u, second_block, err)) {
      return false;
    }
    if (second_block.size() <
        static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT)) {
      err = "short Type 5 CC READ BINARY response";
      return false;
    }
    cc.insert(cc.end(), second_block.begin(),
              second_block.begin() +
                  static_cast<std::ptrdiff_t>(NFC_TAG_T5T_CC_LEN_SHORT));
  }
  err.clear();
  return true;
}

bool Type5UidLsbFirst(const std::vector<std::uint8_t>& uid,
                      std::vector<std::uint8_t>& out, std::string& err) {
  if (uid.size() != NFC_TAG_T5T_ISO15693_SYS_INFO_UID_FIELD_LEN) {
    err = "Type 5 transparent exchange requires an 8-byte UID";
    return false;
  }
  out.assign(uid.rbegin(), uid.rend());
  err.clear();
  return true;
}

bool Type5TransparentExchange(PcscCard& card,
                              const std::vector<std::uint8_t>& iso15693_cmd,
                              std::vector<std::uint8_t>& response,
                              std::string& err) {
  if (iso15693_cmd.empty() ||
      iso15693_cmd.size() > static_cast<std::size_t>(NFC_BYTE_VALUE_MAX)) {
    err = "invalid ISO15693 transparent command length";
    return false;
  }
  std::vector<std::uint8_t> capdu;
  capdu.reserve(static_cast<std::size_t>(NFC_ISO7816_SHORT_APDU_HDR_LEN) +
                iso15693_cmd.size());
  capdu.push_back(static_cast<std::uint8_t>(NFC_ISO7816_CLA_PROPRIETARY));
  capdu.push_back(static_cast<std::uint8_t>(NFC_PCSC_ESCAPE_TRANSPARENT_INS));
  capdu.push_back(static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS));
  capdu.push_back(static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS));
  capdu.push_back(static_cast<std::uint8_t>(iso15693_cmd.size()));
  capdu.insert(capdu.end(), iso15693_cmd.begin(), iso15693_cmd.end());
  if (TransmitOk(card, capdu, response, err)) {
    return true;
  }
  capdu[NFC_ISO7816_APDU_IDX_P2] =
      static_cast<std::uint8_t>(NFC_PCSC_GET_DATA_ATS);
  return TransmitOk(card, capdu, response, err);
}

bool Type5TransparentReadBlock(PcscCard& card,
                               const std::vector<std::uint8_t>& uid,
                               std::uint16_t block,
                               std::vector<std::uint8_t>& data,
                               std::string& err) {
  std::vector<std::uint8_t> uid_lsb;
  if (!Type5UidLsbFirst(uid, uid_lsb, err)) {
    return false;
  }
  std::vector<std::uint8_t> cmd = Type5AddressedBlockCommand(
      NFC_TAG_T5T_ISO15693_CMD_READ_SINGLE,
      NFC_TAG_T5T_ISO15693_CMD_EXT_READ_SINGLE, uid_lsb, block);
  std::vector<std::uint8_t> response;
  if (!Type5TransparentExchange(card, cmd, response, err)) {
    return false;
  }
  /* [T5T-ISO15693] §7.1/§7.4 — a standard response begins with a flags byte. If
   * the error flag (bit 0) is set the response carries an error code, not block
   * data. A response without the flags byte (exactly one block) is the raw
   * fallback. */
  if (response.size() >= kType5TransparentFlagsAndBlockBytes) {
    if ((response[0] & static_cast<std::uint8_t>(
                           NFC_TAG_T5T_ISO15693_RESP_FLAG_ERROR)) != 0u) {
      err = "ISO15693 error flag set in transparent read response";
      return false;
    }
    data.assign(response.begin() + 1,
                response.begin() + 1 +
                    static_cast<std::ptrdiff_t>(NFC_TAG_T5T_CC_LEN_SHORT));
    err.clear();
    return true;
  }
  if (response.size() >= static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT)) {
    data.assign(response.begin(),
                response.begin() +
                    static_cast<std::ptrdiff_t>(NFC_TAG_T5T_CC_LEN_SHORT));
    err.clear();
    return true;
  }
  err = "short ISO15693 transparent read response";
  return false;
}

bool Type5TransparentWriteBlock(PcscCard& card,
                                const std::vector<std::uint8_t>& uid,
                                std::uint16_t block,
                                const std::vector<std::uint8_t>& data,
                                std::string& err) {
  if (data.empty() ||
      data.size() > static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_EXTENDED)) {
    err = "invalid ISO15693 write block size";
    return false;
  }
  std::vector<std::uint8_t> uid_lsb;
  if (!Type5UidLsbFirst(uid, uid_lsb, err)) {
    return false;
  }
  std::vector<std::uint8_t> cmd = Type5AddressedBlockCommand(
      NFC_TAG_T5T_ISO15693_CMD_WRITE_SINGLE,
      NFC_TAG_T5T_ISO15693_CMD_EXT_WRITE_SINGLE, uid_lsb, block);
  cmd.insert(cmd.end(), data.begin(), data.end());
  std::vector<std::uint8_t> response;
  if (!Type5TransparentExchange(card, cmd, response, err)) {
    return false;
  }
  if (response.empty() ||
      (response[0] &
       static_cast<std::uint8_t>(NFC_TAG_T5T_ISO15693_RESP_FLAG_ERROR)) == 0u) {
    err.clear();
    return true;
  }
  err = "ISO15693 transparent write returned error flags";
  return false;
}

bool Type5ReadBlock(PcscCard& card, const std::vector<std::uint8_t>& uid,
                    std::uint16_t block, std::vector<std::uint8_t>& data,
                    std::string& err) {
  if (Type5StorageReadBinary(card, block, data, err)) {
    if (data.size() >= static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT)) {
      data.resize(static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT));
      return true;
    }
    err = "short Type 5 storage READ BINARY response";
    return false;
  }
  const std::string kStorageErr = err;
  if (Type5TransparentReadBlock(card, uid, block, data, err)) {
    return true;
  }
  if (!kStorageErr.empty() && kStorageErr != err) {
    err = kStorageErr + "; transparent fallback: " + err;
  }
  return false;
}

bool Type5WriteBlock(PcscCard& card, const std::vector<std::uint8_t>& uid,
                     std::uint16_t block, const std::vector<std::uint8_t>& data,
                     std::string& err) {
  if (Type5StorageUpdateBinary(card, block, data, err)) {
    err.clear();
    return true;
  }
  const std::string kStorageErr = err;
  if (Type5TransparentWriteBlock(card, uid, block, data, err)) {
    return true;
  }
  if (!kStorageErr.empty() && kStorageErr != err) {
    err = kStorageErr + "; transparent fallback: " + err;
  }
  return false;
}

bool Type5StorageWriteUnit(PcscCard& card,
                           const std::vector<std::uint8_t>& uid_lsb,
                           std::uint16_t unit,
                           const std::vector<std::uint8_t>& bytes,
                           std::string& err) {
  if (bytes.size() > static_cast<std::size_t>(NFC_STORAGE_TYPE5_BLOCK_SIZE)) {
    if ((bytes.size() > static_cast<std::size_t>(NFC_BYTE_VALUE_MAX)) ||
        ((bytes.size() %
          static_cast<std::size_t>(NFC_STORAGE_TYPE5_BLOCK_SIZE)) != 0u)) {
      err = "invalid Type 5 storage UPDATE BINARY chunk size";
      return false;
    }
    return Type5StorageUpdateBinary(card, unit, bytes, err);
  }
  return Type5WriteBlock(card, uid_lsb, unit, bytes, err);
}

bool Type5TransparentGetSystemInfo(PcscCard& card,
                                   const std::vector<std::uint8_t>& uid,
                                   std::vector<std::uint8_t>& system_info,
                                   std::string& err) {
  std::vector<std::uint8_t> uid_lsb;
  if (!Type5UidLsbFirst(uid, uid_lsb, err)) {
    return false;
  }
  std::vector<std::uint8_t> cmd = Type5AddressedCommand(
      static_cast<std::uint8_t>(NFC_TAG_T5T_ISO15693_CMD_GET_SYS_INFO),
      uid_lsb);
  return Type5TransparentExchange(card, cmd, system_info, err);
}

bool Type5TransparentGetSystemInfoExt(PcscCard& card,
                                      const std::vector<std::uint8_t>& uid,
                                      std::vector<std::uint8_t>& system_info,
                                      std::string& err) {
  std::vector<std::uint8_t> uid_lsb;
  if (!Type5UidLsbFirst(uid, uid_lsb, err)) {
    return false;
  }
  return Type5TransparentExchange(
      card, Type5AddressedSystemInfoExtCommand(uid_lsb), system_info, err);
}

namespace {

bool Type5SystemInfoResponseOk(const std::vector<std::uint8_t>& system_info,
                               std::size_t min_len) {
  return system_info.size() >= min_len &&
         ((system_info[0] & static_cast<std::uint8_t>(
                                NFC_TAG_T5T_ISO15693_RESP_FLAG_ERROR)) == 0u);
}

bool Type5CcSignalsMlenOverflow(const nfc_tag_type5_info_t& info) {
  return nfc_tag_type5_cc_signals_mlen_overflow(&info);
}

void Type5ApplySystemInfo(PcscCard& card, const std::vector<std::uint8_t>& uid,
                          nfc_tag_type5_info_t& info,
                          std::vector<std::uint8_t>& system_info) {
  if (info.block_count != 0u) {
    return;
  }
  if (system_info.empty()) {
    system_info = TryGetDataBytes(
        card, static_cast<std::uint8_t>(NFC_PCSC_GET_DATA_TYPE5_SYS_INFO),
        static_cast<std::uint8_t>(NFC_ISO7816_GET_DATA_P2_DEFAULT));
  }
  if (Type5SystemInfoResponseOk(
          system_info, static_cast<std::size_t>(
                           NFC_TAG_T5T_ISO15693_SYS_INFO_MIN_REPLY_LEN))) {
    nfc_tag_type5_apply_system_info(
        &info, system_info.data(),
        static_cast<std::uint8_t>(std::min<std::size_t>(
            system_info.size(), static_cast<std::size_t>(NFC_BYTE_VALUE_MAX))));
  } else {
    std::vector<std::uint8_t> transparent_sys;
    std::string sys_err;
    if (Type5TransparentGetSystemInfo(card, uid, transparent_sys, sys_err) &&
        Type5SystemInfoResponseOk(
            transparent_sys,
            static_cast<std::size_t>(
                NFC_TAG_T5T_ISO15693_SYS_INFO_MIN_REPLY_LEN))) {
      system_info = std::move(transparent_sys);
      nfc_tag_type5_apply_system_info(
          &info, system_info.data(),
          static_cast<std::uint8_t>(std::min<std::size_t>(
              system_info.size(),
              static_cast<std::size_t>(NFC_BYTE_VALUE_MAX))));
    }
  }
  if (Type5CcSignalsMlenOverflow(info)) {
    std::vector<std::uint8_t> ext_system_info;
    std::string ext_err;
    if (Type5TransparentGetSystemInfoExt(card, uid, ext_system_info, ext_err) &&
        Type5SystemInfoResponseOk(
            ext_system_info, static_cast<std::size_t>(
                                 NFC_TAG_ST25DV_EXT_SYS_INFO_MIN_REPLY_LEN))) {
      system_info = std::move(ext_system_info);
      nfc_tag_type5_apply_system_info_ext(
          &info, system_info.data(),
          static_cast<std::uint8_t>(std::min<std::size_t>(
              system_info.size(),
              static_cast<std::size_t>(NFC_TAG_T5T_SYS_INFO_RAW_FIELD_MAX))));
    }
  }
  nfc_tag_type5_resolve_mlen_overflow(&info);
}

std::uint16_t Type5DataAreaBytes(const nfc_tag_type5_info_t& info,
                                 const std::vector<std::uint8_t>& cc) {
  std::uint16_t area = info.data_area_size_bytes;
  if (info.block_count == 0u ||
      info.block_size != NFC_STORAGE_TYPE5_BLOCK_SIZE) {
    return area;
  }
  const std::uint16_t kCcLen = Type5CcLenOrDefault(info, cc);
  const auto kCcBlocks =
      static_cast<std::uint16_t>(kCcLen / NFC_STORAGE_TYPE5_BLOCK_SIZE);
  if (info.block_count <= kCcBlocks) {
    return area;
  }
  const std::uint32_t kGeom =
      static_cast<std::uint32_t>(info.block_count - kCcBlocks) *
      NFC_STORAGE_TYPE5_BLOCK_SIZE;
  if (kGeom > std::numeric_limits<std::uint16_t>::max()) {
    return area;
  }
  const auto kGeomArea = static_cast<std::uint16_t>(kGeom);
  return kGeomArea > area ? kGeomArea : area;
}

bool Type5WriteCc(PcscCard& card, const std::vector<std::uint8_t>& uid,
                  std::uint8_t mlen, std::string& err) {
  const std::vector<std::uint8_t> kCcBlock{
      static_cast<std::uint8_t>(NFC_FORUM_CC_MAGIC),
      static_cast<std::uint8_t>(NFC_T5T_CC_VER_ACCESS), mlen,
      static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS)};
  return Type5WriteBlock(card, uid, 0u, kCcBlock, err);
}

bool Type5RefreshCcIfNeeded(PcscCard& card,
                            const std::vector<std::uint8_t>& uid,
                            const nfc_tag_type5_info_t& info,
                            const std::vector<std::uint8_t>& cc,
                            std::size_t tlv_len, std::string& err) {
  const std::size_t kNeedUnits =
      (tlv_len +
       static_cast<std::size_t>(NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES - 1u)) /
      static_cast<std::size_t>(NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES);
  /* [T5T-ISO15693] §4.3.1.17 — the short (4-byte) CC stores MLEN in a single
   * byte. Larger areas require the 8-byte extended CC (2-byte MLEN in
   * bytes 6..7). Fail closed instead of writing a wrapped MLEN that would
   * corrupt the CC. */
  if (kNeedUnits >
      static_cast<std::size_t>(std::numeric_limits<std::uint8_t>::max())) {
    err = "NDEF area exceeds 8-bit T5T CC MLEN; extended CC write unsupported";
    return false;
  }
  auto need_mlen = static_cast<std::uint8_t>(kNeedUnits);
  need_mlen = std::max(
      need_mlen, static_cast<std::uint8_t>(NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES));
  if (info.block_count > 0u &&
      info.block_size ==
          static_cast<std::uint8_t>(NFC_STORAGE_TYPE5_BLOCK_SIZE)) {
    const auto kCcBlocks = static_cast<std::uint16_t>(
        Type5CcLenOrDefault(info, cc) / NFC_STORAGE_TYPE5_BLOCK_SIZE);
    if (info.block_count > kCcBlocks) {
      const auto kMlenMax = static_cast<std::uint8_t>(
          (static_cast<std::uint32_t>(info.block_count - kCcBlocks) *
           static_cast<std::uint32_t>(NFC_STORAGE_TYPE5_BLOCK_SIZE)) /
          static_cast<std::uint32_t>(NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES));
      need_mlen = std::min(need_mlen, kMlenMax);
    }
  }
  /* [T5T-ISO15693] §4.3.1.17 — an 8-byte extended CC encodes MLEN in bytes 6..7
   * with byte 2 == 0. Do not overwrite it with a short CC (that would corrupt
   * the extended layout); the extended MLEN already covers the available area.
   */
  if (nfc_storage_type5_declared_cc_len_from_first_block(
          cc.data(), static_cast<std::uint16_t>(cc.size())) ==
      NFC_TAG_T5T_CC_LEN_EXTENDED) {
    err.clear();
    return true;
  }
  const std::uint8_t kCurMlen =
      (cc.size() >= static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT))
          ? cc[NFC_TAG_T5T_CC_MLEN_BYTE_INDEX]
          : 0u;
  if (kCurMlen >= need_mlen) {
    err.clear();
    return true;
  }
  if (!Type5WriteCc(card, uid, need_mlen, err)) {
    return false;
  }
  err.clear();
  return true;
}

}  // namespace

bool ReadType5Cc(PcscCard& card, const std::vector<std::uint8_t>& uid,
                 std::vector<std::uint8_t>& cc, std::string& err) {
  if (cc.size() < static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT)) {
    std::vector<std::uint8_t> cached = TryGetDataBytes(
        card, NFC_PCSC_GET_DATA_TYPE5_CC, NFC_ISO7816_GET_DATA_P2_DEFAULT);
    if (!cached.empty()) {
      cc = std::move(cached);
    }
  }
  if (ReadType5CcStorage(card, cc, err)) {
    return true;
  }
  const std::string kStorageErr = err;
  std::vector<std::uint8_t> first_block;
  if (!Type5TransparentReadBlock(card, uid, 0u, first_block, err)) {
    if (!kStorageErr.empty() && kStorageErr != err) {
      err = kStorageErr + "; transparent fallback: " + err;
    }
    return false;
  }
  cc = first_block;
  if (nfc_storage_type5_declared_cc_len_from_first_block(
          cc.data(), static_cast<std::uint16_t>(cc.size())) ==
      NFC_TAG_T5T_CC_LEN_EXTENDED) {
    std::vector<std::uint8_t> second_block;
    if (!Type5TransparentReadBlock(card, uid, 1u, second_block, err)) {
      return false;
    }
    cc.insert(cc.end(), second_block.begin(), second_block.end());
  }
  err.clear();
  return true;
}
bool ReadType5NdefTlv(PcscCard& card, const std::vector<std::uint8_t>& uid,
                      std::uint16_t tlv_start_offset,
                      std::uint16_t data_area_size, PcscTagSnapshot& tag,
                      std::string& err) {
  if (static_cast<std::uint32_t>(tlv_start_offset) +
          static_cast<std::uint32_t>(data_area_size) >
      std::numeric_limits<std::uint16_t>::max()) {
    err = "Type 5 TLV area exceeds host address range";
    return false;
  }
  const auto kBlocks =
      StorageType5ReadBlockLimit(tlv_start_offset, data_area_size);
  if (kBlocks == 0u) {
    err = "Type 5 TLV area exceeds host read range";
    return false;
  }
  const auto kTotalLen = static_cast<std::uint16_t>(
      kBlocks * static_cast<std::uint16_t>(NFC_STORAGE_TYPE5_BLOCK_SIZE));
  std::vector<std::uint8_t> raw;
  raw.reserve(
      std::min<std::uint16_t>(kTotalLen, NFC_PCSC_ISO_DEP_APDU_RESP_MAX));

  for (std::uint16_t block = 0u; block < kBlocks;) {
    const auto kCopied = static_cast<std::uint16_t>(raw.size());
    const auto kRemaining = static_cast<std::uint16_t>(kTotalLen - kCopied);
    std::vector<std::uint8_t> block_data;
    if (!Type5ReadBlock(card, uid, block, block_data, err)) {
      return false;
    }
    const auto kWant = static_cast<std::uint16_t>(std::min<std::size_t>(
        block_data.size(), static_cast<std::size_t>(kRemaining)));
    if (block_data.size() < kWant) {
      err = "short Type 5 block read response";
      return false;
    }
    raw.insert(raw.end(), block_data.begin(),
               block_data.begin() + static_cast<std::ptrdiff_t>(kWant));
    block = static_cast<std::uint16_t>(block + 1u);
    if (raw.size() <= tlv_start_offset) {
      continue;
    }

    nfc_ndef_tlv_t tlv{};
    nfc_ndef_tlv_status_t const kStatus = nfc_ndef_find_message_tlv(
        raw.data(), static_cast<std::uint16_t>(raw.size()), tlv_start_offset,
        &tlv);
    if (kStatus == NFC_NDEF_TLV_OK) {
      tag.ndef_message_.assign(
          raw.begin() + static_cast<std::ptrdiff_t>(tlv.value_offset),
          raw.begin() +
              static_cast<std::ptrdiff_t>(tlv.value_offset + tlv.value_len));
      tag.records_ = ParseNdefRecords(tag.ndef_message_);
      err.clear();
      return true;
    }
    if (kStatus == NFC_NDEF_TLV_NOT_FOUND) {
      if (TlvAreaHasTerminator(raw, tlv_start_offset) ||
          raw.size() >= kTotalLen) {
        tag.ndef_message_.clear();
        tag.records_.clear();
        err.clear();
        return true;
      }
      continue;
    }
    if (kStatus != NFC_NDEF_TLV_TRUNCATED) {
      err = std::string("NDEF TLV ") + TlvStatusName(kStatus);
      return false;
    }
  }

  tag.ndef_message_.clear();
  tag.records_.clear();
  err = "NDEF TLV truncated";
  return false;
}

bool ReadType5StorageNdef(PcscCard& card, const std::vector<std::uint8_t>& uid,
                          PcscTagSnapshot& tag,
                          std::vector<std::uint8_t>& type5_cc,
                          std::vector<std::uint8_t>& type5_system_info,
                          std::string& err) {
  nfc_tag_type5_info_t info{};
  if (!ReadType5Cc(card, uid, type5_cc, err) ||
      !ParseType5Cc(type5_cc, info, err)) {
    return false;
  }
  Type5ApplySystemInfo(card, uid, info, type5_system_info);
  const auto kCcLen = Type5CcLenOrDefault(info, type5_cc);
  const auto kDataArea = Type5DataAreaBytes(info, type5_cc);
  tag.max_ndef_size_ = StorageTlvPayloadCap(kDataArea);
  tag.read_access_open_ = info.read_access_open;
  tag.write_access_open_ = info.write_access_open;
  if (!info.read_access_open) {
    err = "tag reports read access restricted";
    return false;
  }
  return ReadType5NdefTlv(card, uid, kCcLen, kDataArea, tag, err);
}

bool WriteType5StorageNdef(PcscCard& card, const std::vector<std::uint8_t>& uid,
                           const std::vector<std::uint8_t>& ndef,
                           std::string& err) {
  std::vector<std::uint8_t> cc;
  std::vector<std::uint8_t> tlv_area;
  nfc_tag_type5_info_t info{};
  if (!ReadType5Cc(card, uid, cc, err) || !ParseType5Cc(cc, info, err)) {
    return false;
  }
  if (!info.write_access_open) {
    err = "tag reports write access restricted";
    return false;
  }
  std::vector<std::uint8_t> type5_system_info;
  Type5ApplySystemInfo(card, uid, info, type5_system_info);
  const auto kDataArea = Type5DataAreaBytes(info, cc);
  const auto kBuildArea =
      (info.block_count == 0u &&
       kDataArea < std::numeric_limits<std::uint16_t>::max())
          ? std::numeric_limits<std::uint16_t>::max()
          : kDataArea;
  if (!BuildStorageNdefTlv(ndef, kBuildArea, tlv_area, err)) {
    return false;
  }
  if (info.block_count != 0u && tlv_area.size() > kDataArea) {
    err = "NDEF payload exceeds tag data area";
    return false;
  }
  if (!Type5RefreshCcIfNeeded(card, uid, info, cc, tlv_area.size(), err)) {
    return false;
  }
  const auto kCcLen = Type5CcLenOrDefault(info, cc);
  if (kCcLen == 0u || (kCcLen % static_cast<std::uint16_t>(
                                    NFC_STORAGE_TYPE5_BLOCK_SIZE)) != 0u) {
    err = "invalid Type 5 CC length for block addressing";
    return false;
  }
  if (tlv_area.size() > std::numeric_limits<std::uint16_t>::max()) {
    err = "Type 5 TLV image exceeds host block range";
    return false;
  }
  const auto kStartBlock = static_cast<std::uint16_t>(
      kCcLen / static_cast<std::uint16_t>(NFC_STORAGE_TYPE5_BLOCK_SIZE));
  const auto kBlocks = static_cast<std::uint16_t>(
      (tlv_area.size() + static_cast<std::size_t>(NFC_STORAGE_TYPE2_CC_PAGE)) /
      static_cast<std::size_t>(NFC_STORAGE_TYPE5_BLOCK_SIZE));
  if (kBlocks != 0u &&
      (static_cast<std::uint32_t>(kStartBlock) +
           static_cast<std::uint32_t>(kBlocks) >
       (static_cast<std::uint32_t>(std::numeric_limits<std::uint16_t>::max()) +
        1u))) {
    err = "Type 5 write crosses host block range";
    return false;
  }
  return StorageWriteUnitsWithIo(card, uid, kStartBlock,
                                 NFC_STORAGE_TYPE5_BLOCK_SIZE, tlv_area,
                                 Type5StorageWriteUnit, err);
}
#endif  // NERO_USERSPACE_HAVE_PCSC

}  // namespace nero_nfc::pcsc_internal
