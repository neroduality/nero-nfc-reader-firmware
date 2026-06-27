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

#include "nero_nfc_hex.h"
#include "nero_nfc_limits.h"
#include "nero_nfc_ndef.h"
#include "nero_nfc_null.h"
#include "nero_nfc_pcsc_internal.h"
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
  kType5TransparentFlagsBytes + static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT);

} // namespace

std::vector<std::uint8_t> type5_addressed_command(std::uint8_t command,
                                                  const std::vector<std::uint8_t> &uid_lsb) {
  std::vector<std::uint8_t> cmd;
  cmd.reserve(NFC_TAG_T5T_ISO15693_CMD_BUF_MAX);
  cmd.push_back(NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED);
  cmd.push_back(command);
  cmd.insert(cmd.end(), uid_lsb.begin(), uid_lsb.end());
  return cmd;
}

std::vector<std::uint8_t> type5_addressed_block_command(std::uint8_t short_command,
                                                        std::uint8_t extended_command,
                                                        const std::vector<std::uint8_t> &uid_lsb,
                                                        std::uint16_t block) {
  std::vector<std::uint8_t> cmd = type5_addressed_command(
    block > NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX ? extended_command : short_command, uid_lsb);
  if (block > NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX) {
    cmd[0] = static_cast<std::uint8_t>(cmd[0] | NFC_TAG_T5T_ISO15693_FLAG_PROTOCOL_EXTENSION);
    cmd.push_back(static_cast<std::uint8_t>(block & NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX));
    cmd.push_back(
      static_cast<std::uint8_t>(block >> static_cast<unsigned>(NFC_ISO7816_U16_HIGH_BYTE_SHIFT)));
  } else {
    cmd.push_back(static_cast<std::uint8_t>(block));
  }
  return cmd;
}

std::vector<std::uint8_t>
type5_addressed_read_multiple_command(const std::vector<std::uint8_t> &uid_lsb,
                                      std::uint16_t first_block, std::uint16_t block_count) {
  const auto count_field = static_cast<std::uint16_t>(block_count - 1u);
  const bool extended = (first_block > NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX) ||
                        (count_field > NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX);
  std::vector<std::uint8_t> cmd = type5_addressed_command(
    extended ? static_cast<std::uint8_t>(NFC_TAG_T5T_ISO15693_CMD_EXT_READ_MULTIPLE)
             : static_cast<std::uint8_t>(NFC_TAG_T5T_ISO15693_CMD_READ_MULTIPLE),
    uid_lsb);
  if (extended) {
    cmd[0] = static_cast<std::uint8_t>(cmd[0] | NFC_TAG_T5T_ISO15693_FLAG_PROTOCOL_EXTENSION);
    cmd.push_back(
      static_cast<std::uint8_t>(first_block & NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX));
    cmd.push_back(static_cast<std::uint8_t>(
      first_block >> static_cast<unsigned>(NFC_ISO7816_U16_HIGH_BYTE_SHIFT)));
    cmd.push_back(
      static_cast<std::uint8_t>(count_field & NFC_TAG_T5T_ISO15693_BLOCK_ADDR_1BYTE_MAX));
    cmd.push_back(static_cast<std::uint8_t>(
      count_field >> static_cast<unsigned>(NFC_ISO7816_U16_HIGH_BYTE_SHIFT)));
  } else {
    cmd.push_back(static_cast<std::uint8_t>(first_block));
    cmd.push_back(static_cast<std::uint8_t>(count_field));
  }
  return cmd;
}

std::vector<std::uint8_t>
type5_addressed_system_info_ext_command(const std::vector<std::uint8_t> &uid_lsb) {
  std::vector<std::uint8_t> cmd;
  cmd.reserve(static_cast<std::size_t>(NFC_TAG_ST25DV_EXT_SYS_INFO_CMD_HEADER_LEN) +
              uid_lsb.size());
  cmd.push_back(static_cast<std::uint8_t>(NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED |
                                          NFC_TAG_T5T_ISO15693_FLAG_PROTOCOL_EXTENSION));
  cmd.push_back(static_cast<std::uint8_t>(NFC_TAG_T5T_ISO15693_CMD_EXT_GET_SYS_INFO));
  cmd.push_back(static_cast<std::uint8_t>(NFC_TAG_ST25DV_EXT_SYS_INFO_REQUEST_FIELDS));
  cmd.insert(cmd.end(), uid_lsb.begin(), uid_lsb.end());
  return cmd;
}

#ifdef NERO_USERSPACE_HAVE_PCSC

bool parse_type5_cc(const std::vector<std::uint8_t> &cc, nfc_tag_type5_info_t &info,
                    std::string &err) {
  info = {};
  if (cc.size() < static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT)) {
    err = "Type 5 CC read returned fewer than 4 bytes";
    return false;
  }
  nfc_tag_type5_apply_cc(
    &info, cc.data(),
    static_cast<std::uint8_t>(std::min<std::size_t>(cc.size(), NFC_TAG_T5T_CC_LEN_EXTENDED)));
  if (!info.cc_valid || info.data_area_size_bytes == 0u) {
    err = "invalid Type 5 capability container";
    return false;
  }
  err.clear();
  return true;
}

std::uint16_t type5_cc_len_or_default(const nfc_tag_type5_info_t &info,
                                      const std::vector<std::uint8_t> &cc) {
  return nfc_storage_type5_cc_len_or_default(info.cc_len, cc.empty() ? NERO_NFC_NULL : cc.data(),
                                             static_cast<std::uint16_t>(cc.size()));
}
bool read_type5_cc_storage(PcscCard &card, std::vector<std::uint8_t> &cc, std::string &err) {
  std::vector<std::uint8_t> first_block;
  if (cc.size() >= static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT)) {
    first_block.assign(cc.begin(),
                       cc.begin() + static_cast<std::ptrdiff_t>(NFC_TAG_T5T_CC_LEN_SHORT));
  } else if (!type5_storage_read_binary(card, 0u, first_block, err)) {
    return false;
  }
  if (first_block.size() < static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT)) {
    err = "short Type 5 CC READ BINARY response";
    return false;
  }
  const std::uint16_t cc_len = nfc_storage_type5_declared_cc_len_from_first_block(
    first_block.data(), static_cast<std::uint16_t>(first_block.size()));
  if (cc_len == 0u) {
    err = "invalid Type 5 CC first block";
    return false;
  }
  if (cc.size() >= cc_len) {
    cc.resize(cc_len);
    err.clear();
    return true;
  }
  cc = first_block;
  if (cc_len == static_cast<std::uint16_t>(NFC_TAG_T5T_CC_LEN_EXTENDED)) {
    std::vector<std::uint8_t> second_block;
    if (!type5_storage_read_binary(card, 1u, second_block, err)) {
      return false;
    }
    if (second_block.size() < static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT)) {
      err = "short Type 5 CC READ BINARY response";
      return false;
    }
    cc.insert(cc.end(), second_block.begin(),
              second_block.begin() + static_cast<std::ptrdiff_t>(NFC_TAG_T5T_CC_LEN_SHORT));
  }
  err.clear();
  return true;
}

bool type5_uid_lsb_first(const std::vector<std::uint8_t> &uid, std::vector<std::uint8_t> &out,
                         std::string &err) {
  if (uid.size() != NFC_TAG_T5T_ISO15693_SYS_INFO_UID_FIELD_LEN) {
    err = "Type 5 transparent exchange requires an 8-byte UID";
    return false;
  }
  out.assign(uid.rbegin(), uid.rend());
  err.clear();
  return true;
}

bool type5_transparent_exchange(PcscCard &card, const std::vector<std::uint8_t> &iso15693_cmd,
                                std::vector<std::uint8_t> &response, std::string &err) {
  if (iso15693_cmd.empty() || iso15693_cmd.size() > static_cast<std::size_t>(NFC_BYTE_VALUE_MAX)) {
    err = "invalid ISO15693 transparent command length";
    return false;
  }
  std::vector<std::uint8_t> capdu;
  capdu.reserve(static_cast<std::size_t>(NFC_ISO7816_SHORT_APDU_HDR_LEN) + iso15693_cmd.size());
  capdu.push_back(static_cast<std::uint8_t>(NFC_ISO7816_CLA_PROPRIETARY));
  capdu.push_back(static_cast<std::uint8_t>(NFC_PCSC_ESCAPE_TRANSPARENT_INS));
  capdu.push_back(static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS));
  capdu.push_back(static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS));
  capdu.push_back(static_cast<std::uint8_t>(iso15693_cmd.size()));
  capdu.insert(capdu.end(), iso15693_cmd.begin(), iso15693_cmd.end());
  if (transmit_ok(card, capdu, response, err)) {
    return true;
  }
  capdu[NFC_ISO7816_APDU_IDX_P2] = static_cast<std::uint8_t>(NFC_PCSC_GET_DATA_ATS);
  return transmit_ok(card, capdu, response, err);
}

bool type5_transparent_read_block(PcscCard &card, const std::vector<std::uint8_t> &uid,
                                  std::uint16_t block, std::vector<std::uint8_t> &data,
                                  std::string &err) {
  std::vector<std::uint8_t> uid_lsb;
  if (!type5_uid_lsb_first(uid, uid_lsb, err)) {
    return false;
  }
  std::vector<std::uint8_t> cmd = type5_addressed_block_command(
    NFC_TAG_T5T_ISO15693_CMD_READ_SINGLE, NFC_TAG_T5T_ISO15693_CMD_EXT_READ_SINGLE, uid_lsb, block);
  std::vector<std::uint8_t> response;
  if (!type5_transparent_exchange(card, cmd, response, err)) {
    return false;
  }
  /* [T5T-ISO15693] §7.1/§7.4 — a standard response begins with a flags byte. If the
   * error flag (bit 0) is set the response carries an error code, not block
   * data. A response without the flags byte (exactly one block) is the raw
   * fallback. */
  if (response.size() >= kType5TransparentFlagsAndBlockBytes) {
    if ((response[0] & static_cast<std::uint8_t>(NFC_TAG_T5T_ISO15693_RESP_FLAG_ERROR)) != 0u) {
      err = "ISO15693 error flag set in transparent read response";
      return false;
    }
    data.assign(response.begin() + 1,
                response.begin() + 1 + static_cast<std::ptrdiff_t>(NFC_TAG_T5T_CC_LEN_SHORT));
    err.clear();
    return true;
  }
  if (response.size() >= static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT)) {
    data.assign(response.begin(),
                response.begin() + static_cast<std::ptrdiff_t>(NFC_TAG_T5T_CC_LEN_SHORT));
    err.clear();
    return true;
  }
  err = "short ISO15693 transparent read response";
  return false;
}

bool type5_transparent_write_block(PcscCard &card, const std::vector<std::uint8_t> &uid,
                                   std::uint16_t block, const std::vector<std::uint8_t> &data,
                                   std::string &err) {
  if (data.empty() || data.size() > static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_EXTENDED)) {
    err = "invalid ISO15693 write block size";
    return false;
  }
  std::vector<std::uint8_t> uid_lsb;
  if (!type5_uid_lsb_first(uid, uid_lsb, err)) {
    return false;
  }
  std::vector<std::uint8_t> cmd =
    type5_addressed_block_command(NFC_TAG_T5T_ISO15693_CMD_WRITE_SINGLE,
                                  NFC_TAG_T5T_ISO15693_CMD_EXT_WRITE_SINGLE, uid_lsb, block);
  cmd.insert(cmd.end(), data.begin(), data.end());
  std::vector<std::uint8_t> response;
  if (!type5_transparent_exchange(card, cmd, response, err)) {
    return false;
  }
  if (response.empty() ||
      (response[0] & static_cast<std::uint8_t>(NFC_TAG_T5T_ISO15693_RESP_FLAG_ERROR)) == 0u) {
    err.clear();
    return true;
  }
  err = "ISO15693 transparent write returned error flags";
  return false;
}

bool type5_read_block(PcscCard &card, const std::vector<std::uint8_t> &uid, std::uint16_t block,
                      std::vector<std::uint8_t> &data, std::string &err) {
  if (type5_storage_read_binary(card, block, data, err)) {
    if (data.size() >= static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT)) {
      data.resize(static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT));
      return true;
    }
    err = "short Type 5 storage READ BINARY response";
    return false;
  }
  const std::string storage_err = err;
  if (type5_transparent_read_block(card, uid, block, data, err)) {
    return true;
  }
  if (!storage_err.empty() && storage_err != err) {
    err = storage_err + "; transparent fallback: " + err;
  }
  return false;
}

bool type5_write_block(PcscCard &card, const std::vector<std::uint8_t> &uid, std::uint16_t block,
                       const std::vector<std::uint8_t> &data, std::string &err) {
  if (type5_storage_update_binary(card, block, data, err)) {
    err.clear();
    return true;
  }
  const std::string storage_err = err;
  if (type5_transparent_write_block(card, uid, block, data, err)) {
    return true;
  }
  if (!storage_err.empty() && storage_err != err) {
    err = storage_err + "; transparent fallback: " + err;
  }
  return false;
}

bool type5_storage_write_unit(PcscCard &card, const std::vector<std::uint8_t> &uid_lsb,
                              std::uint16_t unit, const std::vector<std::uint8_t> &bytes,
                              std::string &err) {
  if (bytes.size() > static_cast<std::size_t>(NFC_STORAGE_TYPE5_BLOCK_SIZE)) {
    if ((bytes.size() > static_cast<std::size_t>(NFC_BYTE_VALUE_MAX)) ||
        ((bytes.size() % static_cast<std::size_t>(NFC_STORAGE_TYPE5_BLOCK_SIZE)) != 0u)) {
      err = "invalid Type 5 storage UPDATE BINARY chunk size";
      return false;
    }
    return type5_storage_update_binary(card, unit, bytes, err);
  }
  return type5_write_block(card, uid_lsb, unit, bytes, err);
}

bool type5_transparent_get_system_info(PcscCard &card, const std::vector<std::uint8_t> &uid,
                                       std::vector<std::uint8_t> &system_info, std::string &err) {
  std::vector<std::uint8_t> uid_lsb;
  if (!type5_uid_lsb_first(uid, uid_lsb, err)) {
    return false;
  }
  std::vector<std::uint8_t> cmd = type5_addressed_command(
    static_cast<std::uint8_t>(NFC_TAG_T5T_ISO15693_CMD_GET_SYS_INFO), uid_lsb);
  return type5_transparent_exchange(card, cmd, system_info, err);
}

bool type5_transparent_get_system_info_ext(PcscCard &card, const std::vector<std::uint8_t> &uid,
                                           std::vector<std::uint8_t> &system_info,
                                           std::string &err) {
  std::vector<std::uint8_t> uid_lsb;
  if (!type5_uid_lsb_first(uid, uid_lsb, err)) {
    return false;
  }
  return type5_transparent_exchange(card, type5_addressed_system_info_ext_command(uid_lsb),
                                    system_info, err);
}

namespace {

bool type5_system_info_response_ok(const std::vector<std::uint8_t> &system_info,
                                   std::size_t min_len) {
  return system_info.size() >= min_len &&
         ((system_info[0] & static_cast<std::uint8_t>(NFC_TAG_T5T_ISO15693_RESP_FLAG_ERROR)) == 0u);
}

bool type5_cc_signals_mlen_overflow(const nfc_tag_type5_info_t &info) {
  return nfc_tag_type5_cc_signals_mlen_overflow(&info);
}

void type5_apply_system_info(PcscCard &card, const std::vector<std::uint8_t> &uid,
                             nfc_tag_type5_info_t &info, std::vector<std::uint8_t> &system_info) {
  if (info.block_count != 0u) {
    return;
  }
  if (system_info.empty()) {
    system_info =
      try_get_data_bytes(card, static_cast<std::uint8_t>(NFC_PCSC_GET_DATA_TYPE5_SYS_INFO),
                         static_cast<std::uint8_t>(NFC_ISO7816_GET_DATA_P2_DEFAULT));
  }
  if (type5_system_info_response_ok(
        system_info, static_cast<std::size_t>(NFC_TAG_T5T_ISO15693_SYS_INFO_MIN_REPLY_LEN))) {
    nfc_tag_type5_apply_system_info(
      &info, system_info.data(),
      static_cast<std::uint8_t>(
        std::min<std::size_t>(system_info.size(), static_cast<std::size_t>(NFC_BYTE_VALUE_MAX))));
  } else {
    std::vector<std::uint8_t> transparent_sys;
    std::string sys_err;
    if (type5_transparent_get_system_info(card, uid, transparent_sys, sys_err) &&
        type5_system_info_response_ok(
          transparent_sys, static_cast<std::size_t>(NFC_TAG_T5T_ISO15693_SYS_INFO_MIN_REPLY_LEN))) {
      system_info = std::move(transparent_sys);
      nfc_tag_type5_apply_system_info(
        &info, system_info.data(),
        static_cast<std::uint8_t>(
          std::min<std::size_t>(system_info.size(), static_cast<std::size_t>(NFC_BYTE_VALUE_MAX))));
    }
  }
  if (type5_cc_signals_mlen_overflow(info)) {
    std::vector<std::uint8_t> ext_system_info;
    std::string ext_err;
    if (type5_transparent_get_system_info_ext(card, uid, ext_system_info, ext_err) &&
        type5_system_info_response_ok(
          ext_system_info, static_cast<std::size_t>(NFC_TAG_ST25DV_EXT_SYS_INFO_MIN_REPLY_LEN))) {
      system_info = std::move(ext_system_info);
      nfc_tag_type5_apply_system_info_ext(
        &info, system_info.data(),
        static_cast<std::uint8_t>(std::min<std::size_t>(
          system_info.size(), static_cast<std::size_t>(NFC_TAG_T5T_SYS_INFO_RAW_FIELD_MAX))));
    }
  }
  nfc_tag_type5_resolve_mlen_overflow(&info);
}

std::uint16_t type5_data_area_bytes(const nfc_tag_type5_info_t &info,
                                    const std::vector<std::uint8_t> &cc) {
  std::uint16_t area = info.data_area_size_bytes;
  if (info.block_count == 0u || info.block_size != NFC_STORAGE_TYPE5_BLOCK_SIZE) {
    return area;
  }
  const std::uint16_t cc_len = type5_cc_len_or_default(info, cc);
  const std::uint16_t cc_blocks = static_cast<std::uint16_t>(cc_len / NFC_STORAGE_TYPE5_BLOCK_SIZE);
  if (info.block_count <= cc_blocks) {
    return area;
  }
  const std::uint32_t geom =
    static_cast<std::uint32_t>(info.block_count - cc_blocks) * NFC_STORAGE_TYPE5_BLOCK_SIZE;
  if (geom > std::numeric_limits<std::uint16_t>::max()) {
    return area;
  }
  const auto geom_area = static_cast<std::uint16_t>(geom);
  return geom_area > area ? geom_area : area;
}

bool type5_write_cc(PcscCard &card, const std::vector<std::uint8_t> &uid, std::uint8_t mlen,
                    std::string &err) {
  const std::vector<std::uint8_t> cc_block{static_cast<std::uint8_t>(NFC_FORUM_CC_MAGIC),
                                           static_cast<std::uint8_t>(NFC_T5T_CC_VERSION), mlen,
                                           static_cast<std::uint8_t>(NFC_ISO7816_SW2_SUCCESS)};
  return type5_write_block(card, uid, 0u, cc_block, err);
}

bool type5_refresh_cc_if_needed(PcscCard &card, const std::vector<std::uint8_t> &uid,
                                const nfc_tag_type5_info_t &info,
                                const std::vector<std::uint8_t> &cc, std::size_t tlv_len,
                                std::string &err) {
  const std::size_t need_units =
    (tlv_len + static_cast<std::size_t>(NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES - 1u)) /
    static_cast<std::size_t>(NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES);
  /* [T5T-ISO15693] §4.3.1.17 — the short (4-byte) CC stores MLEN in a single
   * byte. Larger areas require the 8-byte extended CC (2-byte MLEN in
   * bytes 6..7). Fail closed instead of writing a wrapped MLEN that would
   * corrupt the CC. */
  if (need_units > static_cast<std::size_t>(std::numeric_limits<std::uint8_t>::max())) {
    err = "NDEF area exceeds 8-bit T5T CC MLEN; extended CC write unsupported";
    return false;
  }
  std::uint8_t need_mlen = static_cast<std::uint8_t>(need_units);
  if (need_mlen < static_cast<std::uint8_t>(NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES)) {
    need_mlen = static_cast<std::uint8_t>(NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES);
  }
  if (info.block_count > 0u &&
      info.block_size == static_cast<std::uint8_t>(NFC_STORAGE_TYPE5_BLOCK_SIZE)) {
    const std::uint16_t cc_blocks =
      static_cast<std::uint16_t>(type5_cc_len_or_default(info, cc) / NFC_STORAGE_TYPE5_BLOCK_SIZE);
    if (info.block_count > cc_blocks) {
      const std::uint8_t mlen_max =
        static_cast<std::uint8_t>((static_cast<std::uint32_t>(info.block_count - cc_blocks) *
                                   static_cast<std::uint32_t>(NFC_STORAGE_TYPE5_BLOCK_SIZE)) /
                                  static_cast<std::uint32_t>(NFC_TAG_T2T_AREA_SIZE_UNIT_BYTES));
      if (need_mlen > mlen_max) {
        need_mlen = mlen_max;
      }
    }
  }
  /* [T5T-ISO15693] §4.3.1.17 — an 8-byte extended CC encodes MLEN in bytes 6..7
   * with byte 2 == 0. Do not overwrite it with a short CC (that would corrupt
   * the extended layout); the extended MLEN already covers the available area.
   */
  if (nfc_storage_type5_declared_cc_len_from_first_block(
        cc.data(), static_cast<std::uint16_t>(cc.size())) == NFC_TAG_T5T_CC_LEN_EXTENDED) {
    err.clear();
    return true;
  }
  const std::uint8_t cur_mlen = (cc.size() >= static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT))
                                  ? cc[NFC_TAG_T5T_CC_MLEN_BYTE_INDEX]
                                  : 0u;
  if (cur_mlen >= need_mlen) {
    err.clear();
    return true;
  }
  if (!type5_write_cc(card, uid, need_mlen, err)) {
    return false;
  }
  err.clear();
  return true;
}

} // namespace

bool read_type5_cc(PcscCard &card, const std::vector<std::uint8_t> &uid,
                   std::vector<std::uint8_t> &cc, std::string &err) {
  if (cc.size() < static_cast<std::size_t>(NFC_TAG_T5T_CC_LEN_SHORT)) {
    std::vector<std::uint8_t> cached =
      try_get_data_bytes(card, NFC_PCSC_GET_DATA_TYPE5_CC, NFC_ISO7816_GET_DATA_P2_DEFAULT);
    if (!cached.empty()) {
      cc = std::move(cached);
    }
  }
  if (read_type5_cc_storage(card, cc, err)) {
    return true;
  }
  const std::string storage_err = err;
  std::vector<std::uint8_t> first_block;
  if (!type5_transparent_read_block(card, uid, 0u, first_block, err)) {
    if (!storage_err.empty() && storage_err != err) {
      err = storage_err + "; transparent fallback: " + err;
    }
    return false;
  }
  cc = first_block;
  if (nfc_storage_type5_declared_cc_len_from_first_block(
        cc.data(), static_cast<std::uint16_t>(cc.size())) == NFC_TAG_T5T_CC_LEN_EXTENDED) {
    std::vector<std::uint8_t> second_block;
    if (!type5_transparent_read_block(card, uid, 1u, second_block, err)) {
      return false;
    }
    cc.insert(cc.end(), second_block.begin(), second_block.end());
  }
  err.clear();
  return true;
}
bool read_type5_ndef_tlv(PcscCard &card, const std::vector<std::uint8_t> &uid,
                         std::uint16_t tlv_start_offset, std::uint16_t data_area_size,
                         PcscTagSnapshot &tag, std::string &err) {
  if (static_cast<std::uint32_t>(tlv_start_offset) + static_cast<std::uint32_t>(data_area_size) >
      std::numeric_limits<std::uint16_t>::max()) {
    err = "Type 5 TLV area exceeds host address range";
    return false;
  }
  const auto blocks = storage_type5_read_block_limit(tlv_start_offset, data_area_size);
  if (blocks == 0u) {
    err = "Type 5 TLV area exceeds host read range";
    return false;
  }
  const auto total_len =
    static_cast<std::uint16_t>(blocks * static_cast<std::uint16_t>(NFC_STORAGE_TYPE5_BLOCK_SIZE));
  std::vector<std::uint8_t> raw;
  raw.reserve(std::min<std::uint16_t>(total_len, NFC_PCSC_ISO_DEP_APDU_RESP_MAX));

  for (std::uint16_t block = 0u; block < blocks;) {
    const auto copied = static_cast<std::uint16_t>(raw.size());
    const auto remaining = static_cast<std::uint16_t>(total_len - copied);
    std::vector<std::uint8_t> block_data;
    if (!type5_read_block(card, uid, block, block_data, err)) {
      return false;
    }
    const auto want = static_cast<std::uint16_t>(
      std::min<std::size_t>(block_data.size(), static_cast<std::size_t>(remaining)));
    if (block_data.size() < want) {
      err = "short Type 5 block read response";
      return false;
    }
    raw.insert(raw.end(), block_data.begin(),
               block_data.begin() + static_cast<std::ptrdiff_t>(want));
    block = static_cast<std::uint16_t>(block + 1u);
    if (raw.size() <= tlv_start_offset) {
      continue;
    }

    nfc_ndef_tlv_t tlv{};
    nfc_ndef_tlv_status_t const status = nfc_ndef_find_message_tlv(
      raw.data(), static_cast<std::uint16_t>(raw.size()), tlv_start_offset, &tlv);
    if (status == NFC_NDEF_TLV_OK) {
      tag.ndef_message.assign(raw.begin() + static_cast<std::ptrdiff_t>(tlv.value_offset),
                              raw.begin() +
                                static_cast<std::ptrdiff_t>(tlv.value_offset + tlv.value_len));
      tag.records = parse_ndef_records(tag.ndef_message);
      err.clear();
      return true;
    }
    if (status == NFC_NDEF_TLV_NOT_FOUND) {
      if (tlv_area_has_terminator(raw, tlv_start_offset) || raw.size() >= total_len) {
        tag.ndef_message.clear();
        tag.records.clear();
        err.clear();
        return true;
      }
      continue;
    }
    if (status != NFC_NDEF_TLV_TRUNCATED) {
      err = std::string("NDEF TLV ") + tlv_status_name(status);
      return false;
    }
  }

  tag.ndef_message.clear();
  tag.records.clear();
  err = "NDEF TLV truncated";
  return false;
}

bool read_type5_storage_ndef(PcscCard &card, const std::vector<std::uint8_t> &uid,
                             PcscTagSnapshot &tag, std::vector<std::uint8_t> &type5_cc,
                             std::vector<std::uint8_t> &type5_system_info, std::string &err) {
  nfc_tag_type5_info_t info{};
  if (!read_type5_cc(card, uid, type5_cc, err) || !parse_type5_cc(type5_cc, info, err)) {
    return false;
  }
  type5_apply_system_info(card, uid, info, type5_system_info);
  const auto cc_len = type5_cc_len_or_default(info, type5_cc);
  const auto data_area = type5_data_area_bytes(info, type5_cc);
  tag.max_ndef_size = storage_tlv_payload_cap(data_area);
  tag.read_access_open = info.read_access_open;
  tag.write_access_open = info.write_access_open;
  if (!info.read_access_open) {
    err = "tag reports read access restricted";
    return false;
  }
  return read_type5_ndef_tlv(card, uid, cc_len, data_area, tag, err);
}

bool write_type5_storage_ndef(PcscCard &card, const std::vector<std::uint8_t> &uid,
                              const std::vector<std::uint8_t> &ndef, std::string &err) {
  std::vector<std::uint8_t> cc;
  std::vector<std::uint8_t> tlv_area;
  nfc_tag_type5_info_t info{};
  if (!read_type5_cc(card, uid, cc, err) || !parse_type5_cc(cc, info, err)) {
    return false;
  }
  if (!info.write_access_open) {
    err = "tag reports write access restricted";
    return false;
  }
  std::vector<std::uint8_t> type5_system_info;
  type5_apply_system_info(card, uid, info, type5_system_info);
  const auto data_area = type5_data_area_bytes(info, cc);
  const auto build_area =
    (info.block_count == 0u && data_area < std::numeric_limits<std::uint16_t>::max())
      ? std::numeric_limits<std::uint16_t>::max()
      : data_area;
  if (!build_storage_ndef_tlv(ndef, build_area, tlv_area, err)) {
    return false;
  }
  if (info.block_count != 0u && tlv_area.size() > data_area) {
    err = "NDEF payload exceeds tag data area";
    return false;
  }
  if (!type5_refresh_cc_if_needed(card, uid, info, cc, tlv_area.size(), err)) {
    return false;
  }
  const auto cc_len = type5_cc_len_or_default(info, cc);
  if (cc_len == 0u || (cc_len % static_cast<std::uint16_t>(NFC_STORAGE_TYPE5_BLOCK_SIZE)) != 0u) {
    err = "invalid Type 5 CC length for block addressing";
    return false;
  }
  if (tlv_area.size() > std::numeric_limits<std::uint16_t>::max()) {
    err = "Type 5 TLV image exceeds host block range";
    return false;
  }
  const auto start_block =
    static_cast<std::uint16_t>(cc_len / static_cast<std::uint16_t>(NFC_STORAGE_TYPE5_BLOCK_SIZE));
  const auto blocks = static_cast<std::uint16_t>(
    (tlv_area.size() + static_cast<std::size_t>(NFC_STORAGE_TYPE2_CC_PAGE)) /
    static_cast<std::size_t>(NFC_STORAGE_TYPE5_BLOCK_SIZE));
  if (blocks != 0u &&
      (static_cast<std::uint32_t>(start_block) + static_cast<std::uint32_t>(blocks) >
       (static_cast<std::uint32_t>(std::numeric_limits<std::uint16_t>::max()) + 1u))) {
    err = "Type 5 write crosses host block range";
    return false;
  }
  return storage_write_units_with_io(card, uid, start_block, NFC_STORAGE_TYPE5_BLOCK_SIZE, tlv_area,
                                     type5_storage_write_unit, err);
}
#endif // NERO_USERSPACE_HAVE_PCSC

} // namespace nero_nfc::pcsc_internal
