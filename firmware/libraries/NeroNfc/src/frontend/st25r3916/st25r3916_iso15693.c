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

#include "st25r3916_iso15693.h"

#include "nero_nfc_null.h"

#define ISO15693_CMD_INVENTORY 0x01u
#define ISO15693_CMD_READ_SINGLE_BLOCK 0x20u
#define ISO15693_CMD_WRITE_SINGLE_BLOCK 0x21u
#define ISO15693_CMD_EXT_READ_SINGLE 0x30u
#define ISO15693_CMD_EXT_WRITE_SINGLE 0x31u
#define ST25_ISO15693_STREAM_SOF_1OF4 0x21u
#define ST25_ISO15693_STREAM_EOF_1OF4 0x04u
#define ST25_ISO15693_STREAM_00_1OF4 0x02u
#define ST25_ISO15693_STREAM_01_1OF4 0x08u
#define ST25_ISO15693_STREAM_10_1OF4 0x20u
#define ST25_ISO15693_STREAM_11_1OF4 0x80u
#define ST25_ISO15693_MAX_STREAM_FRAME 128u

enum {
  K_ST25_V_CRC_INIT = 0xFFFFu,
  K_ST25_V_CRC_POLY = 0x8408u,
  K_ST25_V_STREAM_NIBBLES_PER_BYTE = 4u,
  K_ST25_V_DIBIT_MASK = 0x03u,
  K_ST25_V_DIBIT_SHIFT = 2u,
  K_ST25_V_DIBIT0 = 0u,
  K_ST25_V_DIBIT1 = 1u,
  K_ST25_V_DIBIT2 = 2u,
  K_ST25_V_CRC_LEN = 2u,
  K_ST25_V_MANCHESTER_START_POS = 5u,
  K_ST25_V_STREAM_MIN_IN_LEN = 3u,
  K_ST25_V_SOF_MASK = 0x1Fu,
  K_ST25_V_SOF_EXPECT = 0x17u,
  K_ST25_V_EOF_HIGH_MASK = 0xE0u,
  K_ST25_V_EOF_HIGH_EXPECT = 0xA0u,
  K_ST25_V_EOF_LOW_EXPECT = 0x03u,
  K_ST25_V_MAN_ONE = 0x02u,
  K_ST25_V_MAN_STEP = 2u,
  K_ST25_V_INVENTORY_CMD_CAP = 3u,
  K_ST25_V_INVENTORY_RX_CAP = 12u,
  K_ST25_V_INVENTORY_TIMEOUT_MS = 30u,
  K_ST25_V_INVENTORY_MIN_RX = 10u,
  K_ST25_V_INVENTORY_UID_RX_OFF = 2u,
  K_ST25_V_READ_CMD_CAP = 12u,
  K_ST25_V_READ_RX_CAP = 36u,
  K_ST25_V_WRITE_CMD_CAP = 16u,
  K_ST25_V_WRITE_RX_CAP = 4u,
  K_ST25_V_MAX_BLOCK_DATA = 8u,
  K_ST25_V_WRITE_TIMEOUT_MS = 60u,
  K_ST25_V_READ_TIMEOUT_MS = 30u,
  K_ST25_V_MIN_STATUS_RX = 2u,
  K_ST25_V_GET_SYS_INFO_CMD_CAP = 12u,
  K_ST25_V_GET_SYS_INFO_RX_CAP = 16u,
  K_ST25_V_GET_SYS_INFO_MIN_RX = 11u,
  K_ST25_V_INFO_FLAG_DSFID = 0x02u,
  K_ST25_V_INFO_FLAG_AFI = 0x04u,
  K_ST25_V_MEM_SIZE_FIELD_LEN = 2u,
  K_ST25_V_BLOCK_SIZE_MASK = 0x1Fu,
  K_ST25_V_IDX2 = 2u,
};

uint16_t st25_iso15693_crc16(const uint8_t* data, uint16_t len) {
  uint16_t crc = K_ST25_V_CRC_INIT;

  if (data == NERO_NFC_NULL) {
    return 0u;
  }
  for (uint16_t i = 0u; i < len; i++) {
    crc = (uint16_t)(crc ^ (uint16_t)(data[i]));
    for (uint8_t bit = 0u; bit < NFC_BITS_PER_BYTE; bit++) {
      if ((crc & 0x0001u) != 0u) {
        crc = (uint16_t)((crc >> 1) ^ K_ST25_V_CRC_POLY);
      } else {
        crc = (uint16_t)(crc >> 1);
      }
    }
  }
  return (uint16_t)(~crc);
}

NERO_NFC_NODISCARD bool st25_iso15693_stream_put1of4(uint8_t data, uint8_t* out,
                                                     uint16_t out_max,
                                                     uint16_t* pos) {
  if ((out == NERO_NFC_NULL) || (pos == NERO_NFC_NULL) ||
      ((uint16_t)(*pos + K_ST25_V_STREAM_NIBBLES_PER_BYTE) > out_max)) {
    return false;
  }
  for (unsigned i = 0u; i < (unsigned)K_ST25_V_STREAM_NIBBLES_PER_BYTE; i++) {
    switch (data & K_ST25_V_DIBIT_MASK) {
      case K_ST25_V_DIBIT0:
        if (!nero_nfc_store_u8(out, (size_t)(out_max), (size_t)((*pos)++),
                               (uint8_t)(ST25_ISO15693_STREAM_00_1OF4))) {
          return false;
        }
        break;
      case K_ST25_V_DIBIT1:
        if (!nero_nfc_store_u8(out, (size_t)(out_max), (size_t)((*pos)++),
                               (uint8_t)(ST25_ISO15693_STREAM_01_1OF4))) {
          return false;
        }
        break;
      case K_ST25_V_DIBIT2:
        if (!nero_nfc_store_u8(out, (size_t)(out_max), (size_t)((*pos)++),
                               (uint8_t)(ST25_ISO15693_STREAM_10_1OF4))) {
          return false;
        }
        break;
      default:
        if (!nero_nfc_store_u8(out, (size_t)(out_max), (size_t)((*pos)++),
                               (uint8_t)(ST25_ISO15693_STREAM_11_1OF4))) {
          return false;
        }
        break;
    }
    data = (uint8_t)(data >> K_ST25_V_DIBIT_SHIFT);
  }
  return true;
}

NERO_NFC_NODISCARD bool st25_iso15693_stream_encode(const uint8_t* tx,
                                                    uint16_t tx_len,
                                                    uint8_t* out,
                                                    uint16_t out_max,
                                                    uint16_t* out_len) {
  uint16_t pos = 0u;
  uint16_t crc;

  if (out_len != NERO_NFC_NULL) {
    *out_len = 0u;
  }
  if ((tx == NERO_NFC_NULL) || (out == NERO_NFC_NULL) ||
      (out_len == NERO_NFC_NULL) || (tx_len == 0u) ||
      (out_max < K_ST25_V_CRC_LEN)) {
    return false;
  }
  if (!nero_nfc_store_u8(out, (size_t)(out_max), (size_t)(pos++),
                         (uint8_t)(ST25_ISO15693_STREAM_SOF_1OF4))) {
    return false;
  }
  for (uint16_t i = 0u; i < tx_len; i++) {
    if (!st25_iso15693_stream_put1of4(tx[i], out, out_max, &pos)) {
      return false;
    }
  }
  crc = st25_iso15693_crc16(tx, tx_len);
  if (!st25_iso15693_stream_put1of4((uint8_t)(crc & NFC_BYTE_VALUE_MAX), out,
                                    out_max, &pos) ||
      !st25_iso15693_stream_put1of4((uint8_t)(crc >> NFC_BYTE_SHIFT_8), out,
                                    out_max, &pos)) {
    return false;
  }
  if (!nero_nfc_store_u8(out, (size_t)(out_max), (size_t)(pos++),
                         (uint8_t)(ST25_ISO15693_STREAM_EOF_1OF4))) {
    return false;
  }
  *out_len = pos;
  return true;
}

uint8_t st25_iso15693_stream_bit(const uint8_t* buf, uint16_t buf_len,
                                 uint16_t bit_pos) {
  if (buf_len <= (bit_pos / NFC_BITS_PER_BYTE)) {
    return 0u;
  }
  return (uint8_t)(((unsigned)(nero_nfc_u8_at(
                        buf, (size_t)(buf_len),
                        (size_t)(bit_pos / NFC_BITS_PER_BYTE))) >>
                    (bit_pos % NFC_BITS_PER_BYTE)) &
                   0x01u);
}

int st25_iso15693_stream_decode(const uint8_t* in, uint16_t in_len,
                                uint8_t* out, uint16_t out_max) {
  uint8_t tmp[ST25_ISO15693_MAX_STREAM_FRAME];
  uint16_t manchester_pos = K_ST25_V_MANCHESTER_START_POS;
  uint16_t bit_pos = 0u;
  uint16_t byte_len;
  uint16_t crc;
  uint16_t zi;

  if ((in == NERO_NFC_NULL) || (out == NERO_NFC_NULL) ||
      (in_len < K_ST25_V_STREAM_MIN_IN_LEN) ||
      (in_len > ST25_ISO15693_MAX_STREAM_FRAME) ||
      ((nero_nfc_u8_at(in, (size_t)(in_len), (size_t)(0)) &
        K_ST25_V_SOF_MASK) != K_ST25_V_SOF_EXPECT)) {
    return -1;
  }

  for (zi = 0u; zi < (uint16_t)sizeof(tmp); zi++) {
    tmp[zi] = 0u;
  }

  while ((uint16_t)(manchester_pos + 1u) <
         (uint16_t)(in_len * NFC_BITS_PER_BYTE)) {
    uint8_t man;

    if (((bit_pos % NFC_BITS_PER_BYTE) == 0u) &&
        (((manchester_pos / NFC_BITS_PER_BYTE) + 1u) < in_len) &&
        ((in[manchester_pos / NFC_BITS_PER_BYTE] & K_ST25_V_EOF_HIGH_MASK) ==
         K_ST25_V_EOF_HIGH_EXPECT) &&
        (nero_nfc_u8_at(in, (size_t)(in_len),
                        (size_t)((manchester_pos / NFC_BITS_PER_BYTE) + 1u)) ==
         K_ST25_V_EOF_LOW_EXPECT)) {
      break;
    }
    if (bit_pos >= (uint16_t)(sizeof(tmp) * NFC_BITS_PER_BYTE)) {
      return -1;
    }

    man = st25_iso15693_stream_bit(in, in_len, manchester_pos);
    man = (uint8_t)(man |
                    (uint8_t)(st25_iso15693_stream_bit(
                                  in, in_len, (uint16_t)(manchester_pos + 1u))
                              << 1));
    if (man == K_ST25_V_MAN_ONE) {
      tmp[bit_pos / NFC_BITS_PER_BYTE] |=
          (uint8_t)(1u << (bit_pos % NFC_BITS_PER_BYTE));
    } else if (man != 0x01u) {
      return -1;
    }
    bit_pos++;
    manchester_pos = (uint16_t)(manchester_pos + K_ST25_V_MAN_STEP);
  }

  if ((bit_pos == 0u) || ((bit_pos % NFC_BITS_PER_BYTE) != 0u)) {
    return -1;
  }
  byte_len = (uint16_t)(bit_pos / NFC_BITS_PER_BYTE);
  if ((byte_len <= K_ST25_V_CRC_LEN) ||
      ((uint16_t)(byte_len - K_ST25_V_CRC_LEN) > out_max)) {
    return -1;
  }

  crc = st25_iso15693_crc16(tmp, (uint16_t)(byte_len - K_ST25_V_CRC_LEN));
  if ((tmp[byte_len - K_ST25_V_CRC_LEN] !=
       (uint8_t)(crc & NFC_BYTE_VALUE_MAX)) ||
      (tmp[byte_len - 1u] != (uint8_t)(crc >> NFC_BYTE_SHIFT_8))) {
    return -1;
  }
  for (uint16_t i = 0u; i < (uint16_t)(byte_len - K_ST25_V_CRC_LEN); i++) {
    out[i] = tmp[i];
  }
  return (int)(byte_len - K_ST25_V_CRC_LEN);
}

NERO_NFC_NODISCARD bool st25_iso15693_inventory(
    st25_iso15693_transceive_fn_t transceive, void* context,
    uint8_t uid_out[ST25_ISO15693_UID_LEN]) {
  uint8_t cmd[K_ST25_V_INVENTORY_CMD_CAP];
  uint8_t rx[K_ST25_V_INVENTORY_RX_CAP];
  int rlen;

  if (uid_out != NERO_NFC_NULL) {
    for (uint8_t i = 0u; i < ST25_ISO15693_UID_LEN; i++) {
      uid_out[i] = 0u;
    }
  }
  if ((transceive == NERO_NFC_NULL) || (uid_out == NERO_NFC_NULL)) {
    return false;
  }

  cmd[0] = ISO15693_FLAGS_INVENTORY; /* 1-slot inventory */
  cmd[1] = ISO15693_CMD_INVENTORY;
  cmd[K_ST25_V_IDX2] = 0x00u; /* mask length = 0 */

  rlen = transceive(context, cmd, sizeof(cmd), rx, sizeof(rx),
                    K_ST25_V_INVENTORY_TIMEOUT_MS);
  if (rlen < K_ST25_V_INVENTORY_MIN_RX) {
    return false;
  }
  if ((rx[0] & 0x01u) != 0u) {
    return false; /* response error flag */
  }
  /* rx[0]=flags, rx[1]=DSFID, rx[2..9]=UID (LSB first). Skip DSFID, then
   * reverse the 8-byte UID. */
  for (uint8_t i = 0u; i < ST25_ISO15693_UID_LEN; i++) {
    uid_out[i] =
        rx[K_ST25_V_INVENTORY_UID_RX_OFF + (ST25_ISO15693_UID_LEN - 1u - i)];
  }
  return true;
}

int st25_iso15693_read_block(st25_iso15693_transceive_fn_t transceive,
                             void* context,
                             const uint8_t uid[ST25_ISO15693_UID_LEN],
                             uint8_t block_addr, uint8_t* buf,
                             uint8_t buf_len) {
  uint8_t cmd[K_ST25_V_READ_CMD_CAP];
  uint8_t rx[K_ST25_V_READ_RX_CAP];
  int rlen;
  uint8_t copy_len;
  uint8_t n = 0u;

  if ((transceive == NERO_NFC_NULL) || (uid == NERO_NFC_NULL) ||
      (buf == NERO_NFC_NULL)) {
    return -1;
  }

  cmd[n++] = NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED;
  cmd[n++] = ISO15693_CMD_READ_SINGLE_BLOCK;
  for (uint8_t i = 0u; i < ST25_ISO15693_UID_LEN; i++) {
    cmd[n++] = uid[ST25_ISO15693_UID_LEN - 1u - i];
  }
  cmd[n++] = block_addr;

  rlen = transceive(context, cmd, n, rx, sizeof(rx), K_ST25_V_READ_TIMEOUT_MS);
  if (rlen < K_ST25_V_MIN_STATUS_RX) {
    return -1;
  }
  if ((rx[0] & 0x01u) != 0u) {
    return -1;
  }
  copy_len = (uint8_t)(rlen - 1);
  if (copy_len > buf_len) {
    copy_len = buf_len;
  }
  if (!nero_nfc_copy_bytes(buf, buf_len, 0u, &rx[1], copy_len)) {
    return -1;
  }
  return (int)(copy_len);
}

NERO_NFC_NODISCARD bool st25_iso15693_write_block(
    st25_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[ST25_ISO15693_UID_LEN], uint8_t block_addr,
    const uint8_t* data, uint8_t data_len) {
  uint8_t cmd[K_ST25_V_WRITE_CMD_CAP];
  uint8_t rx[K_ST25_V_WRITE_RX_CAP];
  int rlen;
  uint8_t n = 0u;

  if ((transceive == NERO_NFC_NULL) || (uid == NERO_NFC_NULL) ||
      (data == NERO_NFC_NULL) || (data_len == 0u) ||
      (data_len > K_ST25_V_MAX_BLOCK_DATA)) {
    return false;
  }

  cmd[n++] = NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED;
  cmd[n++] = ISO15693_CMD_WRITE_SINGLE_BLOCK;
  for (uint8_t i = 0u; i < ST25_ISO15693_UID_LEN; i++) {
    cmd[n++] = uid[ST25_ISO15693_UID_LEN - 1u - i];
  }
  cmd[n++] = block_addr;
  for (uint8_t i = 0u; i < data_len; i++) {
    cmd[n++] = data[i];
  }

  rlen = transceive(context, cmd, n, rx, sizeof(rx), K_ST25_V_WRITE_TIMEOUT_MS);
  if (rlen < 1) {
    return false;
  }
  return (rx[0] & 0x01u) == 0u;
}

NERO_NFC_NODISCARD bool st25_iso15693_get_system_info(
    st25_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[ST25_ISO15693_UID_LEN], uint16_t* nb_blocks_out,
    uint8_t* block_size_out) {
  uint8_t cmd[K_ST25_V_GET_SYS_INFO_CMD_CAP];
  uint8_t rx[K_ST25_V_GET_SYS_INFO_RX_CAP];
  int rlen;
  uint8_t info_flags;
  uint8_t pos;
  uint8_t n = 0u;

  if (nb_blocks_out != NERO_NFC_NULL) {
    *nb_blocks_out = 0u;
  }
  if (block_size_out != NERO_NFC_NULL) {
    *block_size_out = 0u;
  }
  if (transceive == NERO_NFC_NULL) {
    return false;
  }

  cmd[n++] = NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED;
  cmd[n++] = NFC_TAG_T5T_ISO15693_CMD_GET_SYS_INFO;
  if (uid != NERO_NFC_NULL) {
    for (uint8_t i = 0u; i < ST25_ISO15693_UID_LEN; i++) {
      cmd[n++] = uid[ST25_ISO15693_UID_LEN - 1u - i];
    }
  } else {
    /*
     * Spec allows unaddressed GetSystemInfo (Address flag = 0). Re-encode
     * the request flags accordingly so the tag does not expect the UID.
     */
    cmd[0] = ISO15693_FLAG_DATA_RATE;
  }

  rlen = transceive(context, cmd, n, rx, sizeof(rx), K_ST25_V_READ_TIMEOUT_MS);
  if (rlen < K_ST25_V_GET_SYS_INFO_MIN_RX) {
    return false;
  }
  if ((rx[0] & 0x01u) != 0u) {
    return false;
  }

  info_flags = rx[1];
  pos = (uint8_t)(K_ST25_V_INVENTORY_UID_RX_OFF + ST25_ISO15693_UID_LEN);
  if ((info_flags & 0x01u) != 0u) {
    pos++; /* skip DSFID */
  }
  if ((info_flags & K_ST25_V_INFO_FLAG_DSFID) != 0u) {
    pos++; /* skip AFI */
  }
  if ((info_flags & K_ST25_V_INFO_FLAG_AFI) == 0u) {
    return false;
  }
  if ((uint16_t)(pos + K_ST25_V_MEM_SIZE_FIELD_LEN) > (uint16_t)(rlen)) {
    return false;
  }
  if (nb_blocks_out != NERO_NFC_NULL) {
    *nb_blocks_out = (uint16_t)((uint16_t)(rx[pos]) + 1u);
  }
  if (block_size_out != NERO_NFC_NULL) {
    *block_size_out = (uint8_t)((rx[pos + 1u] & K_ST25_V_BLOCK_SIZE_MASK) + 1u);
  }
  return true;
}

int st25_iso15693_ext_read_block(st25_iso15693_transceive_fn_t transceive,
                                 void* context,
                                 const uint8_t uid[ST25_ISO15693_UID_LEN],
                                 uint16_t block_addr, uint8_t* buf,
                                 uint8_t buf_len) {
  uint8_t cmd[K_ST25_V_READ_CMD_CAP];
  uint8_t rx[K_ST25_V_READ_RX_CAP];
  int rlen;
  uint8_t copy_len;
  uint8_t n = 0u;

  if ((transceive == NERO_NFC_NULL) || (uid == NERO_NFC_NULL) ||
      (buf == NERO_NFC_NULL)) {
    return -1;
  }

  cmd[n++] = (uint8_t)(NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED |
                       NFC_TAG_T5T_ISO15693_FLAG_PROTOCOL_EXTENSION);
  cmd[n++] = ISO15693_CMD_EXT_READ_SINGLE;
  for (uint8_t i = 0u; i < ST25_ISO15693_UID_LEN; i++) {
    cmd[n++] = uid[ST25_ISO15693_UID_LEN - 1u - i];
  }
  cmd[n++] = (uint8_t)(block_addr & NFC_BYTE_VALUE_MAX);
  cmd[n++] = (uint8_t)(block_addr >> NFC_BYTE_SHIFT_8);

  rlen = transceive(context, cmd, n, rx, sizeof(rx), K_ST25_V_READ_TIMEOUT_MS);
  if (rlen < K_ST25_V_MIN_STATUS_RX) {
    return -1;
  }
  if ((rx[0] & 0x01u) != 0u) {
    return -1; /* tag returned an error code */
  }
  copy_len = (uint8_t)(rlen - 1);
  if (copy_len > buf_len) {
    copy_len = buf_len;
  }
  if (!nero_nfc_copy_bytes(buf, buf_len, 0u, &rx[1], copy_len)) {
    return -1;
  }
  return (int)(copy_len);
}

NERO_NFC_NODISCARD bool st25_iso15693_ext_write_block(
    st25_iso15693_transceive_fn_t transceive, void* context,
    const uint8_t uid[ST25_ISO15693_UID_LEN], uint16_t block_addr,
    const uint8_t* data, uint8_t data_len) {
  uint8_t cmd[K_ST25_V_WRITE_CMD_CAP];
  uint8_t rx[K_ST25_V_WRITE_RX_CAP];
  int rlen;
  uint8_t n = 0u;

  if ((transceive == NERO_NFC_NULL) || (uid == NERO_NFC_NULL) ||
      (data == NERO_NFC_NULL) || (data_len == 0u) ||
      (data_len > K_ST25_V_MAX_BLOCK_DATA)) {
    return false;
  }

  cmd[n++] = (uint8_t)(NFC_TAG_T5T_ISO15693_FLAGS_ADDRESSED |
                       NFC_TAG_T5T_ISO15693_FLAG_PROTOCOL_EXTENSION);
  cmd[n++] = ISO15693_CMD_EXT_WRITE_SINGLE;
  for (uint8_t i = 0u; i < ST25_ISO15693_UID_LEN; i++) {
    cmd[n++] = uid[ST25_ISO15693_UID_LEN - 1u - i];
  }
  cmd[n++] = (uint8_t)(block_addr & NFC_BYTE_VALUE_MAX);
  cmd[n++] = (uint8_t)(block_addr >> NFC_BYTE_SHIFT_8);
  for (uint8_t i = 0u; i < data_len; i++) {
    cmd[n++] = data[i];
  }

  /*
   * Programming time: ST25DV / ST25TV datasheets specify ≤5 ms typical.
   * 60 ms is generous and forgiving of weak coupling.
   */
  rlen = transceive(context, cmd, n, rx, sizeof(rx), K_ST25_V_WRITE_TIMEOUT_MS);
  if (rlen < 1) {
    return false;
  }
  return (rx[0] & 0x01u) == 0u;
}
