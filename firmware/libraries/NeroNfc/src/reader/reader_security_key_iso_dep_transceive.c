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
#include "reader_security_key_iso_dep_transceive.h"

#include "nfc_ctap_codec.h"
#include "nfc_pcsc_contactless.h"
#include "nero_nfc_mem_util.h"
#include "reader_context.h"
#include "reader_hal.h"
#include "reader_iso_dep_apdu_relay.h"
#include "reader_iso_dep_frame.h"
#include "reader_iso_dep_timing.h"
#include "reader_output.h"
#include "reader_security_key_iso_dep_session.h"
#include "reader_iso_dep_debug.h"

#include <stdbool.h>
#include <stdint.h>
#include "nero_nfc_format.h"

enum {
  READER_ISO_DEP_ERR_NONE = 0u,
  READER_ISO_DEP_ERR_TRANSCEIVE_TIMEOUT = 0x01u,
  READER_ISO_DEP_ERR_TX_CHAIN_WTX_DEADLINE = 0x03u,
  READER_ISO_DEP_ERR_TX_CHAIN_WTX_SHORT = 0x04u,
  READER_ISO_DEP_ERR_TX_CHAIN_WTX_OVERFLOW = 0x05u,
  READER_ISO_DEP_ERR_TX_CHAIN_WTX_ECHO_TIMEOUT = 0x06u,
  READER_ISO_DEP_ERR_TX_CHAIN_RNAK_LIMIT = 0x07u,
  READER_ISO_DEP_ERR_TX_CHAIN_RNAK_RESEND_TIMEOUT = 0x08u,
  READER_ISO_DEP_ERR_TX_CHAIN_UNEXPECTED_FRAME = 0x09u,
  READER_ISO_DEP_ERR_RECV_WTX_DEADLINE = 0x0Au,
  READER_ISO_DEP_ERR_RECV_WTX_SHORT = 0x0Bu,
  READER_ISO_DEP_ERR_RECV_WTX_OVERFLOW = 0x0Cu,
  READER_ISO_DEP_ERR_RECV_WTX_ECHO_TIMEOUT = 0x0Du,
  READER_ISO_DEP_ERR_RECV_I_BLOCK_SHORT = 0x0Eu,
  READER_ISO_DEP_ERR_RECV_COPY_INF = 0x0Fu,
  READER_ISO_DEP_ERR_RECV_CHAINED_ACK_TIMEOUT = 0x10u,
  READER_ISO_DEP_ERR_RECV_I_BLOCK_NUMBER = 0x11u,
  READER_ISO_DEP_ERR_RECV_INF_DROPPED = 0x12u,
  READER_ISO_DEP_ERR_INCOMPLETE_IBLOCK = 0x13u,
  READER_ISO_DEP_ERR_TX_CHAIN_CCID_ABORT = 0x16u,
  READER_ISO_DEP_ERR_RECV_CCID_ABORT = 0x17u,
  READER_ISO_DEP_CHAIN_RNAK_MAX = 2u,
  ISO_DEP_DUMP_APDU_HEAD = 36u,
  ISO_DEP_DUMP_TX_WIRE = 28u,
  ISO_DEP_DUMP_RX_RAW = 80u,
  ISO_DEP_DUMP_UNEXPECTED_FRAME = 48u,
  ISO_DEP_DUMP_RX_POST_WTX = 64u,
  ISO_DEP_DUMP_RX_ORPHAN = 80u,
  ISO_DEP_DUMP_RESP_CHUNK = 96u,
  ISO_DEP_DUMP_CMD_APDU = 48u,
  ISO_DEP_DUMP_FINAL_RESP = 96u,
  READER_ISO_DEP_WTX_ECHO_TX_CAP = 8u,
  READER_ISO_DEP_CHAIN_ACK_TX_CAP = 4u,
  ISO_DEP_WTX_LOG_MIN = 3u,
  /* [DERIVED] S(WTX) recognition mask; not a standalone ISO14443-4 SPEC entry.
   * File-local: only this TU matches PCB against ISO_DEP_PCB_S_WTX. */
  ISO_DEP_PCB_SWTX_MASK = 0xF7u,
};

static void iso_dep_note_wtx_wait(uint16_t wtx_count, uint32_t total_start_ms) {
#if !defined(NERO_CCID_USB_BUILD)
  (void)total_start_ms;
#endif
  reader_security_key_iso_dep_ccid_heartbeat();
  if ((G_ISO_DEP_TRACE == 0u) || (wtx_count < ISO_DEP_WTX_LOG_MIN)) {
    return;
  }
  nero_nfc_log_write("[ISO-DEP] waiting on S(WTX) x");
  {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                            (unsigned)((uint32_t)(wtx_count)));
    nero_nfc_log_write(ndc);
  }
  nero_nfc_log_write(" (~");
  {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(
        ndc, sizeof ndc, "%u",
        (unsigned)(reader_iso_dep_ms_to_seconds(reader_hal_millis()) -
                   total_start_ms));
    nero_nfc_log_write(ndc);
  }
  nero_nfc_log_write(
      "s): authenticator is alive and likely waiting for user presence; "
      "keep the key on the "
      "reader and touch the sensor if required.\r\n");
}

bool reader_security_key_ccid_abort_pending(void) {
#if defined(NERO_CCID_USB_BUILD)
  uint8_t slot = 0u;
  uint8_t seq = 0u;
  return reader_hal_ccid_abort_request_pending(&slot, &seq);
#else
  return false;
#endif
}

/* Safe room in `resp` after `used` bytes — avoids uint16_t underflow in GET
 * RESPONSE tail math. */
static uint16_t reader_security_key_resp_tail_cap(uint16_t resp_buf_len,
                                                  uint16_t used) {
  if (used >= resp_buf_len) {
    return 0u;
  }
  return (uint16_t)(resp_buf_len - used);
}

static int reader_security_key_send_i_block(const uint8_t* apdu,
                                            uint16_t apdu_len, uint8_t* resp,
                                            uint16_t resp_buf_len,
                                            uint16_t frame_timeout_ms) {
  uint8_t* tx = G_ISO_DEP_IBLOCK_TX;
  uint8_t rx[READER_ISO_DEP_IBLOCK_RX_BUF_LEN];
  uint16_t total = 0u;
  uint16_t wtx_count = 0u;
  int rlen = 0;
  uint8_t expected_block;
  uint32_t total_start_ms = reader_hal_millis();
  const bool add_nad = reader_security_key_iso_dep_tx_add_nad(apdu_len, apdu);
  const uint8_t tx_hdr_len = reader_security_key_iso_dep_tx_hdr_len(add_nad);
  bool completed_iblock = false;
  uint16_t apdu_off = 0u;
  uint8_t blk_sent = 0u;
  const uint16_t frag_cap =
      reader_security_key_iso_dep_apdu_chunk_budget(tx_hdr_len);
  const uint16_t link_timeout_ms =
      reader_security_key_iso_dep_link_response_timeout_ms();

  if (((apdu == NERO_NFC_NULL) && (apdu_len != 0u)) ||
      (resp == NERO_NFC_NULL)) {
    nero_nfc_secure_clear(rx, sizeof(rx));
    return -1;
  }
  if ((frag_cap == 0u) || (tx_hdr_len == 0u)) {
    if (G_ISO_DEP_TRACE != 0u) {
      nero_nfc_log_line(
          "[ISO-DEP] send_i_block FAIL: frag_cap or tx_hdr_len invalid");
    }
    nero_nfc_secure_clear(rx, sizeof(rx));
    return -1;
  }

  if (G_ISO_DEP_TRACE != 0u) {
    nero_nfc_log_write("[ISO-DEP] send_i_block apdu_len=");
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                              (unsigned)((uint32_t)(apdu_len)));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_write(" tx_hdr=");
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                              (unsigned)((uint32_t)(tx_hdr_len)));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_write(" nad=");
    nero_nfc_log_write(add_nad ? "1" : "0");
    nero_nfc_log_write(" frag_cap=");
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                              (unsigned)((uint32_t)(frag_cap)));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_write(" g_block_num=");
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                              (unsigned)((uint32_t)(G_BLOCK_NUM)));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_write("\r\n");
    reader_iso_dep_debug_dump("APDU head", apdu, apdu_len,
                              ISO_DEP_DUMP_APDU_HEAD);
  }

  while (apdu_off < apdu_len) {
    blk_sent = (uint8_t)(G_BLOCK_NUM & ISO_DEP_BLOCK_NUM_MASK);
    reader_iso_dep_i_block_tx_t tx_info;

    if (!reader_iso_dep_build_i_block_tx(
            tx, ISO_DEP_IBLOCK_TX_BUF_LEN, apdu, apdu_len, apdu_off, frag_cap,
            G_ISO_DEP_PCB_HAS_CID, G_ISO_DEP_CID, add_nad, ISO_DEP_TX_NAD_VALUE,
            blk_sent, &tx_info)) {
      if (G_ISO_DEP_TRACE != 0u) {
        nero_nfc_log_line(
            "[ISO-DEP] send_i_block FAIL: build I-block TX fragment");
      }
      nero_nfc_secure_clear(rx, sizeof(rx));
      return -1;
    }
    if (G_ISO_DEP_TRACE != 0u) {
      nero_nfc_log_write("[ISO-DEP] TX frag apdu_off=");
      {
        char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
        (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                (unsigned)((uint32_t)(apdu_off)));
        nero_nfc_log_write(ndc);
      }
      nero_nfc_log_write(" frag_len=");
      {
        char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
        (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                (unsigned)((uint32_t)(tx_info.frag_len)));
        nero_nfc_log_write(ndc);
      }
      nero_nfc_log_write(" chain_more=");
      nero_nfc_log_write(tx_info.chain_more ? "1" : "0");
      nero_nfc_log_write(" blk_sent=");
      {
        char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
        (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                (unsigned)((uint32_t)(blk_sent)));
        nero_nfc_log_write(ndc);
      }
      nero_nfc_log_write(" pcb_tx=0x");
      {
        char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
        (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X",
                                (unsigned)(tx_info.pcb));
        nero_nfc_log_write(nhx);
      }
      nero_nfc_log_write(" wire_len=");
      {
        char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
        (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                (unsigned)((uint32_t)(tx_info.wire_len)));
        nero_nfc_log_write(ndc);
      }
      nero_nfc_log_write("\r\n");
      reader_iso_dep_debug_dump("TX wire", tx, tx_info.wire_len,
                                ISO_DEP_DUMP_TX_WIRE);
    }
    rlen = reader_security_key_iso_dep_transceive(
        tx, tx_info.wire_len, rx, sizeof(rx), true, link_timeout_ms);
    if (rlen < 1) {
      if (G_ISO_DEP_TRACE != 0u) {
        nero_nfc_log_write(
            "[ISO-DEP] send_i_block FAIL: security_key_transceive timeout "
            "rlen<1\r\n");
      }
      reader_security_key_iso_dep_snap_raw_rx(NERO_NFC_NULL, 0);
      reader_security_key_iso_dep_set_last_error(
          READER_ISO_DEP_ERR_TRANSCEIVE_TIMEOUT);
      nero_nfc_secure_clear(rx, sizeof(rx));
      return -1;
    }
    reader_security_key_iso_dep_snap_raw_rx(rx, rlen);
    if (G_ISO_DEP_TRACE != 0u) {
      nero_nfc_log_write("[ISO-DEP] RX rlen=");
      {
        char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
        (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)((int32_t)(rlen)));
        nero_nfc_log_write(ndc);
      }
      nero_nfc_log_write(" cls=");
      if ((rx[0] & ISO_DEP_PCB_CLASS_MASK) == ISO_DEP_PCB_CLASS_I_BLOCK) {
        nero_nfc_log_write("I");
      } else if ((rx[0] & ISO_DEP_PCB_CLASS_MASK) ==
                 ISO_DEP_PCB_CLASS_R_BLOCK) {
        nero_nfc_log_write("R");
      } else if ((rx[0] & ISO_DEP_PCB_CLASS_MASK) ==
                 ISO_DEP_PCB_CLASS_S_BLOCK) {
        nero_nfc_log_write("S");
      } else {
        nero_nfc_log_write("?");
      }
      nero_nfc_log_write(" pcb=0x");
      {
        char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
        (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(rx[0]));
        nero_nfc_log_write(nhx);
      }
      nero_nfc_log_write("\r\n");
      reader_iso_dep_debug_dump("RX raw", rx, (uint16_t)(rlen),
                                ISO_DEP_DUMP_RX_RAW);
    }
    if (tx_info.chain_more) {
      uint8_t rnak_retries = 0u;

      for (;;) {
        uint8_t pcb = rx[0];
        uint8_t hdr_skip = reader_iso_dep_rx_hdr_skip(pcb);

        if ((pcb & ISO_DEP_PCB_SWTX_MASK) == ISO_DEP_PCB_S_WTX) {
          uint8_t wtx_tx[READER_ISO_DEP_WTX_ECHO_TX_CAP];
          uint8_t wtx_len;

          if ((reader_hal_millis() - total_start_ms) >
              (uint32_t)(frame_timeout_ms)) {
            if (G_ISO_DEP_TRACE != 0u) {
              nero_nfc_log_line(
                  "[ISO-DEP] TX-chain FAIL: total WTX deadline exceeded");
            }
            reader_security_key_iso_dep_set_last_error(
                READER_ISO_DEP_ERR_TX_CHAIN_WTX_DEADLINE);
            nero_nfc_secure_clear(rx, sizeof(rx));
            return -1;
          }
          if (reader_security_key_ccid_abort_pending()) {
            if (G_ISO_DEP_TRACE != 0u) {
              nero_nfc_log_line("[ISO-DEP] TX-chain aborted by CCID host");
            }
            reader_security_key_iso_dep_set_last_error(
                READER_ISO_DEP_ERR_TX_CHAIN_CCID_ABORT);
            nero_nfc_secure_clear(rx, sizeof(rx));
            return -1;
          }

          if (!reader_iso_dep_build_wtx_echo(wtx_tx, sizeof(wtx_tx), rx, rlen,
                                             hdr_skip, &wtx_len)) {
            if (G_ISO_DEP_TRACE != 0u) {
              if (rlen < (hdr_skip + ISO_DEP_HDR_BASE_LEN)) {
                nero_nfc_log_line("[ISO-DEP] TX-chain FAIL: WTX rx too short");
              } else {
                nero_nfc_log_line("[ISO-DEP] TX-chain FAIL: WTX len overflow");
              }
            }
            reader_security_key_iso_dep_set_last_error(
                (rlen < (hdr_skip + ISO_DEP_HDR_BASE_LEN))
                    ? READER_ISO_DEP_ERR_TX_CHAIN_WTX_SHORT
                    : READER_ISO_DEP_ERR_TX_CHAIN_WTX_OVERFLOW);
            nero_nfc_secure_clear(rx, sizeof(rx));
            return -1;
          }
          rlen = reader_security_key_iso_dep_transceive(
              wtx_tx, wtx_len, rx, sizeof(rx), true,
              reader_security_key_iso_dep_wtx_response_timeout_ms(rx, rlen,
                                                                  hdr_skip));
          wtx_count++;
          iso_dep_note_wtx_wait(wtx_count, total_start_ms);
          if (rlen < 1) {
            if (G_ISO_DEP_TRACE != 0u) {
              nero_nfc_log_line(
                  "[ISO-DEP] TX-chain FAIL: timeout after WTX echo");
            }
            reader_security_key_iso_dep_snap_raw_rx(NERO_NFC_NULL, 0);
            reader_security_key_iso_dep_set_last_error(
                READER_ISO_DEP_ERR_TX_CHAIN_WTX_ECHO_TIMEOUT);
            nero_nfc_secure_clear(rx, sizeof(rx));
            return -1;
          }
          reader_security_key_iso_dep_snap_raw_rx(rx, rlen);
          continue;
        }
        if (reader_security_key_iso_dep_rx_is_chain_nak_for_block(rx, rlen,
                                                                  blk_sent)) {
          if (rnak_retries >= READER_ISO_DEP_CHAIN_RNAK_MAX) {
            if (G_ISO_DEP_TRACE != 0u) {
              nero_nfc_log_write(
                  "[ISO-DEP] TX-chain FAIL: repeated R-NAK after blk_sent=");
              {
                char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
                (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                        (unsigned)((uint32_t)(blk_sent)));
                nero_nfc_log_write(ndc);
              }
              nero_nfc_log_write("\r\n");
            }
            reader_security_key_iso_dep_set_last_error(
                READER_ISO_DEP_ERR_TX_CHAIN_RNAK_LIMIT);
            nero_nfc_secure_clear(rx, sizeof(rx));
            return -1;
          }
          rnak_retries++;
          if (G_ISO_DEP_TRACE != 0u) {
            nero_nfc_log_write("[ISO-DEP] TX-chain R-NAK retry=");
            {
              char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
              (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                      (unsigned)((uint32_t)(rnak_retries)));
              nero_nfc_log_write(ndc);
            }
            nero_nfc_log_write(" blk_sent=");
            {
              char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
              (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                      (unsigned)((uint32_t)(blk_sent)));
              nero_nfc_log_write(ndc);
            }
            nero_nfc_log_write("\r\n");
          }
          rlen = reader_security_key_iso_dep_transceive(
              tx, tx_info.wire_len, rx, sizeof(rx), true, link_timeout_ms);
          if (rlen < 1) {
            if (G_ISO_DEP_TRACE != 0u) {
              nero_nfc_log_line(
                  "[ISO-DEP] TX-chain FAIL: timeout after R-NAK resend");
            }
            reader_security_key_iso_dep_snap_raw_rx(NERO_NFC_NULL, 0);
            reader_security_key_iso_dep_set_last_error(
                READER_ISO_DEP_ERR_TX_CHAIN_RNAK_RESEND_TIMEOUT);
            nero_nfc_secure_clear(rx, sizeof(rx));
            return -1;
          }
          reader_security_key_iso_dep_snap_raw_rx(rx, rlen);
          continue;
        }
        uint8_t ack_block = 0u;
        if (reader_security_key_iso_dep_rx_is_chain_ack_for_block(
                rx, rlen, blk_sent, &ack_block)) {
          if (G_ISO_DEP_TRACE != 0u) {
            nero_nfc_log_write("[ISO-DEP] TX-chain R-ACK ok ack_block=");
            {
              char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
              (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                      (unsigned)((uint32_t)(ack_block)));
              nero_nfc_log_write(ndc);
            }
            nero_nfc_log_write(" next_block=");
            {
              char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
              (void)nero_nfc_snprintf(
                  ndc, sizeof ndc, "%u",
                  (unsigned)((uint32_t)((blk_sent ^ ISO_DEP_BLOCK_NUM_MASK))));
              nero_nfc_log_write(ndc);
            }
            nero_nfc_log_write(" after blk_sent=");
            {
              char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
              (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                      (unsigned)((uint32_t)(blk_sent)));
              nero_nfc_log_write(ndc);
            }
            nero_nfc_log_write("\r\n");
          }
          break;
        }
        if (reader_iso_dep_rx_rblock_block(rx, rlen, false,
                                           G_ISO_DEP_PCB_HAS_CID, G_ISO_DEP_CID,
                                           &ack_block)) {
          /* [ISO14443-4] §7.5.4 Rule 6 — a valid R(ACK) whose block number
           * differs from the current PCD number requests retransmission of the
           * last chained I-block. It is not an unrecoverable protocol error. */
          if (rnak_retries >= READER_ISO_DEP_CHAIN_RNAK_MAX) {
            reader_security_key_iso_dep_set_last_error(
                READER_ISO_DEP_ERR_TX_CHAIN_UNEXPECTED_FRAME);
            nero_nfc_secure_clear(rx, sizeof(rx));
            return -1;
          }
          rnak_retries++;
          rlen = reader_security_key_iso_dep_transceive(
              tx, tx_info.wire_len, rx, sizeof(rx), true, link_timeout_ms);
          if (rlen < 1) {
            reader_security_key_iso_dep_snap_raw_rx(NERO_NFC_NULL, 0);
            reader_security_key_iso_dep_set_last_error(
                READER_ISO_DEP_ERR_TX_CHAIN_RNAK_RESEND_TIMEOUT);
            nero_nfc_secure_clear(rx, sizeof(rx));
            return -1;
          }
          reader_security_key_iso_dep_snap_raw_rx(rx, rlen);
          continue;
        }
        if (G_ISO_DEP_TRACE != 0u) {
          nero_nfc_log_write(
              "[ISO-DEP] TX-chain FAIL: expected R-ACK next_block=");
          {
            char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
            (void)nero_nfc_snprintf(
                ndc, sizeof ndc, "%u",
                (unsigned)((uint32_t)((blk_sent ^ ISO_DEP_BLOCK_NUM_MASK))));
            nero_nfc_log_write(ndc);
          }
          nero_nfc_log_write(" after blk_sent=");
          {
            char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
            (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                    (unsigned)((uint32_t)(blk_sent)));
            nero_nfc_log_write(ndc);
          }
          nero_nfc_log_write(" CID=");
          {
            char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
            (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                    (unsigned)((uint32_t)(G_ISO_DEP_CID)));
            nero_nfc_log_write(ndc);
          }
          nero_nfc_log_write("\r\n");
          reader_iso_dep_debug_dump("unexpected frame", rx, (uint16_t)(rlen),
                                    ISO_DEP_DUMP_UNEXPECTED_FRAME);
        }
        reader_security_key_iso_dep_set_last_error(
            READER_ISO_DEP_ERR_TX_CHAIN_UNEXPECTED_FRAME);
        nero_nfc_secure_clear(rx, sizeof(rx));
        return -1;
      }
      apdu_off = (uint16_t)(apdu_off + tx_info.frag_len);
      G_BLOCK_NUM ^= ISO_DEP_BLOCK_NUM_MASK;
      continue;
    }
    break;
  }

  expected_block = G_BLOCK_NUM;
  while (rlen > 0) {
    uint8_t pcb = rx[0];
    uint8_t hdr_skip = reader_iso_dep_rx_hdr_skip(pcb);

    if ((pcb & ISO_DEP_PCB_SWTX_MASK) == ISO_DEP_PCB_S_WTX) {
      /* Wait-time extension — echo PICC S(WTX) prefix including optional
       * CID/NAD */
      uint8_t wtx_tx[READER_ISO_DEP_WTX_ECHO_TX_CAP];
      uint8_t wtx_len;

      if ((reader_hal_millis() - total_start_ms) >
          (uint32_t)(frame_timeout_ms)) {
        if (G_ISO_DEP_TRACE != 0u) {
          nero_nfc_log_line("[ISO-DEP] recv FAIL: total WTX deadline exceeded");
        }
        reader_security_key_iso_dep_set_last_error(
            READER_ISO_DEP_ERR_RECV_WTX_DEADLINE);
        nero_nfc_secure_clear(rx, sizeof(rx));
        return -1;
      }
      if (reader_security_key_ccid_abort_pending()) {
        if (G_ISO_DEP_TRACE != 0u) {
          nero_nfc_log_line("[ISO-DEP] recv aborted by CCID host");
        }
        reader_security_key_iso_dep_set_last_error(
            READER_ISO_DEP_ERR_RECV_CCID_ABORT);
        nero_nfc_secure_clear(rx, sizeof(rx));
        return -1;
      }

      if (!reader_iso_dep_build_wtx_echo(wtx_tx, sizeof(wtx_tx), rx, rlen,
                                         hdr_skip, &wtx_len)) {
        if (G_ISO_DEP_TRACE != 0u) {
          if (rlen < (hdr_skip + ISO_DEP_HDR_BASE_LEN)) {
            nero_nfc_log_line("[ISO-DEP] recv WTX: hdr too short");
          } else {
            nero_nfc_log_line("[ISO-DEP] recv WTX: len overflow");
          }
        }
        reader_security_key_iso_dep_set_last_error(
            (rlen < (hdr_skip + ISO_DEP_HDR_BASE_LEN))
                ? READER_ISO_DEP_ERR_RECV_WTX_SHORT
                : READER_ISO_DEP_ERR_RECV_WTX_OVERFLOW);
        nero_nfc_secure_clear(rx, sizeof(rx));
        return -1;
      }
      rlen = reader_security_key_iso_dep_transceive(
          wtx_tx, wtx_len, rx, sizeof(rx), true,
          reader_security_key_iso_dep_wtx_response_timeout_ms(rx, rlen,
                                                              hdr_skip));
      wtx_count++;
      iso_dep_note_wtx_wait(wtx_count, total_start_ms);
      if ((rlen < 1) && (G_ISO_DEP_TRACE != 0u)) {
        nero_nfc_log_line("[ISO-DEP] recv FAIL: timeout after S(WTX) echo");
      }
      if (rlen < 1) {
        reader_security_key_iso_dep_set_last_error(
            READER_ISO_DEP_ERR_RECV_WTX_ECHO_TIMEOUT);
        nero_nfc_secure_clear(rx, sizeof(rx));
        return -1;
      }
      reader_security_key_iso_dep_snap_raw_rx(rx, rlen);
      if (G_ISO_DEP_TRACE != 0u) {
        nero_nfc_log_write("[ISO-DEP] recv after WTX echo rlen=");
        {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d",
                                  (int)((int32_t)(rlen)));
          nero_nfc_log_write(ndc);
        }
        nero_nfc_log_write("\r\n");
        reader_iso_dep_debug_dump("RX post-WTX", rx, (uint16_t)(rlen),
                                  ISO_DEP_DUMP_RX_POST_WTX);
      }
      continue;
    }
    if ((pcb & ISO_DEP_PCB_CLASS_MASK) == ISO_DEP_PCB_CLASS_I_BLOCK) {
      uint16_t inf_len;
      uint8_t inf_off = reader_security_key_iso_dep_pick_inf_offset(rx, rlen);

      if (!reader_iso_dep_rx_i_block_number_matches(rx, rlen, expected_block)) {
        if (G_ISO_DEP_TRACE != 0u) {
          nero_nfc_log_write(
              "[ISO-DEP] recv I-block FAIL: block number mismatch expected=");
          nero_nfc_log_write((expected_block & ISO_DEP_BLOCK_NUM_MASK) != 0u
                                 ? "1\r\n"
                                 : "0\r\n");
        }
        reader_security_key_iso_dep_set_last_error(
            READER_ISO_DEP_ERR_RECV_I_BLOCK_NUMBER);
        nero_nfc_secure_clear(rx, sizeof(rx));
        return -1;
      }
      G_ISO_DEP_LAST_INF_OFF = inf_off;
      if (!reader_iso_dep_i_block_inf_len(rx, rlen, inf_off, pcb, &inf_len,
                                          NERO_NFC_NULL)) {
        if (G_ISO_DEP_TRACE != 0u) {
          nero_nfc_log_write(
              "[ISO-DEP] recv I-block FAIL: rlen < inf_off+2 (frame too "
              "short)\r\n");
        }
        reader_security_key_iso_dep_set_last_error(
            READER_ISO_DEP_ERR_RECV_I_BLOCK_SHORT);
        nero_nfc_secure_clear(rx, sizeof(rx));
        return -1;
      }
      /* Strip RF CRC-A on intermediate chained frames only when it is present
       * in the FIFO. Keep final I-block tails intact so real APDU status words
       * such as 90 00 cannot be mistaken for CRC by coincidence. */
      bool appended_inf = false;
      if (!reader_iso_dep_append_inf(resp, resp_buf_len, &total, &rx[inf_off],
                                     inf_len, &appended_inf)) {
        if (G_ISO_DEP_TRACE != 0u) {
          nero_nfc_log_line("[ISO-DEP] recv FAIL: nero_nfc_copy_bytes INF");
        }
        reader_security_key_iso_dep_set_last_error(
            READER_ISO_DEP_ERR_RECV_COPY_INF);
        nero_nfc_secure_clear(rx, sizeof(rx));
        return -1;
      }
      if (!appended_inf && (inf_len > 0u)) {
        if (G_ISO_DEP_TRACE != 0u) {
          nero_nfc_log_line(
              "[ISO-DEP] recv FAIL: INF dropped (resp_buf overflow)");
        }
        reader_security_key_iso_dep_set_last_error(
            READER_ISO_DEP_ERR_RECV_INF_DROPPED);
        nero_nfc_secure_clear(rx, sizeof(rx));
        return -1;
      }
      /* [ISO14443-4] block-numbering rule B — every accepted I-block with
       * the current number toggles the PCD number, including each chained
       * response fragment. */
      expected_block ^= ISO_DEP_BLOCK_NUM_MASK;
      if ((pcb & ISO_DEP_PCB_CHAIN_BIT) != 0u) {
        uint8_t ack_tx[READER_ISO_DEP_CHAIN_ACK_TX_CAP];
        uint8_t ack_len;

        if (!reader_iso_dep_build_chained_ack(
                ack_tx, sizeof(ack_tx), expected_block, G_ISO_DEP_PCB_HAS_CID,
                G_ISO_DEP_CID, &ack_len)) {
          if (G_ISO_DEP_TRACE != 0u) {
            nero_nfc_log_line(
                "[ISO-DEP] recv FAIL: chained-I ACK build failed");
          }
          reader_security_key_iso_dep_set_last_error(
              READER_ISO_DEP_ERR_RECV_CHAINED_ACK_TIMEOUT);
          nero_nfc_secure_clear(rx, sizeof(rx));
          return -1;
        }
        rlen = reader_security_key_iso_dep_transceive(
            ack_tx, ack_len, rx, sizeof(rx), true, link_timeout_ms);
        reader_security_key_iso_dep_snap_raw_rx(rx, rlen);
        if ((rlen < 1) && (G_ISO_DEP_TRACE != 0u)) {
          nero_nfc_log_line("[ISO-DEP] recv FAIL: timeout after chained-I ACK");
        }
        if (rlen < 1) {
          reader_security_key_iso_dep_set_last_error(
              READER_ISO_DEP_ERR_RECV_CHAINED_ACK_TIMEOUT);
          nero_nfc_secure_clear(rx, sizeof(rx));
          return -1;
        }
        continue;
      }
      completed_iblock = true;
      if (G_ISO_DEP_TRACE != 0u) {
        nero_nfc_log_write("[ISO-DEP] recv final I-block inf_off=");
        {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                  (unsigned)((uint32_t)(inf_off)));
          nero_nfc_log_write(ndc);
        }
        nero_nfc_log_write(" inf_len=");
        {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                  (unsigned)((uint32_t)(inf_len)));
          nero_nfc_log_write(ndc);
        }
        nero_nfc_log_write(" chained_accum=");
        {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                  (unsigned)((uint32_t)(total)));
          nero_nfc_log_write(ndc);
        }
        nero_nfc_log_write("\r\n");
      }
      reader_security_key_iso_dep_set_last_error(READER_ISO_DEP_ERR_NONE);
      break;
    }
    if (G_ISO_DEP_TRACE != 0u) {
      nero_nfc_log_write("[ISO-DEP] recv loop STOP: unexpected pcb cls=");
      if ((pcb & ISO_DEP_PCB_CLASS_MASK) == ISO_DEP_PCB_CLASS_R_BLOCK) {
        nero_nfc_log_write("R");
      } else if ((pcb & ISO_DEP_PCB_CLASS_MASK) == ISO_DEP_PCB_CLASS_S_BLOCK) {
        nero_nfc_log_write("S");
      } else {
        nero_nfc_log_write("?");
      }
      nero_nfc_log_write(" pcb=0x");
      {
        char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
        (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(pcb));
        nero_nfc_log_write(nhx);
      }
      nero_nfc_log_write("\r\n");
      reader_iso_dep_debug_dump("RX orphan", rx, (uint16_t)(rlen),
                                ISO_DEP_DUMP_RX_ORPHAN);
    }
    break;
  }
  if (!completed_iblock && (G_ISO_DEP_TRACE != 0u)) {
    nero_nfc_log_write(
        "[ISO-DEP] send_i_block FAIL: no complete I-block "
        "(completed_iblock=0) total=");
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                              (unsigned)((uint32_t)(total)));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_write("\r\n");
  }
  if (completed_iblock) {
    G_BLOCK_NUM = expected_block;
  }
  if (!completed_iblock && (total > 0)) {
    reader_security_key_iso_dep_set_last_error(
        READER_ISO_DEP_ERR_INCOMPLETE_IBLOCK);
    nero_nfc_secure_clear(rx, sizeof(rx));
    return -1;
  }
  if (G_ISO_DEP_TRACE != 0u) {
    nero_nfc_log_write("[ISO-DEP] send_i_block exit total=");
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)((int32_t)(total)));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_write(" next_block_num=");
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                              (unsigned)((uint32_t)(G_BLOCK_NUM)));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_write("\r\n");
    reader_iso_dep_debug_dump("reassembled APDU resp chunk", resp, total,
                              ISO_DEP_DUMP_RESP_CHUNK);
  }
  nero_nfc_secure_clear(rx, sizeof(rx));
  return (int)(total);
}

int reader_security_key_send_apdu_timeout_ex(const uint8_t* apdu,
                                             uint16_t apdu_len, uint8_t* resp,
                                             uint16_t resp_buf_len,
                                             uint16_t frame_timeout_ms,
                                             bool follow_get_response) {
  int total;

  if (((apdu == NERO_NFC_NULL) && (apdu_len != 0u)) ||
      (resp == NERO_NFC_NULL)) {
    return -1;
  }
  if (G_ISO_DEP_TRACE != 0u) {
    nero_nfc_log_write("[ISO-DEP] send_apdu_timeout apdu_len=");
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                              (unsigned)((uint32_t)(apdu_len)));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_write(" frame_ms=");
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                              (unsigned)((uint32_t)(frame_timeout_ms)));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_write("\r\n");
    reader_iso_dep_debug_dump("CMD APDU", apdu, apdu_len,
                              ISO_DEP_DUMP_CMD_APDU);
  }

  total = reader_security_key_send_i_block(apdu, apdu_len, resp, resp_buf_len,
                                           frame_timeout_ms);
  if (G_ISO_DEP_TRACE != 0u) {
    nero_nfc_log_write("[ISO-DEP] send_apdu_timeout after send_i_block total=");
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)((int32_t)(total)));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_write("\r\n");
  }
  if (total < NFC_ISO7816_SW_STATUS_WORD_LEN) {
    return total;
  }
  total = (int)(reader_iso_dep_trim_crc_suffix(resp, (uint16_t)(total)));
  if (G_ISO_DEP_TRACE != 0u) {
    nero_nfc_log_write("[ISO-DEP] after CRC-trim total=");
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)((int32_t)(total)));
      nero_nfc_log_write(ndc);
    }
    nero_nfc_log_write("\r\n");
  }
  if (total < NFC_ISO7816_SW_STATUS_WORD_LEN) {
    return total;
  }
  {
    uint8_t remaining = 0u;
    while (follow_get_response &&
           nfc_iso7816_response_more_data(resp, total, &remaining)) {
      uint16_t tail_cap;
      uint8_t get_resp[NFC_ISO7816_SHORT_APDU_HDR_LEN] = {
          NFC_ISO7816_CLA_ISO, NFC_ISO7816_INS_GET_RESPONSE,
          NFC_ISO7816_GET_DATA_P2_DEFAULT, NFC_ISO7816_GET_DATA_P2_DEFAULT,
          remaining};
      int more;
      tail_cap =
          reader_security_key_resp_tail_cap(resp_buf_len, (uint16_t)(total));
      if (tail_cap < NFC_ISO7816_SW_STATUS_WORD_LEN) {
        break;
      }
      if (G_ISO_DEP_TRACE != 0u) {
        nero_nfc_log_write("[ISO-DEP] GET RESPONSE chain SW61 remaining=");
        {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                  (unsigned)((uint32_t)(remaining)));
          nero_nfc_log_write(ndc);
        }
        nero_nfc_log_write("\r\n");
      }
      total -= NFC_ISO7816_SW_STATUS_WORD_LEN;
      more = reader_security_key_send_i_block(
          get_resp, sizeof(get_resp), &resp[total], tail_cap, frame_timeout_ms);
      if (G_ISO_DEP_TRACE != 0u) {
        nero_nfc_log_write("[ISO-DEP] GET RESPONSE more=");
        {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d",
                                  (int)((int32_t)(more)));
          nero_nfc_log_write(ndc);
        }
        nero_nfc_log_write("\r\n");
      }
      if (more < NFC_ISO7816_SW_STATUS_WORD_LEN) {
        break;
      }
      total += more;
      total = (int)(reader_iso_dep_trim_crc_suffix(resp, (uint16_t)(total)));
    }
    while (follow_get_response && nfc_ctap_response_more_data(resp, total)) {
      uint16_t tail_cap;
      /* [CTAP2.3] §11.3.7.2 — NFCCTAP_GETRESPONSE: CLA=0x80 INS=0x11, P1/P2
       * RFU=0x00. The spec defines no Le for this command, so it is sent as an
       * ISO7816-4 case-1 APDU (no Lc/Le); the response data is returned over
       * ISO-DEP framing. This is the legacy continuation path; the CCID relay
       * leaves GETRESPONSE to the host (follow_get_response=false). */
      const uint8_t get_resp[] = {NFC_CTAP_CLA, NFC_CTAP_INS_GETRESPONSE,
                                  NFC_ISO7816_GET_DATA_P2_DEFAULT,
                                  NFC_ISO7816_GET_DATA_P2_DEFAULT};
      int more;
      tail_cap =
          reader_security_key_resp_tail_cap(resp_buf_len, (uint16_t)(total));
      if (tail_cap < NFC_ISO7816_SW_STATUS_WORD_LEN) {
        break;
      }
      if (G_ISO_DEP_TRACE != 0u) {
        nero_nfc_log_line("[ISO-DEP] NFCCTAP_GETRESPONSE chain SW9100");
      }
      total -= NFC_ISO7816_SW_STATUS_WORD_LEN;
      more = reader_security_key_send_i_block(
          get_resp, sizeof(get_resp), &resp[total], tail_cap, frame_timeout_ms);
      if (G_ISO_DEP_TRACE != 0u) {
        nero_nfc_log_write("[ISO-DEP] NFCCTAP_GETRESPONSE more=");
        {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d",
                                  (int)((int32_t)(more)));
          nero_nfc_log_write(ndc);
        }
        nero_nfc_log_write("\r\n");
      }
      if (more < NFC_ISO7816_SW_STATUS_WORD_LEN) {
        break;
      }
      total += more;
      total = (int)(reader_iso_dep_trim_crc_suffix(resp, (uint16_t)(total)));
    }
  }
  total = (int)(reader_iso_dep_trim_crc_suffix(resp, (uint16_t)(total)));
  if (G_ISO_DEP_TRACE != 0u) {
    nero_nfc_log_write("[ISO-DEP] send_apdu_timeout final total=");
    {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)((int32_t)(total)));
      nero_nfc_log_write(ndc);
    }
    if ((total >= NFC_ISO7816_SW_STATUS_WORD_LEN)) {
      uint8_t sw1 = 0u;
      uint8_t sw2 = 0u;
      nero_nfc_log_write(" SW=");
      if (nfc_iso7816_response_sw(resp, total, &sw1, &sw2)) {
        {
          char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
          (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(sw1));
          nero_nfc_log_write(nhx);
        }
        {
          char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
          (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(sw2));
          nero_nfc_log_write(nhx);
        }
      }
    }
    nero_nfc_log_write("\r\n");
    if ((total > 0)) {
      reader_iso_dep_debug_dump("final resp", resp, (uint16_t)(total),
                                ISO_DEP_DUMP_FINAL_RESP);
    }
  }
  return total;
}

int reader_security_key_send_apdu_timeout(const uint8_t* apdu,
                                          uint16_t apdu_len, uint8_t* resp,
                                          uint16_t resp_buf_len,
                                          uint16_t frame_timeout_ms) {
  return reader_security_key_send_apdu_timeout_ex(
      apdu, apdu_len, resp, resp_buf_len, frame_timeout_ms, true);
}

int reader_iso_dep_send_apdu(const uint8_t* apdu, uint16_t apdu_len,
                             uint8_t* resp, uint16_t resp_buf_len) {
  return reader_security_key_send_apdu_timeout(
      apdu, apdu_len, resp, resp_buf_len, SECURITY_KEY_SHORT_FRAME_MS);
}
