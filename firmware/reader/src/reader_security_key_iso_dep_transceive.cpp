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
#include "reader_secure_clear_guard.h"
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

namespace {

enum {
  kSecurityKeyIblockIncompleteResendMs = 52u,
  kReaderIsoDepErrNone = 0u,
  kReaderIsoDepErrTransceiveTimeout = 0x01u,
  kReaderIsoDepErrIncompleteResendTimeout = 0x02u,
  kReaderIsoDepErrTxChainWtxDeadline = 0x03u,
  kReaderIsoDepErrTxChainWtxShort = 0x04u,
  kReaderIsoDepErrTxChainWtxOverflow = 0x05u,
  kReaderIsoDepErrTxChainWtxEchoTimeout = 0x06u,
  kReaderIsoDepErrTxChainRnakLimit = 0x07u,
  kReaderIsoDepErrTxChainRnakResendTimeout = 0x08u,
  kReaderIsoDepErrTxChainUnexpectedFrame = 0x09u,
  kReaderIsoDepErrRecvWtxDeadline = 0x0Au,
  kReaderIsoDepErrRecvWtxShort = 0x0Bu,
  kReaderIsoDepErrRecvWtxOverflow = 0x0Cu,
  kReaderIsoDepErrRecvWtxEchoTimeout = 0x0Du,
  kReaderIsoDepErrRecvIBlockShort = 0x0Eu,
  kReaderIsoDepErrRecvCopyInf = 0x0Fu,
  kReaderIsoDepErrRecvChainedAckTimeout = 0x10u,
  kReaderIsoDepErrRecvInfDropped = 0x12u,
  kReaderIsoDepErrIncompleteIblock = 0x13u,
  kReaderIsoDepErrTxChainCcidAbort = 0x16u,
  kReaderIsoDepErrRecvCcidAbort = 0x17u,
  kReaderIsoDepChainRnakMax = 2u,
  kIsoDepDumpApduHead = 36u,
  kIsoDepDumpTxWire = 28u,
  kIsoDepDumpRxRaw = 80u,
  kIsoDepDumpUnexpectedFrame = 48u,
  kIsoDepDumpRxPostWtx = 64u,
  kIsoDepDumpRxOrphan = 80u,
  kIsoDepDumpRespChunk = 96u,
  kIsoDepDumpCmdApdu = 48u,
  kIsoDepDumpFinalResp = 96u,
  kReaderIsoDepWtxEchoTxCap = 8u,
  kReaderIsoDepChainAckTxCap = 4u,
  kIsoDepWtxLogMin = 3u,
};

} // namespace

static void iso_dep_note_wtx_wait(uint16_t wtx_count, uint32_t total_start_ms) {
#if !defined(NERO_CCID_USB_BUILD)
  (void)total_start_ms;
#endif
  reader_security_key_iso_dep_ccid_heartbeat();
  if ((g_iso_dep_trace == 0u) || (wtx_count < kIsoDepWtxLogMin)) {
    return;
  }
  nero_nfc_log_write("[ISO-DEP] waiting on S(WTX) x");
  do {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(wtx_count));
    nero_nfc_log_write(ndc);
  } while (0);
  nero_nfc_log_write(" (~");
  do {
    char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
    (void)nero_nfc_snprintf(
      ndc, sizeof ndc, "%u",
      (unsigned)(uint32_t)(reader_iso_dep_ms_to_seconds(reader_hal_millis()) - total_start_ms));
    nero_nfc_log_write(ndc);
  } while (0);
  nero_nfc_log_write("s): authenticator is alive and likely waiting for user presence; "
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

/* Safe room in `resp` after `used` bytes — avoids uint16_t underflow in GET RESPONSE tail math. */
static uint16_t reader_security_key_resp_tail_cap(uint16_t resp_buf_len, uint16_t used) {
  if (used >= resp_buf_len) {
    return 0u;
  }
  return (uint16_t)(resp_buf_len - used);
}

static int reader_security_key_send_i_block(const uint8_t *apdu, uint16_t apdu_len, uint8_t *resp,
                                            uint16_t resp_buf_len, uint16_t frame_timeout_ms) {
  uint8_t *tx = g_iso_dep_iblock_tx;
  uint8_t rx[READER_ISO_DEP_IBLOCK_RX_BUF_LEN];
  ReaderSecureClearGuard rx_guard(rx, sizeof(rx));
  uint16_t total = 0u;
  uint16_t wtx_count = 0u;
  int rlen = 0;
  uint8_t expected_block;
  uint32_t total_start_ms = reader_hal_millis();
  const bool add_nad = reader_security_key_iso_dep_tx_add_nad(apdu_len, apdu);
  const uint8_t tx_hdr_len = reader_security_key_iso_dep_tx_hdr_len(add_nad);
  bool completed_iblock = false;
  uint16_t apdu_off = 0u;
  const uint16_t frag_cap = reader_security_key_iso_dep_apdu_chunk_budget(tx_hdr_len);
  const uint16_t link_timeout_ms = reader_security_key_iso_dep_link_response_timeout_ms();

  if (((apdu == NERO_NFC_NULL) && (apdu_len != 0u)) || (resp == NERO_NFC_NULL)) {
    return -1;
  }
  if ((frag_cap == 0u) || (tx_hdr_len == 0u)) {
    if (g_iso_dep_trace != 0u) {
      nero_nfc_log_line("[ISO-DEP] send_i_block FAIL: frag_cap or tx_hdr_len invalid");
    }
    return -1;
  }

  if (g_iso_dep_trace != 0u) {
    nero_nfc_log_write("[ISO-DEP] send_i_block apdu_len=");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(apdu_len));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_write(" tx_hdr=");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(tx_hdr_len));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_write(" nad=");
    nero_nfc_log_write(add_nad ? "1" : "0");
    nero_nfc_log_write(" frag_cap=");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(frag_cap));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_write(" g_block_num=");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(g_block_num));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_write("\r\n");
    reader_iso_dep_debug_dump("APDU head", apdu, apdu_len, kIsoDepDumpApduHead);
  }

  while (apdu_off < apdu_len) {
    uint8_t blk_sent = (uint8_t)(g_block_num & ISO_DEP_BLOCK_NUM_MASK);
    reader_iso_dep_i_block_tx_t tx_info;

    if (!reader_iso_dep_build_i_block_tx(tx, ISO_DEP_IBLOCK_TX_BUF_LEN, apdu, apdu_len, apdu_off,
                                         frag_cap, g_iso_dep_pcb_has_cid, g_iso_dep_cid, add_nad,
                                         ISO_DEP_TX_NAD_VALUE, blk_sent, &tx_info)) {
      if (g_iso_dep_trace != 0u) {
        nero_nfc_log_line("[ISO-DEP] send_i_block FAIL: build I-block TX fragment");
      }
      return -1;
    }
    if (g_iso_dep_trace != 0u) {
      nero_nfc_log_write("[ISO-DEP] TX frag apdu_off=");
      do {
        char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
        (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(apdu_off));
        nero_nfc_log_write(ndc);
      } while (0);
      nero_nfc_log_write(" frag_len=");
      do {
        char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
        (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(tx_info.frag_len));
        nero_nfc_log_write(ndc);
      } while (0);
      nero_nfc_log_write(" chain_more=");
      nero_nfc_log_write(tx_info.chain_more ? "1" : "0");
      nero_nfc_log_write(" blk_sent=");
      do {
        char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
        (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(blk_sent));
        nero_nfc_log_write(ndc);
      } while (0);
      nero_nfc_log_write(" pcb_tx=0x");
      do {
        char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
        (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(tx_info.pcb));
        nero_nfc_log_write(nhx);
      } while (0);
      nero_nfc_log_write(" wire_len=");
      do {
        char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
        (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(tx_info.wire_len));
        nero_nfc_log_write(ndc);
      } while (0);
      nero_nfc_log_write("\r\n");
      reader_iso_dep_debug_dump("TX wire", tx, tx_info.wire_len, kIsoDepDumpTxWire);
    }
    rlen = reader_security_key_iso_dep_transceive(tx, tx_info.wire_len, rx, sizeof(rx), true,
                                                  link_timeout_ms);
    if (rlen < 1) {
      if (g_iso_dep_trace != 0u) {
        nero_nfc_log_write("[ISO-DEP] send_i_block FAIL: security_key_transceive timeout "
                           "rlen<1\r\n");
      }
      reader_security_key_iso_dep_snap_raw_rx(NERO_NFC_NULL, 0);
      reader_security_key_iso_dep_set_last_error(kReaderIsoDepErrTransceiveTimeout);
      return -1;
    }
    reader_security_key_iso_dep_snap_raw_rx(rx, rlen);
    /* Truncated PCB-only garbage (rlen=1..2) gets worse if we duplicate the
     * I-block immediately — skip re-send and let upper layers recover.  If we
     * received a partial INF (rlen>=3 but missing CRC), one pause + resend can
     * complete the frame without full WUPA. */
    if (!tx_info.chain_more && ((rx[0] & ISO_DEP_PCB_CLASS_MASK) == ISO_DEP_PCB_CLASS_I_BLOCK)) {
      uint8_t inf_probe = reader_security_key_iso_dep_pick_inf_offset(rx, rlen);
      if ((rlen >= (int)ISO_DEP_INF_MIN_FRAME_LEN) &&
          (rlen < (int)inf_probe + (int)ISO_DEP_INF_STATUS_TAIL_OFFSET)) {
        if (g_iso_dep_trace != 0u) {
          nero_nfc_log_line("[ISO-DEP] PICC I-block incomplete; pause + re-send once");
        }
        reader_hal_delay_ms(kSecurityKeyIblockIncompleteResendMs);
        rlen = reader_security_key_iso_dep_transceive(tx, tx_info.wire_len, rx, sizeof(rx), true,
                                                      link_timeout_ms);
        if (rlen < 1) {
          if (g_iso_dep_trace != 0u) {
            nero_nfc_log_write("[ISO-DEP] send_i_block FAIL: after incomplete-frame resend "
                               "rlen<1\r\n");
          }
          reader_security_key_iso_dep_snap_raw_rx(NERO_NFC_NULL, 0);
          reader_security_key_iso_dep_set_last_error(kReaderIsoDepErrIncompleteResendTimeout);
          return -1;
        }
        reader_security_key_iso_dep_snap_raw_rx(rx, rlen);
      }
    }
    if (g_iso_dep_trace != 0u) {
      nero_nfc_log_write("[ISO-DEP] RX rlen=");
      do {
        char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
        (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)(int32_t)(rlen));
        nero_nfc_log_write(ndc);
      } while (0);
      nero_nfc_log_write(" cls=");
      if ((rx[0] & ISO_DEP_PCB_CLASS_MASK) == ISO_DEP_PCB_CLASS_I_BLOCK) {
        nero_nfc_log_write("I");
      } else if ((rx[0] & ISO_DEP_PCB_CLASS_MASK) == ISO_DEP_PCB_CLASS_R_BLOCK) {
        nero_nfc_log_write("R");
      } else if ((rx[0] & ISO_DEP_PCB_CLASS_MASK) == ISO_DEP_PCB_CLASS_S_BLOCK) {
        nero_nfc_log_write("S");
      } else {
        nero_nfc_log_write("?");
      }
      nero_nfc_log_write(" pcb=0x");
      do {
        char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
        (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(rx[0]));
        nero_nfc_log_write(nhx);
      } while (0);
      nero_nfc_log_write("\r\n");
      reader_iso_dep_debug_dump("RX raw", rx, (uint16_t)rlen, kIsoDepDumpRxRaw);
    }
    if (tx_info.chain_more) {
      uint8_t rnak_retries = 0u;

      for (;;) {
        uint8_t pcb = rx[0];
        uint8_t hdr_skip = reader_iso_dep_rx_hdr_skip(pcb);

        if ((pcb & ISO_DEP_PCB_S_WTX_MASK) == ISO_DEP_PCB_S_WTX) {
          uint8_t wtx_tx[kReaderIsoDepWtxEchoTxCap];
          uint8_t wtx_len;

          if ((reader_hal_millis() - total_start_ms) > (uint32_t)frame_timeout_ms) {
            if (g_iso_dep_trace != 0u) {
              nero_nfc_log_line("[ISO-DEP] TX-chain FAIL: total WTX deadline exceeded");
            }
            reader_security_key_iso_dep_set_last_error(kReaderIsoDepErrTxChainWtxDeadline);
            return -1;
          }
          if (reader_security_key_ccid_abort_pending()) {
            if (g_iso_dep_trace != 0u) {
              nero_nfc_log_line("[ISO-DEP] TX-chain aborted by CCID host");
            }
            reader_security_key_iso_dep_set_last_error(kReaderIsoDepErrTxChainCcidAbort);
            return -1;
          }

          if (!reader_iso_dep_build_wtx_echo(wtx_tx, sizeof(wtx_tx), rx, rlen, hdr_skip,
                                             &wtx_len)) {
            if (g_iso_dep_trace != 0u) {
              if (rlen < (int)(hdr_skip + ISO_DEP_HDR_BASE_LEN)) {
                nero_nfc_log_line("[ISO-DEP] TX-chain FAIL: WTX rx too short");
              } else {
                nero_nfc_log_line("[ISO-DEP] TX-chain FAIL: WTX len overflow");
              }
            }
            reader_security_key_iso_dep_set_last_error(
              (rlen < (int)(hdr_skip + ISO_DEP_HDR_BASE_LEN)) ? kReaderIsoDepErrTxChainWtxShort
                                                              : kReaderIsoDepErrTxChainWtxOverflow);
            return -1;
          }
          rlen = reader_security_key_iso_dep_transceive(
            wtx_tx, wtx_len, rx, sizeof(rx), true,
            reader_security_key_iso_dep_wtx_response_timeout_ms(rx, rlen, hdr_skip));
          wtx_count++;
          iso_dep_note_wtx_wait(wtx_count, total_start_ms);
          if (rlen < 1) {
            if (g_iso_dep_trace != 0u) {
              nero_nfc_log_line("[ISO-DEP] TX-chain FAIL: timeout after WTX echo");
            }
            reader_security_key_iso_dep_snap_raw_rx(NERO_NFC_NULL, 0);
            reader_security_key_iso_dep_set_last_error(kReaderIsoDepErrTxChainWtxEchoTimeout);
            return -1;
          }
          reader_security_key_iso_dep_snap_raw_rx(rx, rlen);
          continue;
        }
        if (reader_security_key_iso_dep_rx_is_chain_nak_for_block(rx, rlen, blk_sent)) {
          if (rnak_retries >= kReaderIsoDepChainRnakMax) {
            if (g_iso_dep_trace != 0u) {
              nero_nfc_log_write("[ISO-DEP] TX-chain FAIL: repeated R-NAK after blk_sent=");
              do {
                char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
                (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(blk_sent));
                nero_nfc_log_write(ndc);
              } while (0);
              nero_nfc_log_write("\r\n");
            }
            reader_security_key_iso_dep_set_last_error(kReaderIsoDepErrTxChainRnakLimit);
            return -1;
          }
          rnak_retries++;
          if (g_iso_dep_trace != 0u) {
            nero_nfc_log_write("[ISO-DEP] TX-chain R-NAK retry=");
            do {
              char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
              (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(rnak_retries));
              nero_nfc_log_write(ndc);
            } while (0);
            nero_nfc_log_write(" blk_sent=");
            do {
              char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
              (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(blk_sent));
              nero_nfc_log_write(ndc);
            } while (0);
            nero_nfc_log_write("\r\n");
          }
          rlen = reader_security_key_iso_dep_transceive(tx, tx_info.wire_len, rx, sizeof(rx), true,
                                                        link_timeout_ms);
          if (rlen < 1) {
            if (g_iso_dep_trace != 0u) {
              nero_nfc_log_line("[ISO-DEP] TX-chain FAIL: timeout after R-NAK resend");
            }
            reader_security_key_iso_dep_snap_raw_rx(NERO_NFC_NULL, 0);
            reader_security_key_iso_dep_set_last_error(kReaderIsoDepErrTxChainRnakResendTimeout);
            return -1;
          }
          reader_security_key_iso_dep_snap_raw_rx(rx, rlen);
          continue;
        }
        uint8_t ack_block = 0u;
        if (reader_security_key_iso_dep_rx_is_chain_ack_for_block(rx, rlen, blk_sent, &ack_block)) {
          if (g_iso_dep_trace != 0u) {
            nero_nfc_log_write("[ISO-DEP] TX-chain R-ACK ok ack_block=");
            do {
              char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
              (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(ack_block));
              nero_nfc_log_write(ndc);
            } while (0);
            nero_nfc_log_write(" next_block=");
            do {
              char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
              (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                      (unsigned)(uint32_t)((blk_sent ^ ISO_DEP_BLOCK_NUM_MASK)));
              nero_nfc_log_write(ndc);
            } while (0);
            nero_nfc_log_write(" after blk_sent=");
            do {
              char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
              (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(blk_sent));
              nero_nfc_log_write(ndc);
            } while (0);
            nero_nfc_log_write("\r\n");
          }
          break;
        }
        if (g_iso_dep_trace != 0u) {
          nero_nfc_log_write("[ISO-DEP] TX-chain FAIL: expected R-ACK next_block=");
          do {
            char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
            (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u",
                                    (unsigned)(uint32_t)((blk_sent ^ ISO_DEP_BLOCK_NUM_MASK)));
            nero_nfc_log_write(ndc);
          } while (0);
          nero_nfc_log_write(" after blk_sent=");
          do {
            char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
            (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(blk_sent));
            nero_nfc_log_write(ndc);
          } while (0);
          nero_nfc_log_write(" CID=");
          do {
            char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
            (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(g_iso_dep_cid));
            nero_nfc_log_write(ndc);
          } while (0);
          nero_nfc_log_write("\r\n");
          reader_iso_dep_debug_dump("unexpected frame", rx, (uint16_t)rlen,
                                    kIsoDepDumpUnexpectedFrame);
        }
        reader_security_key_iso_dep_set_last_error(kReaderIsoDepErrTxChainUnexpectedFrame);
        return -1;
      }
      apdu_off = (uint16_t)(apdu_off + tx_info.frag_len);
      g_block_num ^= ISO_DEP_BLOCK_NUM_MASK;
      continue;
    }
    apdu_off = (uint16_t)(apdu_off + tx_info.frag_len);
    break;
  }

  expected_block = g_block_num;
  while (rlen > 0) {
    uint8_t pcb = rx[0];
    uint8_t hdr_skip = reader_iso_dep_rx_hdr_skip(pcb);

    if ((pcb & ISO_DEP_PCB_S_WTX_MASK) == ISO_DEP_PCB_S_WTX) {
      /* Wait-time extension — echo PICC S(WTX) prefix including optional
       * CID/NAD */
      uint8_t wtx_tx[kReaderIsoDepWtxEchoTxCap];
      uint8_t wtx_len;

      if ((reader_hal_millis() - total_start_ms) > (uint32_t)frame_timeout_ms) {
        if (g_iso_dep_trace != 0u) {
          nero_nfc_log_line("[ISO-DEP] recv FAIL: total WTX deadline exceeded");
        }
        reader_security_key_iso_dep_set_last_error(kReaderIsoDepErrRecvWtxDeadline);
        return -1;
      }
      if (reader_security_key_ccid_abort_pending()) {
        if (g_iso_dep_trace != 0u) {
          nero_nfc_log_line("[ISO-DEP] recv aborted by CCID host");
        }
        reader_security_key_iso_dep_set_last_error(kReaderIsoDepErrRecvCcidAbort);
        return -1;
      }

      if (!reader_iso_dep_build_wtx_echo(wtx_tx, sizeof(wtx_tx), rx, rlen, hdr_skip, &wtx_len)) {
        if (g_iso_dep_trace != 0u) {
          if (rlen < (int)(hdr_skip + ISO_DEP_HDR_BASE_LEN)) {
            nero_nfc_log_line("[ISO-DEP] recv WTX: hdr too short");
          } else {
            nero_nfc_log_line("[ISO-DEP] recv WTX: len overflow");
          }
        }
        reader_security_key_iso_dep_set_last_error((rlen < (int)(hdr_skip + ISO_DEP_HDR_BASE_LEN))
                                                     ? kReaderIsoDepErrRecvWtxShort
                                                     : kReaderIsoDepErrRecvWtxOverflow);
        return -1;
      }
      rlen = reader_security_key_iso_dep_transceive(
        wtx_tx, wtx_len, rx, sizeof(rx), true,
        reader_security_key_iso_dep_wtx_response_timeout_ms(rx, rlen, hdr_skip));
      wtx_count++;
      iso_dep_note_wtx_wait(wtx_count, total_start_ms);
      if ((rlen < 1) && (g_iso_dep_trace != 0u)) {
        nero_nfc_log_line("[ISO-DEP] recv FAIL: timeout after S(WTX) echo");
      }
      if (rlen < 1) {
        reader_security_key_iso_dep_set_last_error(kReaderIsoDepErrRecvWtxEchoTimeout);
        return -1;
      }
      reader_security_key_iso_dep_snap_raw_rx(rx, rlen);
      if (g_iso_dep_trace != 0u) {
        nero_nfc_log_write("[ISO-DEP] recv after WTX echo rlen=");
        do {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)(int32_t)(rlen));
          nero_nfc_log_write(ndc);
        } while (0);
        nero_nfc_log_write("\r\n");
        reader_iso_dep_debug_dump("RX post-WTX", rx, (uint16_t)rlen, kIsoDepDumpRxPostWtx);
      }
      continue;
    }
    if ((pcb & ISO_DEP_PCB_CLASS_MASK) == ISO_DEP_PCB_CLASS_I_BLOCK) {
      uint16_t inf_len;
      uint8_t inf_off = reader_security_key_iso_dep_pick_inf_offset(rx, rlen);

      g_iso_dep_last_inf_off = inf_off;
      if (!reader_iso_dep_i_block_inf_len(rx, rlen, inf_off, pcb, &inf_len, NERO_NFC_NULL)) {
        if (g_iso_dep_trace != 0u) {
          nero_nfc_log_write("[ISO-DEP] recv I-block FAIL: rlen < inf_off+2 (frame too "
                             "short)\r\n");
        }
        reader_security_key_iso_dep_set_last_error(kReaderIsoDepErrRecvIBlockShort);
        return -1;
      }
      /* Strip RF CRC-A on intermediate chained frames only when it is present in
       * the FIFO. Keep final I-block tails intact so real APDU status words
       * such as 90 00 cannot be mistaken for CRC by coincidence. */
      bool appended_inf = false;
      if (!reader_iso_dep_append_inf(resp, resp_buf_len, &total, &rx[inf_off], inf_len,
                                     &appended_inf)) {
        if (g_iso_dep_trace != 0u) {
          nero_nfc_log_line("[ISO-DEP] recv FAIL: nero_nfc_copy_bytes INF");
        }
        reader_security_key_iso_dep_set_last_error(kReaderIsoDepErrRecvCopyInf);
        return -1;
      }
      if (!appended_inf && (inf_len > 0u)) {
        if (g_iso_dep_trace != 0u) {
          nero_nfc_log_line("[ISO-DEP] recv FAIL: INF dropped (resp_buf overflow)");
        }
        reader_security_key_iso_dep_set_last_error(kReaderIsoDepErrRecvInfDropped);
        return -1;
      }
      if ((pcb & ISO_DEP_PCB_CHAIN_BIT) != 0u) {
        uint8_t ack_tx[kReaderIsoDepChainAckTxCap];
        uint8_t ack_len;
        bool ack_nad = ((pcb & ISO_DEP_PCB_NAD_BIT) != 0u);

        expected_block ^= ISO_DEP_BLOCK_NUM_MASK;
        if (!reader_iso_dep_build_chained_ack(
              ack_tx, sizeof(ack_tx), expected_block, g_iso_dep_pcb_has_cid, g_iso_dep_cid, ack_nad,
              reader_security_key_iso_dep_rx_nad_byte(rx, rlen, pcb), &ack_len)) {
          if (g_iso_dep_trace != 0u) {
            nero_nfc_log_line("[ISO-DEP] recv FAIL: chained-I ACK build failed");
          }
          reader_security_key_iso_dep_set_last_error(kReaderIsoDepErrRecvChainedAckTimeout);
          return -1;
        }
        rlen = reader_security_key_iso_dep_transceive(ack_tx, ack_len, rx, sizeof(rx), true,
                                                      link_timeout_ms);
        reader_security_key_iso_dep_snap_raw_rx(rx, rlen);
        if ((rlen < 1) && (g_iso_dep_trace != 0u)) {
          nero_nfc_log_line("[ISO-DEP] recv FAIL: timeout after chained-I ACK");
        }
        if (rlen < 1) {
          reader_security_key_iso_dep_set_last_error(kReaderIsoDepErrRecvChainedAckTimeout);
          return -1;
        }
        continue;
      }
      completed_iblock = true;
      if (g_iso_dep_trace != 0u) {
        nero_nfc_log_write("[ISO-DEP] recv final I-block inf_off=");
        do {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(inf_off));
          nero_nfc_log_write(ndc);
        } while (0);
        nero_nfc_log_write(" inf_len=");
        do {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(inf_len));
          nero_nfc_log_write(ndc);
        } while (0);
        nero_nfc_log_write(" chained_accum=");
        do {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(total));
          nero_nfc_log_write(ndc);
        } while (0);
        nero_nfc_log_write("\r\n");
      }
      reader_security_key_iso_dep_set_last_error(kReaderIsoDepErrNone);
      break;
    }
    if (g_iso_dep_trace != 0u) {
      nero_nfc_log_write("[ISO-DEP] recv loop STOP: unexpected pcb cls=");
      if ((pcb & ISO_DEP_PCB_CLASS_MASK) == ISO_DEP_PCB_CLASS_R_BLOCK) {
        nero_nfc_log_write("R");
      } else if ((pcb & ISO_DEP_PCB_CLASS_MASK) == ISO_DEP_PCB_CLASS_S_BLOCK) {
        nero_nfc_log_write("S");
      } else {
        nero_nfc_log_write("?");
      }
      nero_nfc_log_write(" pcb=0x");
      do {
        char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
        (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(pcb));
        nero_nfc_log_write(nhx);
      } while (0);
      nero_nfc_log_write("\r\n");
      reader_iso_dep_debug_dump("RX orphan", rx, (uint16_t)rlen, kIsoDepDumpRxOrphan);
    }
    break;
  }
  if (!completed_iblock && (g_iso_dep_trace != 0u)) {
    nero_nfc_log_write("[ISO-DEP] send_i_block FAIL: no complete I-block "
                       "(completed_iblock=0) total=");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(total));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_write("\r\n");
  }
  if (completed_iblock) {
    g_block_num ^= ISO_DEP_BLOCK_NUM_MASK;
  }
  if (!completed_iblock && (total > 0)) {
    reader_security_key_iso_dep_set_last_error(kReaderIsoDepErrIncompleteIblock);
    return -1;
  }
  if (g_iso_dep_trace != 0u) {
    nero_nfc_log_write("[ISO-DEP] send_i_block exit total=");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)(int32_t)(total));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_write(" next_block_num=");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(g_block_num));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_write("\r\n");
    reader_iso_dep_debug_dump("reassembled APDU resp chunk", resp, total, kIsoDepDumpRespChunk);
  }
  return (int)total;
}

int reader_security_key_send_apdu_timeout_ex(const uint8_t *apdu, uint16_t apdu_len, uint8_t *resp,
                                             uint16_t resp_buf_len, uint16_t frame_timeout_ms,
                                             bool follow_get_response) {
  int total;

  if (((apdu == NERO_NFC_NULL) && (apdu_len != 0u)) || (resp == NERO_NFC_NULL)) {
    return -1;
  }
  if (g_iso_dep_trace != 0u) {
    nero_nfc_log_write("[ISO-DEP] send_apdu_timeout apdu_len=");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(apdu_len));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_write(" frame_ms=");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(frame_timeout_ms));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_write("\r\n");
    reader_iso_dep_debug_dump("CMD APDU", apdu, apdu_len, kIsoDepDumpCmdApdu);
  }

  total = reader_security_key_send_i_block(apdu, apdu_len, resp, resp_buf_len, frame_timeout_ms);
  if (g_iso_dep_trace != 0u) {
    nero_nfc_log_write("[ISO-DEP] send_apdu_timeout after send_i_block total=");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)(int32_t)(total));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_write("\r\n");
  }
  if (total < NFC_ISO7816_SW_STATUS_WORD_LEN) {
    return total;
  }
  total = (int)reader_iso_dep_trim_crc_suffix(resp, (uint16_t)total);
  if (g_iso_dep_trace != 0u) {
    nero_nfc_log_write("[ISO-DEP] after CRC-trim total=");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)(int32_t)(total));
      nero_nfc_log_write(ndc);
    } while (0);
    nero_nfc_log_write("\r\n");
  }
  if (total < NFC_ISO7816_SW_STATUS_WORD_LEN) {
    return total;
  }
  {
    uint8_t remaining = 0u;
    while (follow_get_response && nfc_iso7816_response_more_data(resp, total, &remaining)) {
      uint16_t tail_cap;
      uint8_t get_resp[NFC_ISO7816_SHORT_APDU_HDR_LEN] = {
        NFC_ISO7816_CLA_ISO, NFC_ISO7816_INS_GET_RESPONSE, NFC_ISO7816_GET_DATA_P2_DEFAULT,
        NFC_ISO7816_GET_DATA_P2_DEFAULT, remaining};
      int more;
      tail_cap = reader_security_key_resp_tail_cap(resp_buf_len, (uint16_t)total);
      if (tail_cap < NFC_ISO7816_SW_STATUS_WORD_LEN) {
        break;
      }
      if (g_iso_dep_trace != 0u) {
        nero_nfc_log_write("[ISO-DEP] GET RESPONSE chain SW61 remaining=");
        do {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%u", (unsigned)(uint32_t)(remaining));
          nero_nfc_log_write(ndc);
        } while (0);
        nero_nfc_log_write("\r\n");
      }
      total -= NFC_ISO7816_SW_STATUS_WORD_LEN;
      more = reader_security_key_send_i_block(get_resp, sizeof(get_resp), &resp[total], tail_cap,
                                              frame_timeout_ms);
      if (g_iso_dep_trace != 0u) {
        nero_nfc_log_write("[ISO-DEP] GET RESPONSE more=");
        do {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)(int32_t)(more));
          nero_nfc_log_write(ndc);
        } while (0);
        nero_nfc_log_write("\r\n");
      }
      if (more < NFC_ISO7816_SW_STATUS_WORD_LEN) {
        break;
      }
      total += more;
      total = (int)reader_iso_dep_trim_crc_suffix(resp, (uint16_t)total);
    }
    while (follow_get_response && nfc_ctap_response_more_data(resp, total)) {
      uint16_t tail_cap;
      /* [CTAP2.3] §11.3.7.2 — NFCCTAP_GETRESPONSE: CLA=0x80 INS=0x11, P1/P2 RFU=0x00.
       * The spec defines no Le for this command, so it is sent as an ISO7816-4
       * case-1 APDU (no Lc/Le); the response data is returned over ISO-DEP
       * framing. This is the legacy continuation path; the CCID relay leaves
       * GETRESPONSE to the host (follow_get_response=false). */
      const uint8_t get_resp[] = {NFC_CTAP_CLA, NFC_CTAP_INS_GETRESPONSE,
                                  NFC_ISO7816_GET_DATA_P2_DEFAULT, NFC_ISO7816_GET_DATA_P2_DEFAULT};
      int more;
      tail_cap = reader_security_key_resp_tail_cap(resp_buf_len, (uint16_t)total);
      if (tail_cap < NFC_ISO7816_SW_STATUS_WORD_LEN) {
        break;
      }
      if (g_iso_dep_trace != 0u) {
        nero_nfc_log_line("[ISO-DEP] NFCCTAP_GETRESPONSE chain SW9100");
      }
      total -= NFC_ISO7816_SW_STATUS_WORD_LEN;
      more = reader_security_key_send_i_block(get_resp, sizeof(get_resp), &resp[total], tail_cap,
                                              frame_timeout_ms);
      if (g_iso_dep_trace != 0u) {
        nero_nfc_log_write("[ISO-DEP] NFCCTAP_GETRESPONSE more=");
        do {
          char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
          (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)(int32_t)(more));
          nero_nfc_log_write(ndc);
        } while (0);
        nero_nfc_log_write("\r\n");
      }
      if (more < NFC_ISO7816_SW_STATUS_WORD_LEN) {
        break;
      }
      total += more;
      total = (int)reader_iso_dep_trim_crc_suffix(resp, (uint16_t)total);
    }
  }
  total = (int)reader_iso_dep_trim_crc_suffix(resp, (uint16_t)total);
  if (g_iso_dep_trace != 0u) {
    nero_nfc_log_write("[ISO-DEP] send_apdu_timeout final total=");
    do {
      char ndc[NERO_NFC_FORMAT_SNPRINTF_DEC_CAP];
      (void)nero_nfc_snprintf(ndc, sizeof ndc, "%d", (int)(int32_t)(total));
      nero_nfc_log_write(ndc);
    } while (0);
    if ((total >= NFC_ISO7816_SW_STATUS_WORD_LEN)) {
      uint8_t sw1 = 0u;
      uint8_t sw2 = 0u;
      nero_nfc_log_write(" SW=");
      if (nfc_iso7816_response_sw(resp, total, &sw1, &sw2)) {
        do {
          char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
          (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(sw1));
          nero_nfc_log_write(nhx);
        } while (0);
        do {
          char nhx[NERO_NFC_FORMAT_SNPRINTF_HEX_BYTE_CAP];
          (void)nero_nfc_snprintf(nhx, sizeof nhx, "%02X", (unsigned)(uint8_t)(sw2));
          nero_nfc_log_write(nhx);
        } while (0);
      }
    }
    nero_nfc_log_write("\r\n");
    if ((total > 0)) {
      reader_iso_dep_debug_dump("final resp", resp, (uint16_t)total, kIsoDepDumpFinalResp);
    }
  }
  return total;
}

int reader_security_key_send_apdu_timeout(const uint8_t *apdu, uint16_t apdu_len, uint8_t *resp,
                                          uint16_t resp_buf_len, uint16_t frame_timeout_ms) {
  return reader_security_key_send_apdu_timeout_ex(apdu, apdu_len, resp, resp_buf_len,
                                                  frame_timeout_ms, true);
}

int reader_iso_dep_send_apdu(const uint8_t *apdu, uint16_t apdu_len, uint8_t *resp,
                             uint16_t resp_buf_len) {
  return reader_security_key_send_apdu_timeout(apdu, apdu_len, resp, resp_buf_len,
                                               SECURITY_KEY_SHORT_FRAME_MS);
}
