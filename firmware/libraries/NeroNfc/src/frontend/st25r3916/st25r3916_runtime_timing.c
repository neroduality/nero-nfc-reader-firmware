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

#include "st25r3916_runtime.h"

enum {
  K_ST25_TX_BITS_PER_BYTE_PARITY = 10u,
  K_ST25_TX_BIT_OVERHEAD = 64u,
  K_ST25_US_PER_SEC = 1000000u,
  K_ST25_TX_BIT_RATE_HZ = 106000u,
  K_ST25_TX_BIT_RATE_ROUND = 105999u,
  K_ST25_TX_GUARD_US = 4000u,
  K_ST25_TX_WAIT_FLOOR_US = 5000u,
};

uint32_t st25_runtime_tx_wait_budget_us(uint16_t tx_len) {
  uint32_t tx_bits = ((uint32_t)(tx_len)*K_ST25_TX_BITS_PER_BYTE_PARITY) +
                     K_ST25_TX_BIT_OVERHEAD;
  uint32_t tx_us = (tx_bits * K_ST25_US_PER_SEC + K_ST25_TX_BIT_RATE_ROUND) /
                   K_ST25_TX_BIT_RATE_HZ;
  uint32_t budget = tx_us + K_ST25_TX_GUARD_US;
  const uint32_t k_floor_us = (uint32_t)(K_ST25_TX_WAIT_FLOOR_US);
  return (budget < k_floor_us) ? k_floor_us : budget;
}
