# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2026 Nero Duality, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Allowed NFC_FRONTEND values: ST25R reader family only. This firmware is wired
# for STMicroelectronics stacks under third_party/ (NFC-RFAL + stm32duino ST25*)
# governed by SLA0052; non-ST analogue front ends are intentionally out of scope.

VALID_ST25R_NFC_FRONTENDS := st25r3916
