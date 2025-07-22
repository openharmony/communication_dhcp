/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DHCP_FUZZ_COMMON_FUNC_H
#define DHCP_FUZZ_COMMON_FUNC_H

#include <cstdint>

namespace OHOS {
namespace DHCP {
constexpr int U32_BYTE0_SHIFT = 24;
constexpr int U32_BYTE1_SHIFT = 16;
constexpr int U32_BYTE2_SHIFT = 8;
constexpr int U32_BYTE3_SHIFT = 0;
constexpr int U16_BYTE0_SHIFT = 8;
constexpr int U16_BYTE1_SHIFT = 0;
constexpr int U32_BYTE0_INDEX = 0;
constexpr int U32_BYTE1_INDEX = 1;
constexpr int U32_BYTE2_INDEX = 2;
constexpr int U32_BYTE3_INDEX = 3;
constexpr int U16_BYTE0_INDEX = 0;
constexpr int U16_BYTE1_INDEX = 1;

inline uint32_t U32_AT(const uint8_t* data)
{
    if (data == nullptr) {
        return 0;
    }
    return (static_cast<uint32_t>(data[U32_BYTE0_INDEX]) << U32_BYTE0_SHIFT) |
           (static_cast<uint32_t>(data[U32_BYTE1_INDEX]) << U32_BYTE1_SHIFT) |
           (static_cast<uint32_t>(data[U32_BYTE2_INDEX]) << U32_BYTE2_SHIFT) |
           (static_cast<uint32_t>(data[U32_BYTE3_INDEX]) << U32_BYTE3_SHIFT);
}
inline uint16_t U16_AT(const uint8_t* data)
{
    if (data == nullptr) {
        return 0;
    }
    return (static_cast<uint16_t>(data[U16_BYTE0_INDEX]) << U16_BYTE0_SHIFT) |
           (static_cast<uint16_t>(data[U16_BYTE1_INDEX]) << U16_BYTE1_SHIFT);
}
}  // namespace DHCP
}  // namespace OHOS
#endif

