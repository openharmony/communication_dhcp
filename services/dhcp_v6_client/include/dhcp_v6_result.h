/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef DHCP_V6_RESULT_H
#define DHCP_V6_RESULT_H

#include <vector>
#include <string>
#include <cstdint>

namespace OHOS {
namespace DHCP {

struct DhcpV6Result {
    std::vector<std::string> ipv6Addresses;
    std::vector<std::string> dnsServers;
    uint32_t preferredLifetime = 0;
    uint32_t validLifetime = 0;
    uint32_t t1 = 0;
    uint32_t t2 = 0;
    bool ready = false;  //DHCPv6 result ready flag, indicates whether the result is available for merging
};

} // namespace DHCP
} // namespace OHOS

#endif // DHCP_V6_RESULT_H