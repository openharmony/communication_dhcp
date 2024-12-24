/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <string>
#include "dhcpclientfun_fuzzer.h"
#include "dhcp_client_state_machine.h"
#include "dhcp_ipv6_client.h"
#include "dhcp_socket.h"
#include "securec.h"
#include <linux/rtnetlink.h>
#include <netinet/icmp6.h>

namespace OHOS {
namespace DHCP {
std::string g_ifname = "wlan0";
std::unique_ptr<OHOS::DHCP::DhcpIpv6Client> ipv6Client = std::make_unique<OHOS::DHCP::DhcpIpv6Client>("wlan0");


bool DhcpIpv6FunFuzzerTest(const uint8_t *data, size_t size)
{
    if (ipv6Client == nullptr) {
        return false;
    }
    if (data == nullptr) {
        return false;
    }
    if (size <= 0) {
        return false;
    }
    ipv6Client->handleKernelEvent(data, static_cast<int>(size));
    return true;
}

/* Dhcp Ipv6 Event */
void SetSocketFilterFuzzerTest(const uint8_t *data, size_t size)
{
    ipv6Client->setSocketFilter(nullptr);

    struct sockaddr_nl addr;
    ipv6Client->setSocketFilter(&addr);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    DhcpIpv6FunFuzzerTest(data, size);
    SetSocketFilterFuzzerTest(data, size);
    return 0;
}
} // namespace DHCP
} // namespace OHOS