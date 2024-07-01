/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <string>
#include "dhcpclientfun_fuzzer.h"
#include "dhcp_client_state_machine.h"
#include "dhcp_ipv6_client.h"
#include "securec.h"

namespace OHOS {
namespace Wifi {
std::string ifname = "wlan0";
constexpr size_t DHCP_SLEEP_2 = 2;
std::unique_ptr<OHOS::DHCP::DhcpClientStateMachine> dhcpClient =
    std::make_unique<OHOS::DHCP::DhcpClientStateMachine>(ifname);
std::unique_ptr<OHOS::DHCP::DhcpIpv6Client> ipv6Client = std::make_unique<OHOS::DHCP::DhcpIpv6Client>("wlan0");

bool DhcpClientStateMachineFunFuzzerTest(const uint8_t* data, size_t size)
{
    if (dhcpClient == nullptr) {
        return false;
    }
    time_t curTimestamp = time(nullptr);
    if (curTimestamp == static_cast<time_t>(-1)) {
        return false;
    }
    dhcpClient->DhcpRequestHandle(curTimestamp);
    sleep(DHCP_SLEEP_2);
    dhcpClient->DhcpResponseHandle(curTimestamp);
    return true;
}

bool DhcpIpv6FunFuzzerTest(const uint8_t* data, size_t size)
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

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    DhcpClientStateMachineFunFuzzerTest(data, size);
    DhcpIpv6FunFuzzerTest(data, size);
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS