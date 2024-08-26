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

#include "dhcpaddresspool_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "securec.h"
#include "address_utils.h"
#include "dhcp_address_pool.h"
#include "dhcp_s_define.h"

namespace OHOS {
namespace Wifi {
constexpr size_t DHCP_SLEEP_1 = 2;

void DhcpAddressPoolFuzzTest(const uint8_t* data, size_t size)
{
    AddressBinding binding;
    uint32_t index = 0;
    memcpy_s(binding.chaddr, PID_MAX_LEN, "*", PID_MAX_LEN);
    binding.ipAddress = static_cast<uint32_t>(data[index++]);
    binding.clientId = static_cast<uint32_t>(data[index++]);
    binding.bindingTime = static_cast<uint64_t>(data[index++]);
    binding.pendingTime = static_cast<uint64_t>(data[index++]);
    binding.expireIn = static_cast<uint64_t>(data[index++]);
    binding.leaseTime = static_cast<uint64_t>(data[index++]);
    binding.pendingInterval = static_cast<uint64_t>(data[index++]);
    DhcpAddressPool pool;
    strncpy_s(pool.ifname, IFACE_NAME_SIZE, "*", IFACE_NAME_SIZE - 1);
    pool.netmask = static_cast<uint32_t>(data[index++]);
    pool.serverId = static_cast<uint32_t>(data[index++]);
    pool.gateway = static_cast<uint32_t>(data[index++]);
    pool.leaseTime = static_cast<uint32_t>(data[index++]);
    pool.renewalTime = static_cast<uint32_t>(data[index++]);
    pool.distribution = static_cast<uint32_t>(data[index++]);
    DhcpOptionList options;
    options.size = static_cast<uint32_t>(data[index++]);
    char ifname = static_cast<char>(data[0]);
    uint32_t ipAdd = 0;
    memcpy_s(&ipAdd, sizeof(uint32_t), "192.168.100.1", sizeof(uint32_t));
    int force = static_cast<int>(data[index++]);
    int mode = static_cast<int>(data[index++]);
    uint8_t macAddr[DHCP_HWADDR_LENGTH];
    InitAddressPool(&pool, &ifname, &options);
    FreeAddressPool(&pool);
    IsReservedIp(&pool, ipAdd);
    AddReservedBinding(&macAddr[0]);
    RemoveReservedBinding(&macAddr[0]);
    RemoveBinding(&macAddr[0]);
    AddBinding(&binding);
    AddLease(&pool, &binding);
    GetLease(&pool, ipAdd);
    UpdateLease(&pool, &binding);
    RemoveLease(&pool, &binding);
    LoadBindingRecoders(&pool);
    SaveBindingRecoders(&pool, force);
    QueryBinding(macAddr, &options);
    SetDistributeMode(mode);
    GetDistributeMode();
    DeleteMacInLease(&pool, &binding);
    DeleteMacInLease(nullptr, &binding);
    DeleteMacInLease(&pool, nullptr);
}

void FindBindingByIpFuzzTest(const uint8_t* data, size_t size)
{
    uint32_t ipAddress1 = ParseIpAddr("192.168.100.1");
    uint32_t ipAddress2 = ParseIpAddr("192.168.100.2");
    FindBindingByIp(ipAddress1);
    FindBindingByIp(ipAddress2);
}

void DhcpMacAddrFuzzTest(const uint8_t* data, size_t size)
{
    uint8_t testMac1[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x09, 0};
    uint8_t testMac2[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x0b, 0};
    uint8_t testMac3[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x0a, 0};
    ReleaseBinding((testMac1));
    ReleaseBinding((testMac2));
    IsReserved((testMac1));
    IsReserved((testMac3));
}


/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    sleep(DHCP_SLEEP_1);
    OHOS::Wifi::DhcpAddressPoolFuzzTest(data, size);
    OHOS::Wifi::FindBindingByIpFuzzTest(data, size);
    OHOS::Wifi::DhcpMacAddrFuzzTest(data, size);
    return 0;
}
}  // namespace Wifi
}  // namespace OHOS
