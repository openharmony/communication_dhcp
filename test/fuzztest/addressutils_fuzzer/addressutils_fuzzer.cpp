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

#include "addressutils_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "securec.h"
#include "address_utils.h"
#include "dhcp_s_define.h"

namespace OHOS {
namespace DHCP {
constexpr size_t DHCP_SLEEP_1 = 2;
constexpr size_t U32_AT_SIZE_ZERO = 4;
constexpr int CFG_DATA_MAX_BYTES = 20;

void NetworkAddressTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t ip = static_cast<uint32_t>(data[index++]);
    uint32_t netmask = static_cast<uint32_t>(data[0]);
    NetworkAddress(ip, netmask);
}

void FirstIpAddressTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t ip = static_cast<uint32_t>(data[index++]);
    uint32_t netmask = static_cast<uint32_t>(data[0]);
    FirstIpAddress(ip, netmask);
}

void NextIpAddressTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t currIp = static_cast<uint32_t>(data[index++]);
    uint32_t netmask = static_cast<uint32_t>(data[0]);
    uint32_t offset = static_cast<uint32_t>(data[index++]);
    NextIpAddress(currIp, netmask, offset);
}

void FirstNetIpAddressTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t networkAddr = static_cast<uint32_t>(data[index++]);
    FirstNetIpAddress(networkAddr);
}

void LastIpAddressTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t ip = static_cast<uint32_t>(data[index++]);
    uint32_t netmask = static_cast<uint32_t>(data[0]);
    LastIpAddress(ip, netmask);
}

void IpInNetworkTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t ip = static_cast<uint32_t>(data[index++]);
    uint32_t network = static_cast<uint32_t>(data[index++]);
    uint32_t netmask = static_cast<uint32_t>(data[0]);
    IpInNetwork(ip, network, netmask);
}

void IpInRangeTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t ip = static_cast<uint32_t>(data[index++]);
    uint32_t beginIp = static_cast<uint32_t>(data[index++]);
    uint32_t endIp = static_cast<uint32_t>(data[index++]);
    uint32_t netmask = static_cast<uint32_t>(data[0]);
    IpInRange(ip, beginIp, endIp, netmask);
}

void BroadCastAddressTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t ip = static_cast<uint32_t>(data[index++]);
    uint32_t netmask = static_cast<uint32_t>(data[0]);
    BroadCastAddress(ip, netmask);
}

void ParseIpAddrTest(const uint8_t* data, size_t size)
{
    const char *strIp = "TEXT";
    (void)ParseIpAddr(strIp);
}

void HostTotalTest(const uint8_t* data, size_t size)
{
    uint32_t netmask = static_cast<uint32_t>(data[0]);
    HostTotal(netmask);
}

void ParseIpTest(const uint8_t* data, size_t size)
{
    uint8_t *ipAddr = NULL;
    if (memcpy_s(ipAddr, CFG_DATA_MAX_BYTES, data, CFG_DATA_MAX_BYTES - 1) != EOK) {
        return;
    }
    ParseIp(ipAddr);
}

void IsEmptyHWAddrTest(const uint8_t* data, size_t size)
{
    uint8_t ipAddr[DHCP_HWADDR_LENGTH];
    IsEmptyHWAddr(&ipAddr[0]);
}

void ParseStrMacTest(const uint8_t* data, size_t size)
{
    uint8_t* macAddr = nullptr;
    size_t addrSize = MAC_ADDR_LENGTH;
    ParseStrMac(macAddr, addrSize);
}

void ParseMacAddressTest(const uint8_t* data, size_t size)
{
    const char *strMac = "TEXT";
    uint8_t macAddr[DHCP_HWADDR_LENGTH];
    (void)ParseMacAddress(strMac, &macAddr[0]);
}

void ParseHostNameTest(const uint8_t* data, size_t size)
{
    const char *strHostName = "TEXT";
    char hostName[DHCP_BOOT_FILE_LENGTH];
    (void)ParseHostName(strHostName, &hostName[0]);
}

void HostToNetworkTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t host = static_cast<uint32_t>(data[index++]);
    HostToNetwork(host);
}

void NetworkToHostTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t network = static_cast<uint32_t>(data[index++]);
    NetworkToHost(network);
}

void ParseLogMacTest(const uint8_t* data, size_t size)
{
    uint8_t macAddr[DHCP_HWADDR_LENGTH];
    ParseLogMac(&macAddr[0]);
}

void AddrEquelsTest(const uint8_t* data, size_t size)
{
    int index = 0;
    int addrLength = static_cast<int>(data[index++]);
    uint8_t firstAddr[DHCP_HWADDR_LENGTH];
    uint8_t secondAddr[DHCP_HWADDR_LENGTH];
    AddrEquels(&firstAddr[0], &secondAddr[0], addrLength);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::DHCP::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    sleep(DHCP_SLEEP_1);
    OHOS::DHCP::NetworkAddressTest(data, size);
    OHOS::DHCP::FirstIpAddressTest(data, size);
    OHOS::DHCP::NextIpAddressTest(data, size);
    OHOS::DHCP::FirstNetIpAddressTest(data, size);
    OHOS::DHCP::LastIpAddressTest(data, size);
    OHOS::DHCP::IpInNetworkTest(data, size);
    OHOS::DHCP::IpInRangeTest(data, size);
    OHOS::DHCP::BroadCastAddressTest(data, size);
    OHOS::DHCP::ParseIpAddrTest(data, size);
    OHOS::DHCP::HostTotalTest(data, size);
    OHOS::DHCP::ParseIpTest(data, size);
    OHOS::DHCP::IsEmptyHWAddrTest(data, size);
    OHOS::DHCP::ParseStrMacTest(data, size);
    OHOS::DHCP::ParseMacAddressTest(data, size);
    OHOS::DHCP::ParseHostNameTest(data, size);
    OHOS::DHCP::HostToNetworkTest(data, size);
    OHOS::DHCP::NetworkToHostTest(data, size);
    OHOS::DHCP::ParseLogMacTest(data, size);
    OHOS::DHCP::AddrEquelsTest(data, size);
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS
