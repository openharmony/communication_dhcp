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
namespace Wifi {
constexpr size_t DHCP_SLEEP_1 = 2;

void NetworkAddressTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t ip = static_cast<uint32_t>(data[index++]);
    uint32_t netmask = static_cast<uint32_t>(data[index++]);
    NetworkAddress(ip, netmask);
}

void FirstIpAddressTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t ip = static_cast<uint32_t>(data[index++]);
    uint32_t netmask = static_cast<uint32_t>(data[index++]);
    FirstIpAddress(ip, netmask);
}

void NextIpAddressTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t currIp = static_cast<uint32_t>(data[index++]);
    uint32_t netmask = static_cast<uint32_t>(data[index++]);
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
    uint32_t netmask = static_cast<uint32_t>(data[index++]);
    LastIpAddress(ip, netmask);
}

void IpInNetworkTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t ip = static_cast<uint32_t>(data[index++]);
    uint32_t network = static_cast<uint32_t>(data[index++]);
    uint32_t netmask = static_cast<uint32_t>(data[index++]);
    IpInNetwork(ip, network, netmask);
}

void IpInRangeTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t ip = static_cast<uint32_t>(data[index++]);
    uint32_t beginIp = static_cast<uint32_t>(data[index++]);
    uint32_t endIp = static_cast<uint32_t>(data[index++]);
    uint32_t netmask = static_cast<uint32_t>(data[index++]);
    IpInRange(ip, beginIp, endIp, netmask);
}

void BroadCastAddressTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t ip = static_cast<uint32_t>(data[index++]);
    uint32_t netmask = static_cast<uint32_t>(data[index++]);
    BroadCastAddress(ip, netmask);
}

void ParseIpAddrTest(const uint8_t* data, size_t size)
{
    char strIp;
    if (size > 0) {
        strIp = static_cast<char>(data[0]);
    }
    (void)ParseIpAddr(&strIp);
}

void ParseIpHtonlTest(const uint8_t* data, size_t size)
{
    char strIp;
    if (size > 0) {
        strIp = static_cast<char>(data[0]);
    }
    (void)ParseIpHtonl(&strIp);
}

void NetworkBitsTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t netmask = static_cast<uint32_t>(data[index++]);
    NetworkBits(netmask);
}

void HostBitsTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t netmask = static_cast<uint32_t>(data[index++]);
    HostBits(netmask);
}

void HostTotalTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t netmask = static_cast<uint32_t>(data[index++]);
    HostTotal(netmask);
}

void ParseIpTest(const uint8_t* data, size_t size)
{
    uint8_t index = 0;
    uint8_t ipAddr = static_cast<uint8_t>(data[index++]);
    ParseIp(&ipAddr);
}

void ParseStrIpTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t ipAddr = static_cast<uint32_t>(data[index++]);
    ParseStrIp(ipAddr);
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
    char strMac;
    uint8_t macAddr[DHCP_HWADDR_LENGTH];
    if (size > 0) {
        strMac = static_cast<char>(data[0]);
    }
    (void)ParseMacAddress(&strMac, &macAddr[0]);
}

void ParseHostNameTest(const uint8_t* data, size_t size)
{
    char strHostName;
    char hostName[DHCP_BOOT_FILE_LENGTH];
    if (size > 0) {
        strHostName = static_cast<char>(data[0]);
    }
    (void)ParseHostName(&strHostName, &hostName[0]);
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
    if (data == nullptr) {
        return 0;
    }
    sleep(DHCP_SLEEP_1);
    OHOS::Wifi::NetworkAddressTest(data, size);
    OHOS::Wifi::FirstIpAddressTest(data, size);
    OHOS::Wifi::NextIpAddressTest(data, size);
    OHOS::Wifi::FirstNetIpAddressTest(data, size);
    OHOS::Wifi::LastIpAddressTest(data, size);
    OHOS::Wifi::IpInNetworkTest(data, size);
    OHOS::Wifi::IpInRangeTest(data, size);
    OHOS::Wifi::BroadCastAddressTest(data, size);
    OHOS::Wifi::ParseIpAddrTest(data, size);
    OHOS::Wifi::ParseIpHtonlTest(data, size);
    OHOS::Wifi::NetworkBitsTest(data, size);
    OHOS::Wifi::HostBitsTest(data, size);
    OHOS::Wifi::HostTotalTest(data, size);
    OHOS::Wifi::ParseIpTest(data, size);
    OHOS::Wifi::ParseStrIpTest(data, size);
    OHOS::Wifi::IsEmptyHWAddrTest(data, size);
    OHOS::Wifi::ParseStrMacTest(data, size);
    OHOS::Wifi::ParseMacAddressTest(data, size);
    OHOS::Wifi::ParseHostNameTest(data, size);
    OHOS::Wifi::HostToNetworkTest(data, size);
    OHOS::Wifi::NetworkToHostTest(data, size);
    OHOS::Wifi::ParseLogMacTest(data, size);
    OHOS::Wifi::AddrEquelsTest(data, size);
    return 0;
}
}  // namespace Wifi
}  // namespace OHOS
