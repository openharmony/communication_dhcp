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
#include <fuzzer/FuzzedDataProvider.h>
#include "securec.h"
#include "address_utils.h"
#include "dhcp_s_define.h"

namespace OHOS {
namespace DHCP {
constexpr size_t DHCP_SLEEP_1 = 2;
constexpr size_t U32_AT_SIZE_ZERO = 4;
constexpr int CFG_DATA_MAX_BYTES = 20;

void NetworkAddressTest(FuzzedDataProvider& FDP)
{
    uint32_t ip = FDP.ConsumeIntegral<uint32_t>();
    uint32_t netmask = FDP.ConsumeIntegral<uint32_t>();
    NetworkAddress(ip, netmask);
}

void FirstIpAddressTest(FuzzedDataProvider& FDP)
{
    uint32_t ip = FDP.ConsumeIntegral<uint32_t>();
    uint32_t netmask = FDP.ConsumeIntegral<uint32_t>();
    FirstIpAddress(ip, netmask);
}

void NextIpAddressTest(FuzzedDataProvider& FDP)
{
    uint32_t currIp = FDP.ConsumeIntegral<uint32_t>();
    uint32_t netmask = FDP.ConsumeIntegral<uint32_t>();
    uint32_t offset = FDP.ConsumeIntegral<uint32_t>();
    NextIpAddress(currIp, netmask, offset);
}

void FirstNetIpAddressTest(FuzzedDataProvider& FDP)
{
    uint32_t networkAddr = FDP.ConsumeIntegral<uint32_t>();
    FirstNetIpAddress(networkAddr);
}

void LastIpAddressTest(FuzzedDataProvider& FDP)
{
    uint32_t ip = FDP.ConsumeIntegral<uint32_t>();
    uint32_t netmask = FDP.ConsumeIntegral<uint32_t>();
    LastIpAddress(ip, netmask);
}

void IpInNetworkTest(FuzzedDataProvider& FDP)
{
    uint32_t ip = FDP.ConsumeIntegral<uint32_t>();
    uint32_t network = FDP.ConsumeIntegral<uint32_t>();
    uint32_t netmask = FDP.ConsumeIntegral<uint32_t>();
    IpInNetwork(ip, network, netmask);
}

void IpInRangeTest(FuzzedDataProvider& FDP)
{
    uint32_t ip = FDP.ConsumeIntegral<uint32_t>();
    uint32_t beginIp = FDP.ConsumeIntegral<uint32_t>();
    uint32_t endIp = FDP.ConsumeIntegral<uint32_t>();
    uint32_t netmask = FDP.ConsumeIntegral<uint32_t>();
    IpInRange(ip, beginIp, endIp, netmask);
}

void BroadCastAddressTest(FuzzedDataProvider& FDP)
{
    uint32_t ip = FDP.ConsumeIntegral<uint32_t>();
    uint32_t netmask = FDP.ConsumeIntegral<uint32_t>();
    BroadCastAddress(ip, netmask);
}

void ParseIpAddrTest(const uint8_t* data, size_t size)
{
    const char *strIp = "TEXT";
    (void)ParseIpAddr(strIp);
}

void HostTotalTest(FuzzedDataProvider& FDP)
{
    uint32_t netmask = FDP.ConsumeIntegral<uint32_t>();
    HostTotal(netmask);
}

void ParseIpTest(const uint8_t* data, size_t size)
{
    uint8_t *ipAddr = nullptr;
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

void HostToNetworkTest(FuzzedDataProvider& FDP)
{
    uint32_t host = FDP.ConsumeIntegral<uint32_t>();
    HostToNetwork(host);
}

void NetworkToHostTest(FuzzedDataProvider& FDP)
{
    uint32_t network = FDP.ConsumeIntegral<uint32_t>();
    NetworkToHost(network);
}

void ParseLogMacTest(const uint8_t* data, size_t size)
{
    uint8_t macAddr[DHCP_HWADDR_LENGTH];
    ParseLogMac(&macAddr[0]);
}

void AddrEquelsTest(FuzzedDataProvider& FDP)
{
    int addrLength = FDP.ConsumeIntegral<int>();
    uint8_t firstAddr[DHCP_HWADDR_LENGTH];
    uint8_t secondAddr[DHCP_HWADDR_LENGTH];
    AddrEquels(&firstAddr[0], &secondAddr[0], addrLength);
}

void ParseIpFuzzTest(const uint8_t* data, size_t size)
{
    const uint8_t *ipAddr = reinterpret_cast<const uint8_t *>(data);
    ParseIp(ipAddr);
}

void ParseStrIpFuzzTest(FuzzedDataProvider& FDP)
{
    uint32_t ipAddr = FDP.ConsumeIntegral<uint32_t>();
    ParseStrIp(ipAddr);
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::DHCP::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    FuzzedDataProvider FDP(data, size);
    sleep(DHCP_SLEEP_1);
    OHOS::DHCP::NetworkAddressTest(FDP);
    OHOS::DHCP::FirstIpAddressTest(FDP);
    OHOS::DHCP::NextIpAddressTest(FDP);
    OHOS::DHCP::FirstNetIpAddressTest(FDP);
    OHOS::DHCP::LastIpAddressTest(FDP);
    OHOS::DHCP::IpInNetworkTest(FDP);
    OHOS::DHCP::IpInRangeTest(FDP);
    OHOS::DHCP::BroadCastAddressTest(FDP);
    OHOS::DHCP::ParseIpAddrTest(data, size);
    OHOS::DHCP::HostTotalTest(FDP);
    OHOS::DHCP::ParseIpTest(data, size);
    OHOS::DHCP::IsEmptyHWAddrTest(data, size);
    OHOS::DHCP::ParseStrMacTest(data, size);
    OHOS::DHCP::ParseMacAddressTest(data, size);
    OHOS::DHCP::ParseHostNameTest(data, size);
    OHOS::DHCP::HostToNetworkTest(FDP);
    OHOS::DHCP::NetworkToHostTest(FDP);
    OHOS::DHCP::ParseLogMacTest(data, size);
    OHOS::DHCP::AddrEquelsTest(FDP);
    OHOS::DHCP::ParseIpFuzzTest(data, size);
    OHOS::DHCP::ParseStrIpFuzzTest(FDP);
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS
