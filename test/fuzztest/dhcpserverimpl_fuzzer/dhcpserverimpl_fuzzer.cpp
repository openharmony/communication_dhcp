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
#include <fuzzer/FuzzedDataProvider.h>
#include "dhcpserverimpl_fuzzer.h"
#include "securec.h"
#include "dhcp_server_service_impl.h"
#include "dhcp_server_death_recipient.h"
#include "iremote_object.h"

namespace OHOS {
namespace DHCP {
constexpr size_t U32_AT_SIZE_ZERO = 4;
constexpr size_t DHCP_SLEEP_1 = 2;
constexpr size_t MAX_STRING_SIZE = 1024;
static const int32_t NUM_BYTES = 1;
sptr<DhcpServerServiceImpl> pDhcpServerServiceImpl = DhcpServerServiceImpl::GetInstance();

void InitTest(const uint8_t* data, size_t size)
{
    pDhcpServerServiceImpl->OnStart();
    std::string ifname = "";
    pDhcpServerServiceImpl->StartDhcpServer(ifname);
    ifname = std::string(reinterpret_cast<const char*>(data), size);
    pDhcpServerServiceImpl->StartDhcpServer(ifname);
    std::string ifname1 = "wlan0";
    std::string ifname2 = "";
    pDhcpServerServiceImpl->StopDhcpServer(ifname1);
    pDhcpServerServiceImpl->StopDhcpServer(ifname2);
    pDhcpServerServiceImpl->StopDhcpServer(ifname);
    std::string tagName = "sta";
    DhcpRange range;
    range.iptype = 0;
    pDhcpServerServiceImpl->PutDhcpRange(tagName, range);
    pDhcpServerServiceImpl->PutDhcpRange("", range);
    pDhcpServerServiceImpl->PutDhcpRange(ifname, range);
    pDhcpServerServiceImpl->RemoveDhcpRange(tagName, range);
    pDhcpServerServiceImpl->RemoveDhcpRange("", range);
    pDhcpServerServiceImpl->RemoveDhcpRange(ifname, range);
    std::string tagName2 = "";
    pDhcpServerServiceImpl->RemoveAllDhcpRange(tagName);
    pDhcpServerServiceImpl->RemoveAllDhcpRange(tagName2);
    pDhcpServerServiceImpl->RemoveAllDhcpRange(ifname);
    pDhcpServerServiceImpl->SetDhcpRange(ifname, range);
    pDhcpServerServiceImpl->SetDhcpRange(ifname1, range);
    pDhcpServerServiceImpl->SetDhcpName(ifname1, tagName);
    pDhcpServerServiceImpl->SetDhcpName("", tagName);
    pDhcpServerServiceImpl->SetDhcpName(ifname1, "");
    pDhcpServerServiceImpl->SetDhcpName("", "");
    pDhcpServerServiceImpl->SetDhcpName(ifname, tagName);
    pDhcpServerServiceImpl->IsRemoteDied();
    pDhcpServerServiceImpl->DeleteLeaseFile(ifname1);
    pDhcpServerServiceImpl->DeleteLeaseFile(ifname);
    pDhcpServerServiceImpl->CheckAndUpdateConf("");
    pDhcpServerServiceImpl->CheckAndUpdateConf(ifname1);
    pDhcpServerServiceImpl->CheckAndUpdateConf(ifname);
    pDhcpServerServiceImpl->AddSpecifiedInterface(ifname);
    pDhcpServerServiceImpl->AddSpecifiedInterface(ifname1);
    pDhcpServerServiceImpl->OnStop();
}


void GetDhcpClientInfosTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    std::string ifname1 = "";
    std::string ifname2 = "wlan0";
    std::vector<std::string> leases;
    size_t safeSize = (size > MAX_STRING_SIZE) ? MAX_STRING_SIZE : size;
    leases.push_back(std::string(reinterpret_cast<const char*>(data), safeSize));
    pDhcpServerServiceImpl->GetDhcpClientInfos(ifname1, leases);
    pDhcpServerServiceImpl->GetDhcpClientInfos(ifname2, leases);
}

void UpdateLeasesTimeTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    size_t safeSize = (size > MAX_STRING_SIZE) ? MAX_STRING_SIZE : size;
    std::string leaseTime = std::string(reinterpret_cast<const char*>(data), safeSize);
    pDhcpServerServiceImpl->UpdateLeasesTime(leaseTime);
}

void CheckIpAddrRangeTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    DhcpRange range;
    int call = 2;
    range.strTagName = FDP.ConsumeBytesAsString(NUM_BYTES);
    range.strStartip = FDP.ConsumeBytesAsString(NUM_BYTES);
    range.strEndip = FDP.ConsumeBytesAsString(NUM_BYTES);
    range.strSubnet = FDP.ConsumeBytesAsString(NUM_BYTES);
    range.iptype = FDP.ConsumeIntegral<int>() % call;
    range.leaseHours = FDP.ConsumeIntegral<int>();
    pDhcpServerServiceImpl->CheckIpAddrRange(range);
}


void GetUsingIpRangeTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    std::string ifname1 = "";
    std::string ifname2 = "ww";
    std::string ifname3 = "wlan0";
    size_t safeSize = (size > MAX_STRING_SIZE) ? MAX_STRING_SIZE : size;
    std::string ipRange = std::string(reinterpret_cast<const char*>(data), safeSize);
    pDhcpServerServiceImpl->GetUsingIpRange(ifname1, ipRange);
    pDhcpServerServiceImpl->GetUsingIpRange(ifname2, ipRange);
    pDhcpServerServiceImpl->GetUsingIpRange(ifname3, ipRange);
}

void CreateDefaultConfigFileTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    size_t safeSize = (size > MAX_STRING_SIZE) ? MAX_STRING_SIZE : size;
    std::string strFile = std::string(reinterpret_cast<const char*>(data), safeSize);
    pDhcpServerServiceImpl->CreateDefaultConfigFile(strFile);
}

void DelSpecifiedInterfaceTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    size_t safeSize = (size > MAX_STRING_SIZE) ? MAX_STRING_SIZE : size;
    std::string ifname = std::string(reinterpret_cast<const char*>(data), safeSize);
    pDhcpServerServiceImpl->DelSpecifiedInterface(ifname);
}

void RegisterDhcpServerCallBackTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    size_t safeSize = (size > MAX_STRING_SIZE) ? MAX_STRING_SIZE : size;
    std::string ifname = std::string(reinterpret_cast<const char*>(data), safeSize);
    sptr<IDhcpServerCallBack> serverCallback;
    pDhcpServerServiceImpl->RegisterDhcpServerCallBack(ifname, serverCallback);
}

void DeviceInfoCallBackTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    size_t safeSize = (size > MAX_STRING_SIZE) ? MAX_STRING_SIZE : size;
    std::string ifname = std::string(reinterpret_cast<const char*>(data), safeSize);
    pDhcpServerServiceImpl->DeviceInfoCallBack(ifname);
}

void ConvertLeasesToStationInfosTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    std::vector<std::string> leases;
    std::vector<DhcpStationInfo> stationInfos = {};
    size_t safeSize = (size > MAX_STRING_SIZE) ? MAX_STRING_SIZE : size;
    leases.push_back(std::string(reinterpret_cast<const char*>(data), safeSize));
    pDhcpServerServiceImpl->ConvertLeasesToStationInfos(leases, stationInfos);
}

void DeviceConnectCallBackTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    std::string safeIfname(reinterpret_cast<const char*>(data), size);
    DeviceConnectCallBack(safeIfname.c_str());
}

void SetDhcpNameExtTest(const uint8_t* data, size_t size)
{
    std::string ifname = std::string(reinterpret_cast<const char*>(data), size);
    std::string tagName = std::string(reinterpret_cast<const char*>(data), size);
    std::map<std::string, std::list<DhcpRange>> m_mapTagDhcpRange = {};
    std::list<DhcpRange> dhcpRangelist;
    DhcpRange dhcpRange;
    dhcpRange.strTagName = "";
    dhcpRange.iptype = 0;
    dhcpRangelist.push_back(dhcpRange);
    m_mapTagDhcpRange[""] = dhcpRangelist;
    pDhcpServerServiceImpl->m_mapTagDhcpRange = m_mapTagDhcpRange;
    pDhcpServerServiceImpl->SetDhcpNameExt(ifname, tagName);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::DHCP::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    FuzzedDataProvider FDP(data, size);
    sleep(DHCP_SLEEP_1);
    OHOS::DHCP::InitTest(data, size);
    OHOS::DHCP::GetDhcpClientInfosTest(data, size);
    OHOS::DHCP::UpdateLeasesTimeTest(data, size);
    OHOS::DHCP::CheckIpAddrRangeTest(data, size);
    OHOS::DHCP::GetUsingIpRangeTest(data, size);
    OHOS::DHCP::CreateDefaultConfigFileTest(data, size);
    OHOS::DHCP::DelSpecifiedInterfaceTest(data, size);
    OHOS::DHCP::RegisterDhcpServerCallBackTest(data, size);
    OHOS::DHCP::DeviceInfoCallBackTest(data, size);
    OHOS::DHCP::ConvertLeasesToStationInfosTest(data, size);
    OHOS::DHCP::DeviceConnectCallBackTest(data, size);
    OHOS::DHCP::SetDhcpNameExtTest(data, size);
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS
