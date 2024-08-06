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
#include "dhcpserverimpl_fuzzer.h"
#include "securec.h"
#include "dhcp_server_service_impl.h"
#include "dhcp_server_death_recipient.h"
#include "iremote_object.h"

namespace OHOS {
namespace DHCP {
constexpr size_t DHCP_SLEEP_1 = 2;
sptr<DhcpServerServiceImpl> pDhcpServerServiceImpl = DhcpServerServiceImpl::GetInstance();

void OnStartTest(const uint8_t* data, size_t size)
{
    pDhcpServerServiceImpl->OnStart();
}

void OnStopTest(const uint8_t* data, size_t size)
{
    pDhcpServerServiceImpl->OnStop();
}

void StartDhcpServerTest(const uint8_t* data, size_t size)
{
    std::string ifname1 = "wlan0";
    std::string ifname2 = "";
    pDhcpServerServiceImpl->StartDhcpServer(ifname1);
    pDhcpServerServiceImpl->StartDhcpServer(ifname2);
}

void StopDhcpServerTest(const uint8_t* data, size_t size)
{
    std::string ifname1 = "wlan0";
    std::string ifname2 = "";
    pDhcpServerServiceImpl->StopDhcpServer(ifname1);
    pDhcpServerServiceImpl->StopDhcpServer(ifname2);
}

void PutDhcpRangeTest(const uint8_t* data, size_t size)
{
    std::string tagName = "sta";
    DhcpRange range;
    range.iptype = 0;
    pDhcpServerServiceImpl->PutDhcpRange(tagName, range);
    pDhcpServerServiceImpl->PutDhcpRange("", range);
}

void RemoveDhcpRangeTest(const uint8_t* data, size_t size)
{
    std::string tagName = "sta";
    DhcpRange range;
    range.iptype = 0;
    pDhcpServerServiceImpl->RemoveDhcpRange(tagName, range);
    pDhcpServerServiceImpl->RemoveDhcpRange("", range);
}

void RemoveAllDhcpRangeTest(const uint8_t* data, size_t size)
{
    std::string tagName1 = "sta";
    std::string tagName2 = "";
    pDhcpServerServiceImpl->RemoveAllDhcpRange(tagName1);
    pDhcpServerServiceImpl->RemoveAllDhcpRange(tagName2);
}

void SetDhcpRangeTest(const uint8_t* data, size_t size)
{
    std::string ifname = "wlan0";
    DhcpRange range;
    range.iptype = 0;
    pDhcpServerServiceImpl->SetDhcpRange(ifname, range);
    range.strStartip = "192.168.2.2";
    range.strEndip = "192.168.2.200";
    range.strSubnet = "255.255.255.0";
    pDhcpServerServiceImpl->SetDhcpRange(ifname, range);
}

void SetDhcpNameTest(const uint8_t* data, size_t size)
{
    std::string ifname = "wlan0";
    std::string tagName = "sta";
    pDhcpServerServiceImpl->SetDhcpName(ifname, tagName);
    pDhcpServerServiceImpl->SetDhcpName("", tagName);
    pDhcpServerServiceImpl->SetDhcpName(ifname, "");
    pDhcpServerServiceImpl->SetDhcpName("", "");
}

void GetDhcpClientInfosTest(const uint8_t* data, size_t size)
{
    std::string ifname1 = "";
    std::string ifname2 = "wlan0";
    std::vector<std::string> leases;
    leases.push_back(std::string(reinterpret_cast<const char*>(data), size));
    pDhcpServerServiceImpl->GetDhcpClientInfos(ifname1, leases);
    pDhcpServerServiceImpl->GetDhcpClientInfos(ifname2, leases);
}

void UpdateLeasesTimeTest(const uint8_t* data, size_t size)
{
    std::string leaseTime = std::string(reinterpret_cast<const char*>(data), size);
    pDhcpServerServiceImpl->UpdateLeasesTime(leaseTime);
}

void IsRemoteDiedTest(const uint8_t* data, size_t size)
{
    pDhcpServerServiceImpl->IsRemoteDied();
}

void DeleteLeaseFileTest(const uint8_t* data, size_t size)
{
    std::string ifname = "wlan0";
    pDhcpServerServiceImpl->DeleteLeaseFile(ifname);
}

void CheckAndUpdateConfTest(const uint8_t* data, size_t size)
{
    std::string ifname1 = "";
    std::string ifname2 = "wlan0";
    pDhcpServerServiceImpl->CheckAndUpdateConf(ifname1);
    pDhcpServerServiceImpl->CheckAndUpdateConf(ifname2);
}

void CheckIpAddrRangeTest(const uint8_t* data, size_t size)
{
    DhcpRange range;
    int call = 2;
    range.strTagName = std::string(reinterpret_cast<const char*>(data), size);
    range.strStartip = std::string(reinterpret_cast<const char*>(data), size);
    range.strEndip = std::string(reinterpret_cast<const char*>(data), size);
    range.strSubnet = std::string(reinterpret_cast<const   char*>(data), size);
    range.iptype = static_cast<int>(data[0]) % call;
    range.leaseHours = static_cast<int>(data[0]);
    pDhcpServerServiceImpl->CheckIpAddrRange(range);
}

void AddSpecifiedInterfaceTest(const uint8_t* data, size_t size)
{
    std::string ifname = "wlan0";
    pDhcpServerServiceImpl->AddSpecifiedInterface(ifname);
}

void GetUsingIpRangeTest(const uint8_t* data, size_t size)
{
    std::string ifname1 = "";
    std::string ifname2 = "ww";
    std::string ifname3 = "wlan0";
    std::string ipRange = std::string(reinterpret_cast<const char*>(data), size);
    pDhcpServerServiceImpl->GetUsingIpRange(ifname1, ipRange);
    pDhcpServerServiceImpl->GetUsingIpRange(ifname2, ipRange);
    pDhcpServerServiceImpl->GetUsingIpRange(ifname3, ipRange);
}

void CreateDefaultConfigFileTest(const uint8_t* data, size_t size)
{
    std::string strFile = std::string(reinterpret_cast<const char*>(data), size);
    pDhcpServerServiceImpl->CreateDefaultConfigFile(strFile);
}

void UnregisterSignalTest(const uint8_t* data, size_t size)
{
    pDhcpServerServiceImpl->UnregisterSignal();
}

void IsNativeProcessTest(const uint8_t* data, size_t size)
{
    pDhcpServerServiceImpl->IsNativeProcess();
}

void DelSpecifiedInterfaceTest(const uint8_t* data, size_t size)
{
    std::string ifname = std::string(reinterpret_cast<const char*>(data), size);
    pDhcpServerServiceImpl->DelSpecifiedInterface(ifname);
}

void RegisterDhcpServerCallBackTest(const uint8_t* data, size_t size)
{
    std::string ifname = std::string(reinterpret_cast<const char*>(data), size);
    sptr<IDhcpServerCallBack> serverCallback;
    pDhcpServerServiceImpl->RegisterDhcpServerCallBack(ifname, serverCallback);
}

void StartServiceAbilityTest(const uint8_t* data, size_t size)
{
    int index = 0;
    int sleepS = static_cast<int>(index++);
    pDhcpServerServiceImpl->StartServiceAbility(sleepS);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    sleep(DHCP_SLEEP_1);
    OHOS::DHCP::OnStartTest(data, size);
    OHOS::DHCP::OnStopTest(data, size);
    OHOS::DHCP::StartDhcpServerTest(data, size);
    OHOS::DHCP::StopDhcpServerTest(data, size);
    OHOS::DHCP::PutDhcpRangeTest(data, size);
    OHOS::DHCP::RemoveDhcpRangeTest(data, size);
    OHOS::DHCP::RemoveAllDhcpRangeTest(data, size);
    OHOS::DHCP::SetDhcpRangeTest(data, size);
    OHOS::DHCP::SetDhcpNameTest(data, size);
    OHOS::DHCP::GetDhcpClientInfosTest(data, size);
    OHOS::DHCP::UpdateLeasesTimeTest(data, size);
    OHOS::DHCP::IsRemoteDiedTest(data, size);
    OHOS::DHCP::DeleteLeaseFileTest(data, size);
    OHOS::DHCP::CheckAndUpdateConfTest(data, size);
    OHOS::DHCP::CheckIpAddrRangeTest(data, size);
    OHOS::DHCP::AddSpecifiedInterfaceTest(data, size);
    OHOS::DHCP::GetUsingIpRangeTest(data, size);
    OHOS::DHCP::CreateDefaultConfigFileTest(data, size);
    OHOS::DHCP::UnregisterSignalTest(data, size);
    OHOS::DHCP::IsNativeProcessTest(data, size);
    OHOS::DHCP::DelSpecifiedInterfaceTest(data, size);
    OHOS::DHCP::RegisterDhcpServerCallBackTest(data, size);
    OHOS::DHCP::StartServiceAbilityTest(data, size);
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS
