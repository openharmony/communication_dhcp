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

#include "dhcpserver_fuzzer.h"
#include "dhcp_define.h"
#include "dhcp_server.h"
#include "dhcp_event.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace DHCP {
    static const int32_t NUM_BYTES = 1;
    std::shared_ptr<DhcpServer> dhcpServer = DhcpServer::GetInstance(DHCP_SERVER_ABILITY_ID);
    static OHOS::sptr<DhcpServerCallBack> dhcpServerCallBack =
        OHOS::sptr<DhcpServerCallBack>(new (std::nothrow)DhcpServerCallBack());
    bool DhcpServerFuzzerTest(FuzzedDataProvider& FDP)
    {
        if (dhcpServer == nullptr) {
            return false;
        }
        std::string ifname = FDP.ConsumeBytesAsString(NUM_BYTES);
        DhcpRange range;
        int call = 2;
        range.strTagName = FDP.ConsumeBytesAsString(NUM_BYTES);
        range.strStartip = FDP.ConsumeBytesAsString(NUM_BYTES);
        range.strEndip = FDP.ConsumeBytesAsString(NUM_BYTES);
        range.strSubnet = FDP.ConsumeBytesAsString(NUM_BYTES);
        range.iptype = FDP.ConsumeIntegral<int>() % call;
        range.leaseHours = FDP.ConsumeIntegral<int>();
        std::vector<std::string> dhcpClientInfo;
        dhcpClientInfo.push_back(FDP.ConsumeBytesAsString(NUM_BYTES));

        dhcpServer->StartDhcpServer(ifname);
        dhcpServer->StopDhcpServer(ifname);
        dhcpServer->PutDhcpRange(ifname, range);
        dhcpServer->RemoveDhcpRange(ifname, range);
        dhcpServer->RemoveAllDhcpRange(ifname);
        dhcpServer->SetDhcpRange(ifname, range);
        dhcpServer->SetDhcpName(ifname, ifname);
        dhcpServer->GetDhcpClientInfos(ifname, dhcpClientInfo);
        dhcpServer->UpdateLeasesTime(ifname);
        dhcpServer->RegisterDhcpServerCallBack(ifname, dhcpServerCallBack);

        return true;
    }
}  // namespace DHCP
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    OHOS::DHCP::DhcpServerFuzzerTest(FDP);
    return 0;
}
