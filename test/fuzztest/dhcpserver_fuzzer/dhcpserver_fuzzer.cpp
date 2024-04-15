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

namespace OHOS {
namespace DHCP {
    std::shared_ptr<DhcpServer> dhcpServer = DhcpServer::GetInstance(DHCP_SERVER_ABILITY_ID);
    static OHOS::sptr<DhcpServerCallBack> dhcpServerCallBack =
        OHOS::sptr<DhcpServerCallBack>(new (std::nothrow)DhcpServerCallBack());
    bool DhcpServerFuzzerTest(const uint8_t* data, size_t size)
    {
        if (dhcpServer == nullptr) {
            return false;
        }
        std::string ifname = std::string(reinterpret_cast<const char*>(data), size);
        DhcpRange range;
        int call = 2;
        range.strTagName = std::string(reinterpret_cast<const char*>(data), size);
        range.strStartip = std::string(reinterpret_cast<const char*>(data), size);
        range.strEndip = std::string(reinterpret_cast<const char*>(data), size);
        range.strSubnet = std::string(reinterpret_cast<const   char*>(data), size);
        range.iptype = static_cast<int>(data[0]) % call;
        range.leaseHours = static_cast<int>(data[0]);
        std::vector<std::string> dhcpClientInfo;
        dhcpClientInfo.push_back(std::string(reinterpret_cast<const   char*>(data), size));

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
    OHOS::DHCP::DhcpServerFuzzerTest(data, size);
    return 0;
}
