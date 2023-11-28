/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
#include "dhcp_event.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpSAEvent");

DhcpClientCallBack::DhcpClientCallBack() : callbackEvent(nullptr)
{
    DHCP_LOGI("DhcpClientCallBack");
}

DhcpClientCallBack::~DhcpClientCallBack()
{
    DHCP_LOGI("~DhcpClientCallBack");
}

void DhcpClientCallBack::OnIpSuccessChanged(int status, const std::string& ifname, OHOS::Wifi::DhcpResult& result)
{
    DHCP_LOGI("DhcpClientCallBack OnIpSuccessChanged status:%{public}d,ifname:%{public}s", status, ifname.c_str());
    if (callbackEvent) {
        DhcpResult dhcpResult;
        dhcpResult.iptype = result.iptype;
        dhcpResult.isOptSuc = result.isOptSuc;
        dhcpResult.uOptLeasetime = result.uLeaseTime;
        dhcpResult.uAddTime = result.uAddTime;
        dhcpResult.uGetTime = result.uGetTime;
        if (strcpy_s(dhcpResult.strOptClientId, INET_ADDRSTRLEN, result.strYourCli.c_str()) != EOK) {
            DHCP_LOGE("OnIpSuccessChanged strOptClientId strcpy_s failed!");
        }
        if (strcpy_s(dhcpResult.strOptServerId, INET_ADDRSTRLEN, result.strServer.c_str()) != EOK) {
            DHCP_LOGE("OnIpSuccessChanged strOptServerId strcpy_s failed!");
        }
        if (strcpy_s(dhcpResult.strOptSubnet, INET_ADDRSTRLEN, result.strSubnet.c_str()) != EOK) {
            DHCP_LOGE("OnIpSuccessChanged strOptSubnet strcpy_s failed!");
        }
        if (strcpy_s(dhcpResult.strOptDns1, INET_ADDRSTRLEN, result.strDns1.c_str()) != EOK) {
            DHCP_LOGE("OnIpSuccessChanged strOptDns1 strcpy_s failed!");
        }
        if (strcpy_s(dhcpResult.strOptDns2, INET_ADDRSTRLEN, result.strDns2.c_str()) != EOK) {
            DHCP_LOGE("OnIpSuccessChanged strOptDns2 strcpy_s failed!");
        }
        if (strcpy_s(dhcpResult.strOptRouter1, INET_ADDRSTRLEN, result.strRouter1.c_str()) != EOK) {
            DHCP_LOGE("OnIpSuccessChanged strOptRouter1 strcpy_s failed!");
        }
        if (strcpy_s(dhcpResult.strOptRouter2, INET_ADDRSTRLEN, result.strRouter2.c_str()) != EOK) {
            DHCP_LOGE("OnIpSuccessChanged strOptRouter2 strcpy_s failed!");
        }
        if (strcpy_s(dhcpResult.strOptVendor, INET_ADDRSTRLEN, result.strVendor.c_str()) != EOK) {
            DHCP_LOGE("OnIpSuccessChanged strOptVendor strcpy_s failed!");
        }
        DHCP_LOGI("OnIpSuccessChanged callbackEvent status:%{public}d", status);
        callbackEvent->OnIpSuccessChanged(status, ifname.c_str(), &dhcpResult);
    }
}

void DhcpClientCallBack::OnIpFailChanged(int status, const std::string& ifname, const std::string& reason) 
{
    DHCP_LOGI("DhcpClientCallBack OnIpFailChanged status:%{public}d, ifname:%{public}s, reason:%{public}s", status,
        ifname.c_str(), reason.c_str());
    if (callbackEvent) {
        DHCP_LOGI("OnIpSuccessChanged OnIpFailChanged ok");
        callbackEvent->OnIpFailChanged(status, ifname.c_str(), reason.c_str());
    }
}
#ifndef OHOS_ARCH_LITE
OHOS::sptr<OHOS::IRemoteObject> DhcpClientCallBack::AsObject() 
{
    DHCP_LOGI("DhcpClientCallBack AsObject!");
    return nullptr;
}
#endif
void DhcpClientCallBack::RegisterCallBack(const std::string& ifname, const ClientCallBack *event)
{
    if (event == nullptr) {
        DHCP_LOGE("DhcpClientCallBack event is nullptr!");
        return;
    }
    callbackEvent = event;
}

DhcpServerCallBack::DhcpServerCallBack() : callbackEvent(nullptr)
{
    DHCP_LOGI("DhcpServerCallBack");
}

DhcpServerCallBack::~DhcpServerCallBack()
{
    DHCP_LOGI("~DhcpServerCallBack");
}
void DhcpServerCallBack::OnServerStatusChanged(int status)
{
    DHCP_LOGI("DhcpServerCallBack OnServerStatusChanged status:%{public}d", status);
}
void DhcpServerCallBack::OnServerLeasesChanged(const std::string& ifname, std::vector<std::string>& leases) 
{
    DHCP_LOGI("DhcpServerCallBack OnServerLeasesChanged ifname:%{public}s", ifname.c_str());
}
void DhcpServerCallBack::OnServerSerExitChanged(const std::string& ifname)
{
    DHCP_LOGI("DhcpServerCallBack OnServerSerExitChanged ifname:%{public}s", ifname.c_str());
}
#ifndef OHOS_ARCH_LITE
OHOS::sptr<OHOS::IRemoteObject> DhcpServerCallBack::AsObject() 
{
    DHCP_LOGI("DhcpServerCallBack AsObject!");
    return nullptr;
}
#endif
void DhcpServerCallBack::RegisterCallBack(const std::string& ifname, const ServerCallBack *event)
{
    if (event == nullptr) {
        DHCP_LOGE("DhcpServerCallBack event is nullptr!");
        return;
    }
    callbackEvent = event;
}