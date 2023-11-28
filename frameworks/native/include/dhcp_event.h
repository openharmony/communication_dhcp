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
#ifndef OHOS_DHCP_SA_EVENT_H
#define OHOS_DHCP_SA_EVENT_H

#include "dhcp_logger.h"
#ifndef OHOS_ARCH_LITE
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#endif
#include "securec.h"
#include "dhcp_errcode.h"
#include "../../../interfaces/kits/c/dhcp_result_event.h"
#include "../interfaces/i_dhcp_client_callback.h"
#include "../interfaces/i_dhcp_server_callback.h"
#include "../../../interfaces/inner_api/include/dhcp_define.h"

class DhcpClientCallBack : public OHOS::Wifi::IDhcpClientCallBack {
public:
    DhcpClientCallBack();
    virtual ~DhcpClientCallBack();
public:
    void OnIpSuccessChanged(int status, const std::string& ifname, OHOS::Wifi::DhcpResult& result) override;
    void OnIpFailChanged(int status, const std::string& ifname, const std::string& reason) override;
#ifndef OHOS_ARCH_LITE
    OHOS::sptr<OHOS::IRemoteObject> AsObject() override;
#endif
    void RegisterCallBack(const std::string& ifname, const ClientCallBack *event);
    const ClientCallBack *callbackEvent;
};

class DhcpServerCallBack : public OHOS::Wifi::IDhcpServerCallBack {
public:
    DhcpServerCallBack();
    virtual ~DhcpServerCallBack();
public:
    void OnServerStatusChanged(int status) override;
    void OnServerLeasesChanged(const std::string& ifname, std::vector<std::string>& leases) override;
    void OnServerSerExitChanged(const std::string& ifname) override;
#ifndef OHOS_ARCH_LITE
    OHOS::sptr<OHOS::IRemoteObject> AsObject() override;
#endif
    void RegisterCallBack(const std::string& ifname, const ServerCallBack *event);
    const ServerCallBack *callbackEvent;
};
#endif