/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef OHOS_DHCP_CLIENT_SERVICE_IMPL_H
#define OHOS_DHCP_CLIENT_SERVICE_IMPL_H

#include <map>
#include <list>
#include <thread>
#include <mutex>
#include "i_dhcp_client_callback.h"
#include "dhcp_client_def.h"
#include "dhcp_client_state_machine.h"
#ifdef OHOS_ARCH_LITE
#include "dhcp_client_stub_lite.h"
#else
#include "system_ability.h"
#include "iremote_object.h"
#include "dhcp_client_stub.h"
#endif

namespace OHOS {
namespace DHCP {
enum ClientServiceRunningState { STATE_NOT_START, STATE_RUNNING };
#ifdef OHOS_ARCH_LITE
class DhcpClientServiceImpl : public DhcpClientStub {
#else
class DhcpClientServiceImpl : public SystemAbility, public DhcpClientStub {
#endif

#ifndef OHOS_ARCH_LITE
    DECLARE_SYSTEM_ABILITY(DhcpClientServiceImpl);
#endif
    
public:
    DhcpClientServiceImpl();
    virtual ~DhcpClientServiceImpl();
#ifdef OHOS_ARCH_LITE
    static std::shared_ptr<DhcpClientServiceImpl> GetInstance();
    void OnStart();
    void OnStop();
#else
    static sptr<DhcpClientServiceImpl> GetInstance();
    void OnStart() override;
    void OnStop() override;
#endif

#ifdef OHOS_ARCH_LITE
    ErrCode RegisterDhcpClientCallBack(const std::string& ifname, const std::shared_ptr<IDhcpClientCallBack> &clientCallback) override;
#else
    ErrCode RegisterDhcpClientCallBack(const std::string& ifname, const sptr<IDhcpClientCallBack> &clientCallback) override;
#endif
    ErrCode StartDhcpClient(const RouterConfig &config) override;
    ErrCode StopDhcpClient(const std::string& ifname, bool bIpv6) override;
    bool IsRemoteDied(void) override;
    ErrCode StartOldClient(const RouterCfg &config, DhcpClient &dhcpClient);
    ErrCode StartNewClient(const RouterCfg &config);

    int DhcpIpv4ResultSuccess(struct DhcpIpResult &ipResult);
#ifndef OHOS_ARCH_LITE
    int DhcpOfferResultSuccess(struct DhcpIpResult &ipResult);
#endif
    int DhcpIpv4ResultFail(struct DhcpIpResult &ipResult);
    int DhcpIpv4ResultTimeOut(const std::string &ifname);
    int DhcpIpv4ResultExpired(const std::string &ifname);
    int DhcpIpv6ResultTimeOut(const std::string &ifname);
    int DhcpFreeIpv6(const std::string ifname);
    void DhcpIpv6ResulCallback(const std::string ifname, DhcpIpv6Info &info);
    void PushDhcpResult(const std::string &ifname, OHOS::DHCP::DhcpResult &result);
    bool CheckDhcpResultExist(const std::string &ifname, OHOS::DHCP::DhcpResult &result);
public:
    // manager multi-instance
    std::mutex m_clientServiceMutex;
    std::map<std::string, DhcpClient> m_mapClientService;

    // ip result info
    std::mutex m_dhcpResultMutex;
    std::map<std::string, std::vector<DhcpResult>> m_mapDhcpResult;

    // client call back
    std::mutex m_clientCallBackMutex;
#ifdef OHOS_ARCH_LITE
    std::map<std::string, std::shared_ptr<IDhcpClientCallBack>> m_mapClientCallBack;
#else
    std::map<std::string, sptr<IDhcpClientCallBack>> m_mapClientCallBack;
#endif
private:
    bool Init();
    bool IsGlobalIPv6Address(std::string ipAddress);
    bool mPublishFlag;
    static std::mutex g_instanceLock;
    ClientServiceRunningState mState;
#ifdef OHOS_ARCH_LITE
    static std::shared_ptr<DhcpClientServiceImpl> g_instance;
#else
    static sptr<DhcpClientServiceImpl> g_instance;
#endif
   std::string m_bssid;
};
}  // namespace DHCP
}  // namespace OHOS
#endif