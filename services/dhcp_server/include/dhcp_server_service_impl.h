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

#ifndef OHOS_WIFI_P2P_SERVICE_IMPL_H
#define OHOS_WIFI_P2P_SERVICE_IMPL_H

#ifndef OHOS_ARCH_LITE
#include "system_ability.h"
#include "dhcp_server_stub.h"
#include "iremote_object.h"
#else
#include "dhcp_server_stub_lite.h"
#endif
#include <mutex>
#include <list>
#include <set>
#include <string>

namespace OHOS {
namespace Wifi {
constexpr int MAXRETRYTIMEOUT = 10;

enum ServerServiceRunningState { STATE_NOT_START, STATE_RUNNING };
class DhcpServerServiceImpl :
#ifndef OHOS_ARCH_LITE
public SystemAbility, 
#endif
public DhcpServerStub {
#ifndef OHOS_ARCH_LITE
    DECLARE_SYSTEM_ABILITY(DhcpServerServiceImpl);
#endif

public:
    DhcpServerServiceImpl();
    virtual ~DhcpServerServiceImpl();
#ifdef OHOS_ARCH_LITE
    static std::shared_ptr<DhcpServerServiceImpl> GetInstance();
    void OnStart();
    void OnStop();
#else
    static sptr<DhcpServerServiceImpl> GetInstance();
    void OnStart() override;
    void OnStop() override;
#endif
#ifdef OHOS_ARCH_LITE
    ErrCode RegisterDhcpServerCallBack(const std::string& ifname,
        const std::shared_ptr<IDhcpServerCallBack> &serverCallback) override;
#else
    ErrCode RegisterDhcpServerCallBack(const std::string& ifname,
        const sptr<IDhcpServerCallBack> &serverCallback) override;
#endif
    ErrCode StartDhcpServer(const std::string& ifname) override;
    ErrCode StopDhcpServer(const std::string& ifname) override;
    ErrCode PutDhcpRange(const std::string& tagName, const DhcpRange& range) override;
    ErrCode RemoveDhcpRange(const std::string& tagName, const DhcpRange& range) override;
    ErrCode RemoveAllDhcpRange(const std::string& tagName) override;
    ErrCode SetDhcpRange(const std::string& ifname, const DhcpRange& range) override;
    ErrCode SetDhcpName(const std::string& ifname, const std::string& tagName) override;
    ErrCode GetDhcpClientInfos(const std::string& ifname, std::vector<std::string>& leases) override;
    ErrCode UpdateLeasesTime(const std::string& leaseTime) override;
    bool IsRemoteDied(void) override;

#ifndef OHOS_ARCH_LITE
    void StartServiceAbility(int sleepS);
#endif

    /**
     * @Description : Fork child process function for start dhcp server process.
     *
     * @param ifname - interface name, eg:wlan0 [in]
     * @Return : success - DHCP_OPT_SUCCESS, failed - others.
     */
    int ForkExecProcess(const std::string ifname, const std::string ip, const std::string mask, const std::string pool);

    int DelSpecifiedInterface(const std::string& ifname);


private:
    bool Init();
    int CheckAndUpdateConf(const std::string& ifname);
    bool CheckIpAddrRange(const DhcpRange& range);
    int AddSpecifiedInterface(const std::string& ifname);
    int GetUsingIpRange(const std::string ifname, std::string& ipRange);
    int CreateDefaultConfigFile(const std::string strFile);
    int StopServer(const pid_t& serverPid);
    void UnregisterSignal() const;
    bool IsNativeProcess();

    bool mPublishFlag;
    static std::mutex g_instanceLock;
    ServerServiceRunningState mState;
    std::map<std::string, std::list<DhcpRange>> m_mapInfDhcpRange;  /* dhcp server using ip range */
    std::map<std::string, std::list<DhcpRange>> m_mapTagDhcpRange;  /* dhcp server can be used ip range */
    std::set<std::string> m_setInterfaces;                          /* the started specified interfaces */

    std::mutex m_serverCallBackMutex;
#ifdef OHOS_ARCH_LITE
    std::map<std::string, std::shared_ptr<IDhcpServerCallBack>> m_mapServerCallBack;
#else
    std::map<std::string, sptr<IDhcpServerCallBack>> m_mapServerCallBack;
#endif

private:
#ifdef OHOS_ARCH_LITE
    static std::shared_ptr<DhcpServerServiceImpl> g_instance;
#else
    static sptr<DhcpServerServiceImpl> g_instance;
#endif
    static std::map<std::string, DhcpServerInfo> m_mapDhcpServer;

};
}  // namespace Wifi
}  // namespace OHOS
#endif