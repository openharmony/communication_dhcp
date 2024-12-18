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
#ifndef OHOS_DHCP_SERVER_PROXY_H
#define OHOS_DHCP_SERVER_PROXY_H

#include <string>
#ifdef OHOS_ARCH_LITE
#include "iproxy_client.h"
#else
#include "iremote_proxy.h"
#endif
#include "i_dhcp_server.h"
#include "i_dhcp_server_callback.h"
#include "inner_api/dhcp_server.h"

namespace OHOS {
namespace DHCP {
#ifdef OHOS_ARCH_LITE
class DhcpServerProxy : public IDhcpServer {
public:
    static DhcpServerProxy *GetInstance(void);
    static void ReleaseInstance(void);
    explicit DhcpServerProxy(void);
    ErrCode Init(void);
#else
class DhcpServerProxy : public IRemoteProxy<IDhcpServer> {
public:
    explicit DhcpServerProxy(const sptr<IRemoteObject> &impl);
#endif
    ~DhcpServerProxy();
#ifdef OHOS_ARCH_LITE
    ErrCode RegisterDhcpServerCallBack(const std::string& ifname,
        const std::shared_ptr<IDhcpServerCallBack> &callback) override;
#else
    ErrCode RegisterDhcpServerCallBack(const std::string& ifname, const sptr<IDhcpServerCallBack> &callback) override;
#endif
    ErrCode StartDhcpServer(const std::string& ifname) override;
    ErrCode StopDhcpServer(const std::string& ifname) override;
    ErrCode PutDhcpRange(const std::string& tagName, const DhcpRange& range) override;
    ErrCode RemoveDhcpRange(const std::string& tagName, const DhcpRange& range) override;
    ErrCode RemoveAllDhcpRange(const std::string& tagName) override;
    ErrCode SetDhcpRange(const std::string& ifname, const DhcpRange& range) override;
    ErrCode SetDhcpName(const std::string& ifname, const std::string& tagName) override;
    ErrCode GetDhcpClientInfos(const std::string& ifname, std::vector<std::string>& dhcpClientInfo) override;
    ErrCode UpdateLeasesTime(const std::string& leaseTime) override;
    bool IsRemoteDied() override;
    ErrCode StopServerSa(void) override;

#ifdef OHOS_ARCH_LITE
    void OnRemoteDied(void);
private:
    static DhcpServerProxy *g_instance;
    IClientProxy *remote_ = nullptr;
    SvcIdentity svcIdentity_ = { 0 };
    bool remoteDied_;
#else
private:
    class DhcpServerDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit DhcpServerDeathRecipient(DhcpServerProxy &client) : client_(client) {}
        ~DhcpServerDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override
        {
            client_.OnRemoteDied(remote);
        }

    private:
        DhcpServerProxy &client_;
    };
    void OnRemoteDied(const wptr<IRemoteObject> &remoteObject);
    void RemoveDeathRecipient(void);

    static inline BrokerDelegator<DhcpServerProxy> delegator_;
    sptr<IRemoteObject> remote_ = nullptr;
    bool mRemoteDied;
    std::mutex mutex_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ = nullptr;
#endif
};
}  // namespace DHCP
}  // namespace OHOS
#endif
