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
#ifndef OHOS_DHCP_CLIENT_PROXY_H
#define OHOS_DHCP_CLIENT_PROXY_H

#ifdef OHOS_ARCH_LITE
#include "iproxy_client.h"
#include "serializer.h"
#else
#include "iremote_proxy.h"
#endif
#include <string>
#include "i_dhcp_client.h"
#include "i_dhcp_client_callback.h"
#include "inner_api/dhcp_client.h"

namespace OHOS {
namespace DHCP {
#ifdef OHOS_ARCH_LITE
class DhcpClientProxy : public IDhcpClient {
public:
    static DhcpClientProxy *GetInstance(void);
    static void ReleaseInstance(void);
    explicit DhcpClientProxy();
#else
class DhcpClientProxy : public IRemoteProxy<IDhcpClient> {
public:
    explicit DhcpClientProxy(const sptr<IRemoteObject> &impl);
#endif
    ~DhcpClientProxy();

#ifdef OHOS_ARCH_LITE
    ErrCode RegisterDhcpClientCallBack(const std::string& ifname,
        const std::shared_ptr<IDhcpClientCallBack> &callback) override;
#else
    ErrCode RegisterDhcpClientCallBack(const std::string& ifname, const sptr<IDhcpClientCallBack> &callback) override;
#endif
    ErrCode StartDhcpClient(const std::string& ifname, bool bIpv6) override;
    ErrCode StopDhcpClient(const std::string& ifname, bool bIpv6) override;
    ErrCode RenewDhcpClient(const std::string& ifname) override;
    bool IsRemoteDied() override;
#ifdef OHOS_ARCH_LITE
    void OnRemoteDied(void);
private:
    static DhcpClientProxy *g_instance;
    IClientProxy *remote_ = nullptr;
    SvcIdentity svcIdentity_ = { 0 };
    bool remoteDied_;
#else
private:
    class DhcpClientDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit DhcpClientDeathRecipient(DhcpClientProxy &client) : client_(client) {}
        ~DhcpClientDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override
        {
            client_.OnRemoteDied(remote);
        }

    private:
        DhcpClientProxy &client_;
    };
    void OnRemoteDied(const wptr<IRemoteObject> &remoteObject);
    void RemoveDeathRecipient(void);
    
    static inline BrokerDelegator<DhcpClientProxy> delegator_;
    sptr<IRemoteObject> remote_ = nullptr;
    bool mRemoteDied;
    std::mutex mutex_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ = nullptr;
#endif
};
}  // namespace DHCP
}  // namespace OHOS
#endif
