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
#ifndef OHOS_DHCP_SERVER_CALLBACK_PROXY_H
#define OHOS_DHCP_SERVER_CALLBACK_PROXY_H

#include "i_dhcp_server_callback.h"
#ifdef OHOS_ARCH_LITE
#include "serializer.h"
#else
#include "iremote_proxy.h"
#endif

namespace OHOS {
namespace Wifi {

#ifdef OHOS_ARCH_LITE
class DhcpServerCallbackProxy : public IDhcpServerCallBack {
public:
    explicit DhcpServerCallbackProxy(SvcIdentity *sid);
#else
class DhcpServerCallbackProxy : public IRemoteProxy<IDhcpServerCallBack> {
public:
    explicit DhcpServerCallbackProxy(const sptr<IRemoteObject> &impl);
#endif
    virtual ~DhcpServerCallbackProxy();

    void OnServerStatusChanged(int status) override;
    void OnServerLeasesChanged(const std::string& ifname, std::vector<std::string>& leases) override;
    void OnServerSerExitChanged(const std::string& ifname) override;

private:
#ifdef OHOS_ARCH_LITE
    SvcIdentity sid_;
    static const int DEFAULT_IPC_SIZE = 256;
#else
    static inline BrokerDelegator<DhcpServerCallbackProxy> g_delegator;
#endif
};
}  // namespace Wifi
}  // namespace OHOS
#endif