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
#ifndef OHOS_DHCP_SERVER_IMPL_H
#define OHOS_DHCP_SERVER_IMPL_H

#include <string>
#include "singleton.h"
#include "i_dhcp_server.h"
#include "i_dhcp_server_callback.h"
#include "inner_api/include/dhcp_define.h"
#include "inner_api/dhcp_server.h"

namespace OHOS {
namespace DHCP {
class DhcpServerImpl : public DhcpServer {
    DECLARE_DELAYED_SINGLETON(DhcpServerImpl);
public:
    bool Init(int systemAbilityId);
    bool IsRemoteDied();
#ifdef OHOS_ARCH_LITE
    ErrCode RegisterDhcpServerCallBack(const std::string& ifname,
        const std::shared_ptr<IDhcpServerCallBack> &callback) override;
#else
    ErrCode RegisterDhcpServerCallBack(const std::string& ifname,
        const sptr<IDhcpServerCallBack> &callback) override;
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
    ErrCode StopServerSa(void) override;
private:
    bool GetDhcpServerProxy();
    int systemAbilityId_;
    std::mutex mutex_;
#ifdef OHOS_ARCH_LITE
    std::shared_ptr<IDhcpServer> client_;
#else
    sptr<IDhcpServer> client_;
#endif
};
}  // namespace DHCP
}  // namespace OHOS
#endif
