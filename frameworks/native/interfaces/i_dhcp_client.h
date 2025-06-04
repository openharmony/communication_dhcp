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
#ifndef OHOS_I_DHCP_CLIENT_H
#define OHOS_I_DHCP_CLIENT_H

#include <string>
#ifndef OHOS_ARCH_LITE
#include "iremote_broker.h"
#include "message_parcel.h"
#include "message_option.h"
#endif
#include "i_dhcp_client_callback.h"
#include "inner_api/include/dhcp_define.h"
#include "dhcp_errcode.h"

namespace OHOS {
namespace DHCP {
#ifdef OHOS_ARCH_LITE
class IDhcpClient {
#else
class IDhcpClient : public IRemoteBroker {
#endif
public:
    virtual ~IDhcpClient() {}  
#ifdef OHOS_ARCH_LITE
    virtual ErrCode RegisterDhcpClientCallBack(const std::string& ifname,
        const std::shared_ptr<IDhcpClientCallBack> &callback) = 0;
#else
    virtual ErrCode RegisterDhcpClientCallBack(const std::string& ifname,
        const sptr<IDhcpClientCallBack> &callback) = 0;
#endif
    virtual ErrCode StartDhcpClient(const RouterConfig &config) = 0;
    virtual ErrCode DealWifiDhcpCache(int32_t cmd, const IpCacheInfo &ipCacheInfo) = 0;
    virtual ErrCode StopDhcpClient(const std::string& ifname, bool bIpv6, bool bIpv4 = true) = 0;
    virtual ErrCode StopClientSa(void) = 0;
    virtual bool IsRemoteDied() = 0;
#ifndef OHOS_ARCH_LITE
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.wifi.IDhcpClient");
#endif
};
}  // namespace DHCP
}  // namespace OHOS
#endif