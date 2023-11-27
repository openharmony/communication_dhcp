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
#ifndef OHOS_I_DHCP_SERVICE_H
#define OHOS_I_DHCP_SERVICE_H

#include <string>
#ifndef OHOS_ARCH_LITE
#include "iremote_broker.h"
#include "message_parcel.h"
#include "message_option.h"
#endif
#include "i_dhcp_server_callback.h"
#include "../../../interfaces/inner_api/include/dhcp_define.h"
#include "dhcp_errcode.h"

namespace OHOS {
namespace Wifi {
#ifdef OHOS_ARCH_LITE
class IDhcpServer {
#else
class IDhcpServer : public IRemoteBroker {
#endif
public:
    virtual ~IDhcpServer() {}
#ifdef OHOS_ARCH_LITE
    virtual ErrCode RegisterDhcpServerCallBack(const std::string& ifname,
        const std::shared_ptr<IDhcpServerCallBack> &callback) = 0;
#else
    virtual ErrCode RegisterDhcpServerCallBack(const std::string& ifname,
        const sptr<IDhcpServerCallBack> &callback) = 0;
#endif
    virtual ErrCode StartDhcpServer(const std::string& ifname) = 0;
    virtual ErrCode StopDhcpServer(const std::string& ifname) = 0;
    virtual ErrCode PutDhcpRange(const std::string& tagName, const DhcpRange& range) = 0;
    virtual ErrCode RemoveDhcpRange(const std::string& tagName, const DhcpRange& range) = 0;
    virtual ErrCode RemoveAllDhcpRange(const std::string& tagName) = 0;
    virtual ErrCode SetDhcpRange(const std::string& ifname, const DhcpRange& range) = 0;
    virtual ErrCode SetDhcpName(const std::string& ifname, const std::string& tagName) = 0;
    virtual ErrCode GetDhcpClientInfos(const std::string& ifname, std::vector<std::string>& dhcpClientInfo) = 0;
    virtual ErrCode UpdateLeasesTime(const std::string& leaseTime) = 0;
    virtual bool IsRemoteDied() = 0;
#ifndef OHOS_ARCH_LITE
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.wifi.IDhcpServer");
#endif
};
}  // namespace Wifi
}  // namespace OHOS
#endif