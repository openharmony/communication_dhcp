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
#ifndef OHOS_I_DHCP_CLIENT_CALLBACK_H
#define OHOS_I_DHCP_CLIENT_CALLBACK_H

#include <string>
#ifndef OHOS_ARCH_LITE
#include <iremote_broker.h>
#include "message_parcel.h"
#include "message_option.h"
#endif
#include "inner_api/include/dhcp_define.h"

namespace OHOS {
namespace DHCP {
#ifdef OHOS_ARCH_LITE
class IDhcpClientCallBack {
#else
class IDhcpClientCallBack : public IRemoteBroker {
#endif
public:
    virtual ~IDhcpClientCallBack() {}
    virtual void OnIpSuccessChanged(int status, const std::string& ifname, DhcpResult& result) = 0;
    virtual void OnIpFailChanged(int status, const std::string& ifname, const std::string& reason) = 0;

#ifndef OHOS_ARCH_LITE
    virtual void OnDhcpOfferReport(int status, const std::string& ifname, DhcpResult& result) = 0;
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.wifi.IDhcpClientCallBack");
#endif
};
}  // namespace DHCP
}  // namespace OHOS
#endif