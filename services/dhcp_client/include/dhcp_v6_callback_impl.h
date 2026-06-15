/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_DHCP_V6_CALLBACK_IMPL_H
#define OHOS_DHCP_V6_CALLBACK_IMPL_H

#include "dhcp_v6_callback.h"

namespace OHOS {
namespace DHCP {

class DhcpClientServiceImpl;

class DhcpV6CallbackImpl : public IDhcpV6Callback {
public:
    DhcpV6CallbackImpl(DhcpClientServiceImpl *service, std::string ifname, bool stateless)
        : service_(service), ifname_(std::move(ifname)), stateless_(stateless) {}

    void SetStateless(bool stateless) { stateless_ = stateless; }

    void OnDhcpV6Success(const DhcpV6Result& result) override;
    void OnDhcpV6Failed(int errorCode) override;
    void OnDhcpV6Expired() override;
    void OnDhcpV6Stop() override;

private:
    DhcpClientServiceImpl *service_;
    std::string ifname_;
    bool stateless_ {false};
};

} // namespace DHCP
} // namespace OHOS

#endif // OHOS_DHCP_V6_CALLBACK_IMPL_H
