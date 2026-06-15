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

#include "dhcp_v6_callback_impl.h"
#include "dhcp_client_service_impl.h"

namespace OHOS {
namespace DHCP {

void DhcpV6CallbackImpl::OnDhcpV6Success(const DhcpV6Result& result)
{
    if (service_ == nullptr) {
        return;
    }
    service_->DhcpV6ResultCallback(ifname_, result, stateless_);
}

void DhcpV6CallbackImpl::OnDhcpV6Failed(int errorCode)
{
    if (service_ == nullptr) {
        return;
    }
    service_->DhcpV6FailCallback(ifname_, errorCode, stateless_);
}

void DhcpV6CallbackImpl::OnDhcpV6Expired()
{
    if (service_ == nullptr) {
        return;
    }
    service_->DhcpV6ExpiredCallback(ifname_, stateless_);
}

void DhcpV6CallbackImpl::OnDhcpV6Stop()
{
    if (service_ == nullptr) {
        return;
    }
    service_->DhcpV6StopCallback(ifname_, stateless_);
}

} // namespace DHCP
} // namespace OHOS
