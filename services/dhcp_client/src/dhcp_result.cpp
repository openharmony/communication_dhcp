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

#include <string>
#include <map>
#include <list>
#include <thread>
#include <mutex>
#include "securec.h"

#include "dhcp_client_service_impl.h"
#include "dhcp_logger.h"
#include "inner_api/include/dhcp_define.h"
#include "dhcp_result.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpResult");

bool PublishDhcpIpv4Result(struct DhcpIpResult &ipResult)
{
#ifndef OHOS_ARCH_LITE
    OHOS::sptr<OHOS::DHCP::DhcpClientServiceImpl> clientImpl = OHOS::DHCP::DhcpClientServiceImpl::GetInstance();
#else
    std::shared_ptr<OHOS::DHCP::DhcpClientServiceImpl> clientImpl = OHOS::DHCP::DhcpClientServiceImpl::GetInstance();
#endif
    if (clientImpl == nullptr) {
        DHCP_LOGE("PublishDhcpIpv4Result clientImpl is nullptr!");
        return false;
    }
    DHCP_LOGI("PublishDhcpIpv4Result code:%{public}d ifname:%{public}s", ipResult.code, ipResult.ifname.c_str());
    if (ipResult.code == PUBLISH_CODE_SUCCESS) {
        if (clientImpl->DhcpIpv4ResultSuccess(ipResult) != OHOS::DHCP::DHCP_OPT_SUCCESS) {
            DHCP_LOGE("PublishDhcpIpv4Result DhcpIpv4ResultSuccess failed!");
            return false;
        }
    } else if (ipResult.code == PUBLISH_CODE_TIMEOUT) {
        if (clientImpl->DhcpIpv4ResultTimeOut(ipResult.ifname) != OHOS::DHCP::DHCP_OPT_SUCCESS) {
            DHCP_LOGE("PublishDhcpIpv4Result DhcpIpv4ResultTimeOut failed!");
            return false;
        }
    } else { // PUBLISH_CODE_FAILED
        if (clientImpl->DhcpIpv4ResultFail(ipResult) != OHOS::DHCP::DHCP_OPT_SUCCESS) {
            DHCP_LOGE("PublishDhcpIpv4Result DhcpIpv4ResultFail failed!");
            return false;
        }
    }
    return true;
}

bool DhcpIpv6TimerCallbackEvent(const char *ifname)
{
    DHCP_LOGI("DhcpIpv6TimerCallbackEvent ifname:%{public}s", ifname);
    if (ifname == nullptr) {
        DHCP_LOGE("DhcpIpv6TimerCallbackEvent ifname is nullptr!");
        return false;
    }
#ifndef OHOS_ARCH_LITE
    OHOS::sptr<OHOS::DHCP::DhcpClientServiceImpl> clientImpl = OHOS::DHCP::DhcpClientServiceImpl::GetInstance();
#else
    std::shared_ptr<OHOS::DHCP::DhcpClientServiceImpl> clientImpl = OHOS::DHCP::DhcpClientServiceImpl::GetInstance();
#endif
    if ((clientImpl != nullptr) && (clientImpl->DhcpIpv6ResultTimeOut(ifname) != OHOS::DHCP::DHCP_OPT_SUCCESS)) {
        DHCP_LOGE("DhcpIpv6TimerCallbackEvent DhcpIpv6ResultTimeOut failed!");
        return false;
    }
    return true;
}