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
#include "dhcp_client_service_impl.h"
#include "../../../interfaces/kits/c/dhcp_start_sa_api.h"
#include "../../../frameworks/native/c_adapter/inc/dhcp_c_utils.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpStartClientSa");
#ifndef OHOS_ARCH_LITE
OHOS::sptr<OHOS::Wifi::DhcpClientServiceImpl> g_instance = OHOS::Wifi::DhcpClientServiceImpl::GetInstance();
#endif
NO_SANITIZE("cfi") DhcpErrorCode StartDhcpClientSa()
{
#ifndef OHOS_ARCH_LITE
    if (g_instance == nullptr) {
        DHCP_LOGE("StartDhcpClientSa g_instance is null!");
        return DHCP_INVALID_PARAM;
    }
    g_instance->StartServiceAbility(0);
#endif
    DHCP_LOGI("DhcpServer StartDhcpClientSa StartServiceAbility ok");
    return DHCP_SUCCESS;
}
