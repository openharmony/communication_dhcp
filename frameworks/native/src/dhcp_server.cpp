/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "dhcp_server_impl.h"
#include "dhcp_c_utils.h"
#include "../../../interfaces/inner_api/dhcp_server.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpServer");

namespace OHOS {
namespace Wifi {
NO_SANITIZE("cfi") std::shared_ptr<DhcpServer> DhcpServer::GetInstance(int systemAbilityId)
{
    std::shared_ptr<DhcpServerImpl> pImpl = DelayedSingleton<DhcpServerImpl>::GetInstance();
    if (pImpl && pImpl->Init(systemAbilityId)) {
        DHCP_LOGI("init successfully!");
        return pImpl;
    }
    DHCP_LOGI("new dhcp server failed");
    return nullptr;
}

NO_SANITIZE("cfi") DhcpServer::~DhcpServer()
{
    DelayedSingleton<DhcpServerImpl>::DestroyInstance();
}
}  // namespace Wifi
}  // namespace OHOS