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
#include "mock_dhcp_permission_utils.h"
#include "dhcp_logger.h"
 
DEFINE_DHCPLOG_DHCP_LABEL("MockDhcpPermissionUtils");
namespace DHCP {
namespace Wifi {
DhcpPermissionUtils &DhcpPermissionUtils::GetInstance()
{
    static DhcpPermissionUtils gPermissionUtils;
    return gPermissionUtils;
}
 
bool DhcpPermissionUtils::VerifyIsNativeProcess()
{
    DHCP_LOGI("VerifyDhcpNetworkPermission mock permission granted!");
    return true;
}
 
bool DhcpPermissionUtils::VerifyDhcpNetworkPermission(const std::string &permissionName)
{
    DHCP_LOGI("VerifyDhcpNetworkPermission mock permission granted! name:%{public}s", permissionName.c_str());
    return true;
}
} // namespace DHCP
} // namespace OHOS