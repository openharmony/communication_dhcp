test/fuzztest/fuzz_common_func/mock_dhcp_permission_utils.h
310
0 → 100644
/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_MOCK_DHCP_PERMISSION_UTILS_H
#define OHOS_MOCK_DHCP_PERMISSION_UTILS_H
 
#include <string>
 
namespace DHCP {
namespace Wifi {
class DhcpPermissionUtils {
public:
    static DhcpPermissionUtils &GetInstance();
    static bool VerifyIsNativeProcess();
    static bool VerifyDhcpNetworkPermission(const std::string &permissionName);
    bool VerifyPermission(const std::string &permissionName, const int &pid, const int &uid, const int &tokenId);
};
} // namespace DHCP
} // namespace OHOS
#endif