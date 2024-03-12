/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "dhcp_c_utils.h"
#include <map>
#include "ipc_skeleton.h"
#include "../../../interfaces/kits/c/dhcp_error_code.h"

namespace OHOS {
namespace DHCP {

static std::map<ErrCode, DhcpErrorCode> g_ErrCodeMap = {
    {DHCP_E_SUCCESS, DHCP_SUCCESS},
    {DHCP_E_FAILED, DHCP_FAILED},
    {DHCP_E_INVALID_PARAM, DHCP_INVALID_PARAM},
    {DHCP_E_NON_SYSTEMAPP, DHCP_NON_SYSTEMAPP},
    {DHCP_E_PERMISSION_DENIED, DHCP_PERMISSION_DENIED},
    {DHCP_E_INVALID_CONFIG, DHCP_INVALID_CONFIG},
    {DHCP_E_UNKNOWN, DHCP_UNKNOWN_ERROR}
};

DhcpErrorCode GetCErrorCode(ErrCode errCode)
{
    std::map<ErrCode, DhcpErrorCode>::const_iterator iter = g_ErrCodeMap.find(errCode);
    return iter == g_ErrCodeMap.end() ? DHCP_UNKNOWN_ERROR : iter->second;
}

int GetCallingPid()
{
#ifndef OHOS_ARCH_LITE
    return IPCSkeleton::GetCallingPid();
#else
    return 0;
#endif
}

int GetCallingUid()
{
#ifndef OHOS_ARCH_LITE
    return IPCSkeleton::GetCallingUid();
#else
    return 0;
#endif
}

int GetCallingTokenId()
{
#ifndef OHOS_ARCH_LITE
    return IPCSkeleton::GetCallingTokenID();
#else
    return 0;
#endif
}

}  // namespace DHCP
}  // namespace OHOS