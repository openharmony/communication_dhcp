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
#ifndef OHOS_DHCP_ERRCODE_H
#define OHOS_DHCP_ERRCODE_H

namespace OHOS {
namespace DHCP {
enum ErrCode {
    DHCP_E_SUCCESS = 0,           /* successfully */
    DHCP_E_FAILED,                /* failed */
    DHCP_E_INVALID_PARAM,         /* invalid params */
    DHCP_E_NON_SYSTEMAPP,         /* not system app denied */
    DHCP_E_PERMISSION_DENIED,     /* permission denied */
    DHCP_E_INVALID_CONFIG,        /* invalid config */
    DHCP_E_UNKNOWN
};
}  // namespace DHCP
}  // namespace OHOS
#endif