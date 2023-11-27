/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef OHOS_DHCP_ERROR_CODE_C_H
#define OHOS_DHCP_ERROR_CODE_C_H

typedef enum {
    DHCP_SUCCESS = 0,              /* successfully */
    DHCP_FAILED  = -1,             /* failed */
    DHCP_INVALID_PARAM = -2,       /* invalid params   */
    DHCP_NON_SYSTEMAPP = -3,       /* not system app denied */
    DHCP_PERMISSION_DENIED = -4,   /* permission denied */
    DHCP_INVALID_CONFIG = -5,      /* invalid config */
    DHCP_UNKNOWN_ERROR
} DhcpErrorCode;
#endif