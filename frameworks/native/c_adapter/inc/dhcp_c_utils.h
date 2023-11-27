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
#ifndef DHCP_C_UTILS_H
#define DHCP_C_UTILS_H

#include <string>
#include <vector>
#include "../../../interfaces/kits/c/dhcp_error_code.h"
#include "dhcp_errcode.h"
#include "dhcp_logger.h"

namespace OHOS {
namespace Wifi {
#ifndef NO_SANITIZE
#ifdef __has_attribute
#if __has_attribute(no_sanitize)
#define NO_SANITIZE(type) __attribute__((no_sanitize(type)))
#endif
#endif
#endif

#ifndef NO_SANITIZE
#define NO_SANITIZE(type)
#endif

#ifndef CHECK_PTR_RETURN
#define CHECK_PTR_RETURN(ptr, retValue)             \
    if ((ptr) == nullptr) {                         \
        DHCP_LOGE("Error: the ptr is null!");       \
        return retValue;                            \
    }
#endif

#ifndef CHECK_PTR_RETURN_VOID
#define CHECK_PTR_RETURN_VOID(ptr)                  \
    if ((ptr) == nullptr) {                         \
        DHCP_LOGE("Error: the ptr is null!");       \
        return;                                     \
    }
#endif

DhcpErrorCode GetCErrorCode(ErrCode errCode);
int GetCallingPid();
int GetCallingUid();
int GetCallingTokenId();
}  // namespace Wifi
}  // namespace OHOS
#endif
