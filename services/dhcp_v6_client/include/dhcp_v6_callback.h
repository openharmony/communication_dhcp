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

#ifndef DHCP_V6_CALLBACK_H
#define DHCP_V6_CALLBACK_H

#include "dhcp_v6_result.h"

namespace OHOS {
namespace DHCP {

class IDhcpV6Callback {
public:
    virtual ~IDhcpV6Callback() = default;
    virtual void OnDhcpV6Success(const DhcpV6Result& result) = 0;
    virtual void OnDhcpV6Failed(int errorCode) = 0;
    virtual void OnDhcpV6Expired() = 0;
    virtual void OnDhcpV6Stop() = 0;
};

} // namespace DHCP
} // namespace OHOS

#endif // DHCP_V6_CALLBACK_H
