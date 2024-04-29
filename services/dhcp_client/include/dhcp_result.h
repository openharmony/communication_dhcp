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
#ifndef OHOS_DHCP_RESULT_H
#define OHOS_DHCP_RESULT_H

#include <string>
#include <vector>
#include "dhcp_client_def.h"

#ifdef __cplusplus
extern "C" {
#endif
bool PublishDhcpIpv4Result(struct DhcpIpResult &ipResult);
bool DhcpIpv6TimerCallbackEvent(const char *ifname);
#ifdef __cplusplus
}
#endif
#endif
