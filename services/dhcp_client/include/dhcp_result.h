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
int GetDhcpEventIpv4Result(const int code, const std::vector<std::string> &splits);
int DhcpEventResultHandle(const int code, const std::string &data);
bool PublishDhcpIpv4ResultEvent(const int code, const char *data, const char *ifname);
bool SplitStr(const std::string src, const std::string delim, const int count, std::vector<std::string> &splits);
bool DhcpIpv6TimerCallbackEvent(const char *ifname);
#ifdef __cplusplus
}
#endif
#endif
