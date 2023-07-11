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
#ifndef OHOS_IP6_H
#define OHOS_IP6_H

#ifdef __cplusplus
extern "C" {
#endif

#define DHCP_INET6_ADDRSTRLEN 128

typedef void (*onIpv6AddressEvent)(void* data);

struct DhcpIPV6Info {
    char linkIpv6Addr[DHCP_INET6_ADDRSTRLEN];
    char globalIpv6Addr[DHCP_INET6_ADDRSTRLEN];
    char ipv6MaskAddr[DHCP_INET6_ADDRSTRLEN];
    char randIpv6Addr[DHCP_INET6_ADDRSTRLEN];
};

void *DhcpIPV6Start(void* param);

void DhcpIPV6Stop(void);

int StartIpv6(const char *ifname);

#ifdef __cplusplus
}
#endif
#endif
