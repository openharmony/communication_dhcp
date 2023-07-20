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

#include <string>
#include <sys/types.h>
#include <stdint.h>

namespace OHOS {
namespace Wifi {
const int DHCP_INET6_ADDRSTRLEN = 128;

struct DhcpIpv6Info {
    char linkIpv6Addr[DHCP_INET6_ADDRSTRLEN];
    char globalIpv6Addr[DHCP_INET6_ADDRSTRLEN];
    char ipv6SubnetAddr[DHCP_INET6_ADDRSTRLEN];
    char randIpv6Addr[DHCP_INET6_ADDRSTRLEN];
    char routeAddr[DHCP_INET6_ADDRSTRLEN];
    char dnsAddr[DHCP_INET6_ADDRSTRLEN];
    char dnsAddr2[DHCP_INET6_ADDRSTRLEN];
    int status;   // 1 ipv4 getted, 2 dns getted, 3 ipv4 and dns getted
};

class DhcpIpv6Client {
public:
    DhcpIpv6Client()
    {
        interfaceName = "";
    }
    void *DhcpIpv6Start(const char* param);
    void DhcpIPV6Stop(void);
    int StartIpv6(const char *ifname);
    bool IsRunning()
    {
        return runFlag;
    }
    void SetCallback(std::function<void(const std::string ifname, DhcpIpv6Info &info)> callback)
    {
        onIpv6AddressChanged = callback;
    }
    void Reset();
private:
    int32_t createKernelSocket(void);
    const char* getRouteFromIPV6Addr(const u_char *src, char* route, size_t size);
    void GetIpv6Prefix(const char* ipv6Addr, char* ipv6PrefixBuf, uint8_t prefixLen);
    int getAddrScope(const struct in6_addr *addr);
    int getAddrType(const struct in6_addr *addr);
    unsigned int ipv6AddrScope2Type(unsigned int scope);
    void onIpv6DnsAddEvent(void* data, int len, int ifaIndex);
    void onIpv6AddressAddEvent(void* data, int prefixLen, int ifaIndex);
    void setSocketFilter(void* addr);
    void handleKernelEvent(const uint8_t* data, int len);
    void parseNdUserOptMessage(void* msg, int len);

    std::function<void(const std::string ifname, DhcpIpv6Info &info)> onIpv6AddressChanged;
    std::string interfaceName;
    bool runFlag = false;
    struct DhcpIpv6Info dhcpIpv6Info;
};
}  // namespace Wifi
}  // namespace OHOS

#endif