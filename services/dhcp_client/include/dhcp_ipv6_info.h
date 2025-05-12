/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DHCP_IPV6_INFO_H
#define OHOS_DHCP_IPV6_INFO_H

#include <string>
#include <vector>
#include <map>
#include "securec.h"
namespace OHOS {
namespace DHCP {
inline const int DHCP_INET6_ADDRSTRLEN = 128;
inline const int DNS_DEFAULT_LIFETIME = 3600; // default lifetime for DNS server
enum AddrType {
    UNKNOW = -1,
    DEFAULT = 0,
    GLOBAL,
    SUBNET,
    RAND,
    UNIQUE,
    UNIQUE2
};
struct DhcpIpv6Info {
    char linkIpv6Addr[DHCP_INET6_ADDRSTRLEN];
    char globalIpv6Addr[DHCP_INET6_ADDRSTRLEN];
    char ipv6SubnetAddr[DHCP_INET6_ADDRSTRLEN];
    char randIpv6Addr[DHCP_INET6_ADDRSTRLEN];
    char routeAddr[DHCP_INET6_ADDRSTRLEN];
    char dnsAddr[DHCP_INET6_ADDRSTRLEN];
    char dnsAddr2[DHCP_INET6_ADDRSTRLEN];
    char uniqueLocalAddr1[DHCP_INET6_ADDRSTRLEN];
    char uniqueLocalAddr2[DHCP_INET6_ADDRSTRLEN];
    unsigned int status;   // 1 ipv4 getted, 2 dns getted, 3 ipv4 and dns getted
    std::vector<std::string> vectorDnsAddr;
    uint64_t lifetime {DNS_DEFAULT_LIFETIME}; // min life time of valid lifetime & preferred lifetime
    std::vector<std::string> defaultRouteAddr {};
    std::map<std::string, int> IpAddrMap {};
    void Clear()
    {
        memset_s(linkIpv6Addr, DHCP_INET6_ADDRSTRLEN, 0, DHCP_INET6_ADDRSTRLEN);
        memset_s(globalIpv6Addr, DHCP_INET6_ADDRSTRLEN, 0, DHCP_INET6_ADDRSTRLEN);
        memset_s(ipv6SubnetAddr, DHCP_INET6_ADDRSTRLEN, 0, DHCP_INET6_ADDRSTRLEN);
        memset_s(randIpv6Addr, DHCP_INET6_ADDRSTRLEN, 0, DHCP_INET6_ADDRSTRLEN);
        memset_s(routeAddr, DHCP_INET6_ADDRSTRLEN, 0, DHCP_INET6_ADDRSTRLEN);
        memset_s(dnsAddr, DHCP_INET6_ADDRSTRLEN, 0, DHCP_INET6_ADDRSTRLEN);
        memset_s(dnsAddr2, DHCP_INET6_ADDRSTRLEN, 0, DHCP_INET6_ADDRSTRLEN);
        memset_s(uniqueLocalAddr1, DHCP_INET6_ADDRSTRLEN, 0, DHCP_INET6_ADDRSTRLEN);
        memset_s(uniqueLocalAddr2, DHCP_INET6_ADDRSTRLEN, 0, DHCP_INET6_ADDRSTRLEN);
        status = 0;
        vectorDnsAddr.clear();
        lifetime = DNS_DEFAULT_LIFETIME;
        defaultRouteAddr.clear();
        IpAddrMap.clear();
    }
};

struct DnsServerEntry {
    std::string address;  // dns server
    uint64_t expiry;      // expiry time (ms)
};
class DhcpIpv6InfoManager {
public:
    static bool AddRoute(DhcpIpv6Info &dhcpIpv6Info, std::string defaultRoute);
    static bool RemoveRoute(DhcpIpv6Info &dhcpIpv6Info, std::string defaultRoute);
    static bool UpdateAddr(DhcpIpv6Info &dhcpIpv6Info, std::string addr, AddrType type);
    static bool RemoveAddr(DhcpIpv6Info &dhcpIpv6Info, std::string addr);
};
}  // namespace DHCP
}  // namespace OHOS
#endif /* OHOS_DHCP_IPV6_DEFINE_H */
