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
#ifndef OHOS_DHCP_IP6_H
#define OHOS_DHCP_IP6_H

#include <string>
#include <sys/types.h>
#include <stdint.h>
#ifndef OHOS_ARCH_LITE
#include "dhcp_client_def.h"
#include "common_timer_errors.h"
#include "timer.h"
#endif
#include "dhcp_thread.h"

namespace OHOS {
namespace DHCP {
const int DHCP_INET6_ADDRSTRLEN = 128;

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
};

class DhcpIpv6Client {
public:
    DhcpIpv6Client(std::string ifname);
    virtual ~DhcpIpv6Client();

    bool IsRunning();
    void SetCallback(std::function<void(const std::string ifname, DhcpIpv6Info &info)> callback);
    void *DhcpIpv6Start();
    void DhcpIPV6Stop(void);
    void Reset();
    void RunIpv6ThreadFunc();
    void AddIpv6Address(char *ipv6addr, int len);
    int StartIpv6();
    int StartIpv6Thread(const std::string &ifname, bool isIpv6);
#ifndef OHOS_ARCH_LITE
    void Ipv6TimerCallback();
    void StartIpv6Timer(void);
    void StopIpv6Timer(void);
#endif
public:
private:
    int32_t createKernelSocket(void);
    void GetIpv6Prefix(const char* ipv6Addr, char* ipv6PrefixBuf, uint8_t prefixLen);
    int GetIpFromS6Address(void* addr, int family, char* buf, int buflen);
    int getAddrScope(const struct in6_addr *addr);
    int getAddrType(const struct in6_addr *addr);
    unsigned int ipv6AddrScope2Type(unsigned int scope);
    void onIpv6DnsAddEvent(void* data, int len, int ifaIndex);
    void onIpv6RouteAddEvent(char* gateway, char* dst, int ifaIndex);
    void onIpv6AddressAddEvent(void* data, int prefixLen, int ifaIndex);
    void setSocketFilter(void* addr);
    void handleKernelEvent(const uint8_t* data, int len);
    void parseNdUserOptMessage(void* msg, int len);
    void parseNDRouteMessage(void* msg);
    void parseNewneighMessage(void* msg);
    void getIpv6RouteAddr();
    void fillRouteData(char* buff, int &len);
    bool IsEui64ModeIpv6Address(char *ipv6addr, int len);

    std::function<void(const std::string ifname, DhcpIpv6Info &info)> onIpv6AddressChanged;
    std::string interfaceName;
    struct DhcpIpv6Info dhcpIpv6Info;
    int32_t ipv6SocketFd = 0;
    std::unique_ptr<DhcpThread> ipv6Thread_ = nullptr;
    bool runFlag;
#ifndef OHOS_ARCH_LITE
    uint32_t ipv6TimerId;
    std::mutex ipv6TimerMutex;
#endif
};
}  // namespace DHCP
}  // namespace OHOS

#endif