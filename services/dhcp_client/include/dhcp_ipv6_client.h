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

#include <mutex>
#include <string>
#include <sys/types.h>
#include <stdint.h>
#include <thread>
#include "dhcp_ipv6_dns_repository.h"
namespace OHOS {
namespace DHCP {

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
    int StartIpv6();
    int StartIpv6Thread(const std::string &ifname, bool isIpv6);
public:
private:
    int32_t createKernelSocket(void);
    void GetIpv6Prefix(const char* ipv6Addr, char* ipv6PrefixBuf, uint8_t prefixLen);
    int GetIpFromS6Address(void* addr, int family, char* buf, int buflen);
    int GetAddrScope(void *addr);
    int GetAddrType(const struct in6_addr *addr);
    AddrType AddIpv6Address(char *ipv6addr, int len);
    unsigned int ipv6AddrScope2Type(unsigned int scope);
    void onIpv6DnsAddEvent(void* data, int len, int ifaIndex);
    void OnIpv6RouteUpdateEvent(char* gateway, char* dst, int ifaIndex, bool isAdd = true);
    void OnIpv6AddressUpdateEvent(char *addr, int addrlen, int prefixLen,
                                int ifaIndex, int scope, bool isUpdate);
    int SendRouterSolicitation();
    void setSocketFilter(void* addr);
    void handleKernelEvent(const uint8_t* data, int len);
    void parseNdUserOptMessage(void* msg, int len);
    void ParseAddrMessage(void *msg);
    void parseNDRouteMessage(void* msg);
    void parseNewneighMessage(void* msg);
    void getIpv6RouteAddr();
    void fillRouteData(char* buff, int &len);
    bool IsEui64ModeIpv6Address(const char *ipv6addr, int len, const unsigned char *ifaceMac, int macLen);
    void SetAcceptRa(const std::string &content);
    void PublishIpv6Result();
    bool IsGlobalIpv6Address(const char *ipv6addr, int len);
    bool IsUniqueLocalIpv6Address(const char *ipv6addr, int len);
    // Callback function mutex
    std::mutex ipv6CallbackMutex_;
    std::function<void(const std::string ifname, DhcpIpv6Info &info)> onIpv6AddressChanged_ { nullptr };
    // global variables
    std::mutex mutex_;
    std::string interfaceName;
    struct DhcpIpv6Info dhcpIpv6Info;
    int32_t ipv6SocketFd = 0;
    std::atomic<bool> runFlag_ { false };
    // IPv6 thread
    std::unique_ptr<std::thread> ipv6Thread_ = nullptr;
    // DNS repository
    std::unique_ptr<DnsServerRepository> dhcpIpv6DnsRepository_ = nullptr;
};
}  // namespace DHCP
}  // namespace OHOS

#endif