/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0ys/socket.h
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <signal.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <net/if.h>
#include <errno.h>
#include <thread>
#include "securec.h"
#include "dhcp_logger.h"
#include "dhcp_ipv6_client.h"
#include "dhcp_result.h"
#include "dhcp_thread.h"
#include "dhcp_function.h"

namespace OHOS {
namespace DHCP {
DEFINE_DHCPLOG_DHCP_LABEL("DhcpIpv6Client");

const char *DEFAULUT_BAK_DNS = "240e:4c:4008::1";
const char *DEFAULT_ROUTE = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
const char *DEFAULT_IPV6_ANY_INIT_ADDR = "::";
const int IPV6_ADDR_ANY = 0x0000U;
const int IPV6_ADDR_UNICAST = 0x0001U;
const int IPV6_ADDR_MULTICAST = 0x0002U;
const int IPV6_ADDR_SCOPE_MASK = 0x00F0U;
const int IPV6_ADDR_LOOPBACK = 0x0010U;
const int IPV6_ADDR_LINKLOCAL = 0x0020U;
const int IPV6_ADDR_SITELOCAL = 0x0040U;
const int IPV6_ADDR_COMPATV4 = 0x0080U;
const int IPV6_ADDR_MAPPED = 0x1000U;
const unsigned int IPV6_ADDR_SCOPE_NODELOCAL = 0X01;
const unsigned int  IPV6_ADDR_SCOPE_LINKLOCAL = 0X02;
const unsigned int  IPV6_ADDR_SCOPE_SITELOCAL = 0X05;
const int  IPV6_ADDR_SCOPE_GLOBAL = 0X0E;
const int S6_ADDR_INDEX_ZERO = 0;
const int S6_ADDR_INDEX_FIRST = 1;
const int S6_ADDR_INDEX_SECOND = 2;
const int S6_ADDR_INDEX_THIRD = 3;
const int ADDRTYPE_FLAG_ZERO = 0x00000000;
const int ADDRTYPE_FLAG_ONE = 0x00000001;
const int ADDRTYPE_FLAG_LOWF = 0x0000ffff;
const int ADDRTYPE_FLAG_HIGHE = 0xE0000000;
const int ADDRTYPE_FLAG_HIGHFF = 0xFF000000;
const int ADDRTYPE_FLAG_HIGHFFC = 0xFFC00000;
const int ADDRTYPE_FLAG_HIGHFE8 = 0xFE800000;
const int ADDRTYPE_FLAG_HIGHFEC = 0xFEC00000;
const int ADDRTYPE_FLAG_HIGHFE = 0xFE000000;
const int ADDRTYPE_FLAG_HIGHFC = 0xFC000000;
const int MASK_FILTER = 0x7;
const int KERNEL_BUFF_SIZE = (8 * 1024);
const int ND_OPT_MIN_LEN = 3;
const int ROUTE_BUFF_SIZE = 1024;
const int IPV6_TIMEOUT_USEC = 500000;
const int POSITION_OFFSET_1 = 1;
const int POSITION_OFFSET_2 = 2;
const int POSITION_OFFSET_3 = 3;
const int POSITION_OFFSET_4 = 4;

#define IPV6_ADDR_SCOPE_TYPE(scope) ((scope) << 16)
#define IPV6_ADDR_MC_SCOPE(a) ((a)->s6_addr[1] & 0x0f)
#ifndef ND_OPT_RDNSS
#define ND_OPT_RDNSS 25
struct nd_opt_rdnss {
    uint8_t nd_opt_rdnss_type;
    uint8_t nd_opt_rdnss_len;
    uint16_t nd_opt_rdnss_reserved;
    uint32_t nd_opt_rdnss_lifetime;
} _packed;
#endif

DhcpIpv6Client::DhcpIpv6Client(std::string ifname) : interfaceName(ifname), runFlag(false)
{
#ifndef OHOS_ARCH_LITE
    ipv6TimerId = 0;
#endif
    ipv6Thread_ = std::make_unique<DhcpThread>("InnerIpv6Thread");
    DHCP_LOGI("DhcpIpv6Client()");
}

DhcpIpv6Client::~DhcpIpv6Client()
{
    DHCP_LOGI("~DhcpIpv6Client()");
    if (ipv6Thread_ != nullptr) {
        ipv6Thread_.reset();
    }
}

bool DhcpIpv6Client::IsRunning()
{
    DHCP_LOGI("IsRunning()");
    return runFlag;
}
void DhcpIpv6Client::SetCallback(std::function<void(const std::string ifname, DhcpIpv6Info &info)> callback)
{
    DHCP_LOGI("SetCallback()");
    onIpv6AddressChanged = callback;
}

void DhcpIpv6Client::RunIpv6ThreadFunc()
{
    DhcpIpv6Start();
}

int DhcpIpv6Client::StartIpv6Thread(const std::string &ifname, bool isIpv6)
{
    DHCP_LOGI("StartIpv6Thread ifname:%{public}s bIpv6:%{public}d,runFlag:%{public}d", ifname.c_str(), isIpv6, runFlag);
    if (!runFlag) {
        interfaceName = ifname;
        if (ipv6Thread_ == nullptr) {
            ipv6Thread_ = std::make_unique<DhcpThread>("InnerIpv6Thread");
        }
        std::function<void()> func = [this]() { this->RunIpv6ThreadFunc(); };
        int delayTime = 0;
        bool result = ipv6Thread_->PostAsyncTask(func, delayTime);
        if (!result) {
            DHCP_LOGE("StartIpv6Thread PostAsyncTask failed!");
        }
        DHCP_LOGI("StartIpv6Thread RunIpv6ThreadFunc ok!");
    } else {
        DHCP_LOGI("StartIpv6Thread RunIpv6ThreadFunc!");
    }
    return 0;
}

unsigned int DhcpIpv6Client::ipv6AddrScope2Type(unsigned int scope)
{
    switch (scope) {
        case IPV6_ADDR_SCOPE_NODELOCAL:
            return IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_NODELOCAL) |
                IPV6_ADDR_LOOPBACK;
            break;

        case IPV6_ADDR_SCOPE_LINKLOCAL:
            return IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL) |
                IPV6_ADDR_LINKLOCAL;
            break;

        case IPV6_ADDR_SCOPE_SITELOCAL:
            return IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_SITELOCAL) |
                IPV6_ADDR_SITELOCAL;
            break;

        default:
            break;
    }

    return IPV6_ADDR_SCOPE_TYPE(scope);
}

int DhcpIpv6Client::getAddrType(const struct in6_addr *addr)
{
    if (!addr) {
        DHCP_LOGE("getAddrType failed, data invalid.");
        return IPV6_ADDR_LINKLOCAL;
    }
    unsigned int st = addr->s6_addr32[0];
    if ((st & htonl(ADDRTYPE_FLAG_HIGHE)) != htonl(ADDRTYPE_FLAG_ZERO) &&
        (st & htonl(ADDRTYPE_FLAG_HIGHE)) != htonl(ADDRTYPE_FLAG_HIGHE)) {
        return (IPV6_ADDR_UNICAST | IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));
    }

    if ((st & htonl(ADDRTYPE_FLAG_HIGHFF)) == htonl(ADDRTYPE_FLAG_HIGHFF)) {
        return (IPV6_ADDR_MULTICAST | ipv6AddrScope2Type(IPV6_ADDR_MC_SCOPE(addr)));
    }

    if ((st & htonl(ADDRTYPE_FLAG_HIGHFFC)) == htonl(ADDRTYPE_FLAG_HIGHFE8)) {
        return (IPV6_ADDR_LINKLOCAL | IPV6_ADDR_UNICAST |
            IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL));
    }

    if ((st & htonl(ADDRTYPE_FLAG_HIGHFFC)) == htonl(ADDRTYPE_FLAG_HIGHFEC)) {
        return (IPV6_ADDR_SITELOCAL | IPV6_ADDR_UNICAST |
            IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_SITELOCAL));
    }

    if ((st & htonl(ADDRTYPE_FLAG_HIGHFE)) == htonl(ADDRTYPE_FLAG_HIGHFC)) {
        return (IPV6_ADDR_UNICAST | IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));
    }

    if ((addr->s6_addr32[S6_ADDR_INDEX_ZERO] | addr->s6_addr32[S6_ADDR_INDEX_FIRST]) == 0) {
        if (addr->s6_addr32[S6_ADDR_INDEX_SECOND] == 0) {
            if (addr->s6_addr32[S6_ADDR_INDEX_THIRD] == 0) {
                return IPV6_ADDR_ANY;
            }
            if (addr->s6_addr32[S6_ADDR_INDEX_THIRD] == htonl(ADDRTYPE_FLAG_ONE)) {
                return (IPV6_ADDR_LOOPBACK | IPV6_ADDR_UNICAST |
                    IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL));
            }
            return (IPV6_ADDR_COMPATV4 | IPV6_ADDR_UNICAST |
                IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));
        }
        if (addr->s6_addr32[S6_ADDR_INDEX_THIRD] == htonl(ADDRTYPE_FLAG_LOWF)) {
            return (IPV6_ADDR_MAPPED | IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));
        }
    }

    return (IPV6_ADDR_UNICAST | IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));
}

int DhcpIpv6Client::getAddrScope(const struct in6_addr *addr)
{
    if (!addr) {
        DHCP_LOGE("getAddrType failed, data invalid.");
        return IPV6_ADDR_LINKLOCAL;
    }
    return static_cast<unsigned int>(getAddrType(addr)) & IPV6_ADDR_SCOPE_MASK;
}

void DhcpIpv6Client::GetIpv6Prefix(const char* ipv6Addr, char* ipv6PrefixBuf, uint8_t prefixLen)
{
    if (!ipv6Addr || !ipv6PrefixBuf) {
        DHCP_LOGE("GetIpv6Prefix failed, input invalid.");
        return;
    }
    if (prefixLen >= DHCP_INET6_ADDRSTRLEN) {
        strlcpy(ipv6PrefixBuf, ipv6Addr, DHCP_INET6_ADDRSTRLEN);
        return;
    }

    struct in6_addr ipv6AddrBuf = IN6ADDR_ANY_INIT;
    inet_pton(AF_INET6, ipv6Addr, &ipv6AddrBuf);

    char buf[INET6_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET6, &ipv6AddrBuf, buf, INET6_ADDRSTRLEN) == NULL) {
        strlcpy(ipv6PrefixBuf, ipv6Addr, DHCP_INET6_ADDRSTRLEN);
        return;
    }

    struct in6_addr ipv6Prefix = IN6ADDR_ANY_INIT;
    uint32_t byteIndex = prefixLen / CHAR_BIT;
    if (memset_s(ipv6Prefix.s6_addr, sizeof(ipv6Prefix.s6_addr), 0, sizeof(ipv6Prefix.s6_addr)) != EOK ||
        memcpy_s(ipv6Prefix.s6_addr, sizeof(ipv6Prefix.s6_addr), &ipv6AddrBuf, byteIndex) != EOK) {
        return;
    }
    uint32_t bitOffset = prefixLen & MASK_FILTER;
    if ((bitOffset != 0) && (byteIndex < INET_ADDRSTRLEN)) {
        ipv6Prefix.s6_addr[byteIndex] = ipv6AddrBuf.s6_addr[byteIndex] & (0xff00 >> bitOffset);
    }
    inet_ntop(AF_INET6, &ipv6Prefix, ipv6PrefixBuf, INET6_ADDRSTRLEN);
}

int DhcpIpv6Client::GetIpFromS6Address(void* addr, int family, char* buf, int buflen)
{
    if (!inet_ntop(family, (struct in6_addr*)addr, buf, buflen)) {
        DHCP_LOGE("GetIpFromS6Address failed");
        return -1;
    }
    return 0;
}

void DhcpIpv6Client::onIpv6AddressAddEvent(void* data, int prefixLen, int ifaIndex)
{
    int currIndex = static_cast<int>(if_nametoindex(interfaceName.c_str()));
    if (currIndex != ifaIndex) {
        DHCP_LOGE("address ifaindex invalid, %{public}d != %{public}d", currIndex, ifaIndex);
        return;
    }
    if (!data) {
        DHCP_LOGE("onIpv6AddressAddEvent failed, data invalid.");
        return;
    }
    struct in6_addr *addr = (struct in6_addr*)data;
    char addr_str[INET6_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET6, addr, addr_str, INET6_ADDRSTRLEN);
    int scope = getAddrScope(addr);
    if (scope == 0) {
        getIpv6RouteAddr();
        if (memset_s(dhcpIpv6Info.ipv6SubnetAddr, DHCP_INET6_ADDRSTRLEN,
            0, DHCP_INET6_ADDRSTRLEN) != EOK) {
            DHCP_LOGE("onIpv6AddressAddEvent memset_s failed");
            return;
        }
        dhcpIpv6Info.status |= 1;
        GetIpv6Prefix(DEFAULT_ROUTE, dhcpIpv6Info.ipv6SubnetAddr, prefixLen);
        DHCP_LOGD("onIpv6AddressAddEvent addr:%{private}s, subaddr:%{public}s, route:%{public}s, scope:%{public}d",
            addr_str, dhcpIpv6Info.ipv6SubnetAddr, dhcpIpv6Info.routeAddr, scope);
        AddIpv6Address(addr_str, INET6_ADDRSTRLEN);
    } else if (scope == IPV6_ADDR_LINKLOCAL) {
        if (memset_s(dhcpIpv6Info.linkIpv6Addr, DHCP_INET6_ADDRSTRLEN, 0, DHCP_INET6_ADDRSTRLEN) != EOK ||
            memcpy_s(dhcpIpv6Info.linkIpv6Addr, INET6_ADDRSTRLEN, addr_str, INET6_ADDRSTRLEN) != EOK) {
            DHCP_LOGE("onIpv6AddressAddEvent memset_s or memcpy_s failed");
            return;
        }
        DHCP_LOGD("onIpv6AddressAddEvent addr:%{public}s, subaddr:%{public}s, route:%{public}s, scope:%{public}d",
            addr_str, dhcpIpv6Info.ipv6SubnetAddr, dhcpIpv6Info.routeAddr, scope);
    } else {
        DHCP_LOGD("onIpv6AddressAddEvent other scope:%{public}d", scope);
    }
}

void DhcpIpv6Client::AddIpv6Address(char *ipv6addr, int len)
{
    if (!ipv6addr) {
        DHCP_LOGE("AddIpv6Address ipv6addr is nullptr!");
        return;
    }
    int first = ipv6addr[0]-'0';
    if (first == NUMBER_TWO || first == NUMBER_THREE) { // begin '2' '3'
        if (IsEui64ModeIpv6Address(ipv6addr, len)) {
            DHCP_LOGI("AddIpv6Address add globalIpv6Addr, first=%{public}d", first);
            if (memcpy_s(dhcpIpv6Info.globalIpv6Addr, len, ipv6addr, len) != EOK) {
                DHCP_LOGE("AddIpv6Address memcpy_s failed!");
                return;
            }
        }  else {
            DHCP_LOGI("AddIpv6Address add randIpv6Addr, first=%{public}d", first);
            if (memcpy_s(dhcpIpv6Info.randIpv6Addr, len, ipv6addr, len) != EOK) {
                DHCP_LOGE("onIpv6AddressAddEvent memcpy_s failed!");
                return;
            }
        }
        if (strlen(dhcpIpv6Info.globalIpv6Addr) != 0 || strlen(dhcpIpv6Info.randIpv6Addr) != 0) {
            onIpv6AddressChanged(interfaceName, dhcpIpv6Info);
        }
    } else if (first == NUMBER_FIFTY_FOUR) {  // begin 'f'->54
        if (IsEui64ModeIpv6Address(ipv6addr, len)) {
            if (memcpy_s(dhcpIpv6Info.uniqueLocalAddr1, len, ipv6addr, len) != EOK) {
                DHCP_LOGE("AddIpv6Address memcpy_s failed!");
                return;
            }
            DHCP_LOGI("AddIpv6Address add uniqueLocalAddr1, first=%{public}d", first);
        }  else {
            if (memcpy_s(dhcpIpv6Info.uniqueLocalAddr2, len, ipv6addr, len) != EOK) {
                DHCP_LOGE("AddIpv6Address uniqueLocalAddr2 memcpy_s failed!");
                return;
            }
            DHCP_LOGI("AddIpv6Address add uniqueLocalAddr2, first=%{public}d", first);
        }
        if (strlen(dhcpIpv6Info.uniqueLocalAddr1) != 0 || strlen(dhcpIpv6Info.uniqueLocalAddr2) != 0) {
            onIpv6AddressChanged(interfaceName, dhcpIpv6Info);
        }
    } else {
        DHCP_LOGI("AddIpv6Address other first=%{public}d", first);
    }
}

bool DhcpIpv6Client::IsEui64ModeIpv6Address(char *ipv6addr, int len)
{
    if (ipv6addr == nullptr) {
        DHCP_LOGE("IsEui64ModeIpv6Address ipv6addr is nullptr!");
        return false;
    }
    int ifaceIndex = 0;
    unsigned char ifaceMac[MAC_ADDR_LEN];
    if (GetLocalInterface(interfaceName.c_str(), &ifaceIndex, ifaceMac, NULL) != DHCP_OPT_SUCCESS) {
        DHCP_LOGE("IsEui64ModeIpv6Address GetLocalInterface failed, ifaceName:%{public}s.", interfaceName.c_str());
        return false;
    }
    char macAddr[MAC_ADDR_LEN * MAC_ADDR_CHAR_NUM];
    if (memset_s(macAddr, sizeof(macAddr), 0, sizeof(macAddr)) != EOK) {
        DHCP_LOGE("IsEui64ModeIpv6Address memset_s failed!");
        return false;
    }
    MacChConToMacStr(ifaceMac, MAC_ADDR_LEN, macAddr, sizeof(macAddr));
    std::string localMacString = macAddr;
    std::string ipv6AddrString = ipv6addr;
    size_t macPosition = localMacString.find_last_of(':');
    size_t ipv6position = ipv6AddrString.find_last_of(':');
    DHCP_LOGI("IsEui64ModeIpv6Address name:%{public}s index:%{public}d %{public}zu %{public}zu len:%{public}d",
        interfaceName.c_str(), ifaceIndex, macPosition, ipv6position, len);
    if ((macPosition != std::string::npos) && (ipv6position != std::string::npos)) {
        if (macAddr[macPosition + POSITION_OFFSET_1] == ipv6addr[ipv6position + POSITION_OFFSET_3] &&
            macAddr[macPosition + POSITION_OFFSET_2] == ipv6addr[ipv6position + POSITION_OFFSET_4] &&
            macAddr[macPosition - POSITION_OFFSET_1] == ipv6addr[ipv6position + POSITION_OFFSET_2] &&
            macAddr[macPosition - POSITION_OFFSET_2] == ipv6addr[ipv6position + POSITION_OFFSET_1]) {
            DHCP_LOGI("IsEui64ModeIpv6Address is true!");
            return true;
        }
    }
    return false;
}

void DhcpIpv6Client::onIpv6DnsAddEvent(void* data, int len, int ifaIndex)
{
    int currIndex = static_cast<int>(if_nametoindex(interfaceName.c_str()));
    if (currIndex != ifaIndex) {
        DHCP_LOGE("dnsevent ifaindex invalid, %{public}d != %{public}d", currIndex, ifaIndex);
        return;
    }
    dhcpIpv6Info.status |= (1 << 1);
    (void)strncpy_s(dhcpIpv6Info.dnsAddr, DHCP_INET6_ADDRSTRLEN, DEFAULUT_BAK_DNS, strlen(DEFAULUT_BAK_DNS));
    std::vector<std::string>::iterator iter = find(dhcpIpv6Info.vectorDnsAddr.begin(),
        dhcpIpv6Info.vectorDnsAddr.end(), DEFAULUT_BAK_DNS);
    if (iter == dhcpIpv6Info.vectorDnsAddr.end()) {
        dhcpIpv6Info.vectorDnsAddr.push_back(DEFAULUT_BAK_DNS);
    }
    if (!data) {
        DHCP_LOGE("onIpv6DnsAddEvent failed, data invalid.");
        return;
    }
    struct nd_opt_hdr *opthdr = (struct nd_opt_hdr *)(data);
    uint16_t optlen = opthdr->nd_opt_len;
    if (optlen * CHAR_BIT > len) {
        DHCP_LOGE("dns len invalid optlen:%{public}d > len:%{public}d", optlen, len);
        return;
    }
    if (opthdr->nd_opt_type != ND_OPT_RDNSS) {
        DHCP_LOGE("dns nd_opt_type invlid:%{public}d", opthdr->nd_opt_type);
        return;
    }
    if ((optlen < ND_OPT_MIN_LEN) || !(optlen & 0x1)) {
        DHCP_LOGE("dns optLen invlid:%{public}d", optlen);
        return;
    }
    (void)memset_s(dhcpIpv6Info.dnsAddr2, DHCP_INET6_ADDRSTRLEN, 0, DHCP_INET6_ADDRSTRLEN);
    int numaddrs = (optlen - 1) / 2;
    struct nd_opt_rdnss *rndsopt = (struct nd_opt_rdnss *)opthdr;
    struct in6_addr *addrs = (struct in6_addr *)(rndsopt + 1);
    if (numaddrs > 0) {
        inet_ntop(AF_INET6, addrs + 0, dhcpIpv6Info.dnsAddr2, DHCP_INET6_ADDRSTRLEN);
    }
    for (int i = 0; i < numaddrs; i++) {
        char dnsAddr[DHCP_INET6_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET6, addrs + i, dnsAddr, DHCP_INET6_ADDRSTRLEN);
        iter = find(dhcpIpv6Info.vectorDnsAddr.begin(), dhcpIpv6Info.vectorDnsAddr.end(), dnsAddr);
        if (iter == dhcpIpv6Info.vectorDnsAddr.end()) {
            dhcpIpv6Info.vectorDnsAddr.push_back(dnsAddr);
            DHCP_LOGI("onIpv6DnsAddEvent add dns:%{public}d", i);
        }
    }
}

void DhcpIpv6Client::onIpv6RouteAddEvent(char* gateway, char* dst, int ifaIndex)
{
    int currIndex = static_cast<int>(if_nametoindex(interfaceName.c_str()));
    if (currIndex != ifaIndex) {
        DHCP_LOGE("route ifaindex invalid, %{public}d != %{public}d", currIndex, ifaIndex);
        return;
    }
    DHCP_LOGI("onIpv6RouteAddEvent gateway:%{private}s, dst:%{private}s, ifindex:%{public}d",
        gateway, dst, ifaIndex);
    if (!gateway || !dst) {
        DHCP_LOGE("onIpv6RouteAddEvent input invalid.");
        return;
    }
    if (strlen(dst) == 0 && strlen(gateway) != 0) {
        (void)memset_s(dhcpIpv6Info.routeAddr, DHCP_INET6_ADDRSTRLEN,
            0, DHCP_INET6_ADDRSTRLEN);
        if (strncpy_s(dhcpIpv6Info.routeAddr, DHCP_INET6_ADDRSTRLEN, gateway, strlen(gateway)) != EOK) {
            DHCP_LOGE("onIpv6RouteAddEvent strncpy_s gateway failed");
            return;
        }
    }
}

int32_t DhcpIpv6Client::createKernelSocket(void)
{
    int32_t sz = KERNEL_BUFF_SIZE;
    int32_t on = 1;
    int32_t sockFd = socket(AF_NETLINK, SOCK_RAW, 0);
    if (sockFd < 0) {
        DHCP_LOGE("dhcp6 create socket failed.");
        return -1;
    }
    if (setsockopt(sockFd, SOL_SOCKET, SO_RCVBUFFORCE, &sz, sizeof(sz)) < 0) {
        DHCP_LOGE("setsockopt socket SO_RCVBUFFORCE failed.");
        close(sockFd);
        return -1;
    }
    if (setsockopt(sockFd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz)) < 0) {
        DHCP_LOGE("setsockopt socket SO_RCVBUF failed.");
        close(sockFd);
        return -1;
    }
    if (setsockopt(sockFd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) < 0) {
        DHCP_LOGE("setsockopt socket SO_PASSCRED failed.");
        close(sockFd);
        return -1;
    }
    struct timeval timeout = {1, 0};
    if (setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        DHCP_LOGE("setsockopt socket SO_RCVTIMEO failed.");
    }
    struct sockaddr saddr;
    (void)memset_s(&saddr, sizeof(saddr), 0, sizeof(saddr));
    setSocketFilter(&saddr);
    if (bind(sockFd, &saddr, sizeof(saddr)) < 0) {
        DHCP_LOGE("bind kernel socket failed.");
        close(sockFd);
        return -1;
    }
    return sockFd;
}

void DhcpIpv6Client::Reset()
{
    (void)memset_s(&dhcpIpv6Info, sizeof(dhcpIpv6Info), 0, sizeof(dhcpIpv6Info));
}

void DhcpIpv6Client::getIpv6RouteAddr()
{
    int len = ROUTE_BUFF_SIZE;
    char buffer[ROUTE_BUFF_SIZE] = {0};
    fillRouteData(buffer, len);
    if (send(ipv6SocketFd, buffer, len, 0) < 0) {
        DHCP_LOGE("getIpv6RouteAddr send route info failed.");
    }
    DHCP_LOGE("getIpv6RouteAddr send info ok");
}

int DhcpIpv6Client::StartIpv6()
{
    DHCP_LOGI("StartIpv6 enter. %{public}s", interfaceName.c_str());
    (void)memset_s(&dhcpIpv6Info, sizeof(dhcpIpv6Info), 0, sizeof(dhcpIpv6Info));
    runFlag = true;
    ipv6SocketFd = createKernelSocket();
    if (ipv6SocketFd < 0) {
        runFlag = false;
        DHCP_LOGE("StartIpv6 ipv6SocketFd < 0 failed!");
        return -1;
    }
    uint8_t *buff = (uint8_t*)malloc(KERNEL_BUFF_SIZE * sizeof(uint8_t));
    if (buff == NULL) {
        DHCP_LOGE("StartIpv6 ipv6 malloc buff failed.");
        close(ipv6SocketFd);
        runFlag = false;
        return -1;
    }
    struct timeval timeout = {0};
    fd_set rSet;
    timeout.tv_sec = 0;
    timeout.tv_usec = IPV6_TIMEOUT_USEC;
    while (runFlag) {
        (void)memset_s(buff, KERNEL_BUFF_SIZE * sizeof(uint8_t), 0, KERNEL_BUFF_SIZE * sizeof(uint8_t));
        FD_ZERO(&rSet);
        if (ipv6SocketFd < 0) {
            DHCP_LOGE("error: ipv6SocketFd < 0");
            break;
        }
        FD_SET(ipv6SocketFd, &rSet);
        int iRet = select(ipv6SocketFd + 1, &rSet, NULL, NULL, &timeout);
        if (iRet < 0) {
            if ((iRet == -1) && (errno == EINTR)) {
                DHCP_LOGD("StartIpv6 select errno:%{public}d, a signal was caught!", errno);
            } else {
                DHCP_LOGD("StartIpv6 failed, iRet:%{public}d error:%{public}d", iRet, errno);
            }
            continue;
        }
        if (!FD_ISSET(ipv6SocketFd, &rSet)) {
            continue;
        }
        int32_t len = recv(ipv6SocketFd, buff, 8 *1024, 0);
        if (len < 0) {
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
                continue;
            }
            DHCP_LOGE("StartIpv6 recv kernel socket failed %{public}d.", errno);
            break;
        } else if (len == 0) {
            continue;
        }
        handleKernelEvent(buff, len);
    }
    close(ipv6SocketFd);
    ipv6SocketFd = 0;
    runFlag = false;
    free(buff);
    buff = NULL;
    DHCP_LOGI("DhcpIpv6Client thread exit.");
    return 0;
}

void *DhcpIpv6Client::DhcpIpv6Start()
{
    if (runFlag) {
        DHCP_LOGI("DhcpIpv6Client already started.");
        return NULL;
    }
    int result = StartIpv6();
    if (result < 0) {
        DHCP_LOGE("dhcp6 run failed.");
    }
    return NULL;
}

void DhcpIpv6Client::DhcpIPV6Stop(void)
{
    DHCP_LOGI("DhcpIPV6Stop exit ipv6 thread, runFlag:%{public}d", runFlag);
    runFlag = false;
}

#ifndef OHOS_ARCH_LITE
using TimeOutCallback = std::function<void()>;
void DhcpIpv6Client::Ipv6TimerCallback()
{
    DHCP_LOGI("enter Ipv6TimerCallback, ipv6TimerId:%{public}u", ipv6TimerId);
    StopIpv6Timer();
    DhcpIpv6TimerCallbackEvent(interfaceName.c_str());
}

void DhcpIpv6Client::StartIpv6Timer()
{
    DHCP_LOGI("StartIpv6Timer ipv6TimerId:%{public}u", ipv6TimerId);
    std::unique_lock<std::mutex> lock(ipv6TimerMutex);
    if (ipv6TimerId == 0) {
        TimeOutCallback timeoutCallback = [this] { this->Ipv6TimerCallback(); };
        DhcpTimer::GetInstance()->Register(timeoutCallback, ipv6TimerId, DhcpTimer::DEFAULT_TIMEROUT);
        DHCP_LOGI("StartIpv6Timer success! ipv6TimerId:%{public}u", ipv6TimerId);
    }
    return;
}

void DhcpIpv6Client::StopIpv6Timer()
{
    DHCP_LOGI("StopIpv6Timer ipv6TimerId:%{public}u", ipv6TimerId);
    std::unique_lock<std::mutex> lock(ipv6TimerMutex);
    DhcpTimer::GetInstance()->UnRegister(ipv6TimerId);
    ipv6TimerId = 0;
    return;
}
#endif
}  // namespace DHCP
}  // namespace OHOS