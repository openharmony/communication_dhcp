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
#include <sys/types.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <net/if.h>

#include "securec.h"
#include "dhcp_define.h"
#include "dhcp_api.h"
#include "dhcp_ipv6_event.h"
#include "dhcp_ipv6.h"

#undef LOG_TAG
#define LOG_TAG "WifiDhcp6Client"

pthread_cond_t g_ipv6WaitSignal;
pthread_mutex_t g_ipv6Mutex;

#define DEFAULUT_BAK_DNS "240e:4c:4008::1"
#define DEFAULT_ROUTE "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
const char *DEFAULT_IPV6_ANY_INIT_ADDR = "::";

#define IPV6_WAIT_TIMEOUT (30 * 1000)
#define IPV6_WAIT_NSEC 1000000000
#define IPV6_WAIT_THOUNSAND 1000
#define IPV6_WAIT_USEC 1000000

bool g_runFlag = false;
struct DhcpIPV6Info g_DhcpIpv6Info;

#define IPV6_ADDR_ANY 0x0000U

#define IPV6_ADDR_UNICAST 0x0001U
#define IPV6_ADDR_MULTICAST 0x0002U

#define IPV6_ADDR_SCOPE_TYPE(scope) ((scope) << 16)
#define IPV6_ADDR_MC_SCOPE(a) ((a)->s6_addr[1] & 0x0f)

#define IPV6_ADDR_SCOPE_MASK 0x00F0U

#define IPV6_ADDR_LOOPBACK 0x0010U
#define IPV6_ADDR_LINKLOCAL 0x0020U
#define IPV6_ADDR_SITELOCAL 0x0040U

#define IPV6_ADDR_COMPATV4 0x0080U
#define IPV6_ADDR_MAPPED 0x1000U

#define IPV6_ADDR_SCOPE_NODELOCAL 0X01
#define IPV6_ADDR_SCOPE_LINKLOCAL 0X02
#define IPV6_ADDR_SCOPE_SITELOCAL 0X05
#define IPV6_ADDR_SCOPE_ORGLOCAL 0X08
#define IPV6_ADDR_SCOPE_GLOBAL 0X0E

#define IPV6_MASK_SZ 8
#define INT16SZ 2
#define ENOSPC 28

#define S6_ADDR_INDEX_ZERO 0
#define S6_ADDR_INDEX_FIRST 1
#define S6_ADDR_INDEX_SECOND 2
#define S6_ADDR_INDEX_THIRD 3

#define ADDRTYPE_FLAG_ZERO 0x00000000
#define ADDRTYPE_FLAG_ONE 0x00000001
#define ADDRTYPE_FLAG_LOWF 0x0000ffff
#define ADDRTYPE_FLAG_HIGHE 0xE0000000
#define ADDRTYPE_FLAG_HIGHFF 0xFF000000
#define ADDRTYPE_FLAG_HIGHFFC 0xFFC00000
#define ADDRTYPE_FLAG_HIGHFE8 0xFE800000
#define ADDRTYPE_FLAG_HIGHFEC 0xFEC00000
#define ADDRTYPE_FLAG_HIGHFE 0xFE000000
#define ADDRTYPE_FLAG_HIGHFE 0xFE000000
#define ADDRTYPE_FLAG_HIGHFC 0xFC000000

#define MASK_HALF 2
#define MASK_THREE 3

#define MASK_FILTER 0x7

#ifndef ND_OPT_RDNSS
#define ND_OPT_RDNSS 25
struct nd_opt_rdnss {
    uint8_t nd_opt_rdnss_type;
    uint8_t nd_opt_rdnss_len;
    uint16_t nd_opt_rdnss_reserved;
    uint32_t nd_opt_rdnss_lifetime;
} _packed;
#endif
#define ND_OPT_MIN_LEN 3

#define IPV6_ALL_GETTED 3

#define CHAR_BIT 8

char g_ifName[INFNAME_SIZE] = {0};

static void FormatIPV6Info(struct DhcpIPV6Info* info)
{
    if (!info) {
        return;
    }

    if (strlen(info->linkIpv6Addr) == 0) {
        if (strncpy_s(info->linkIpv6Addr, DHCP_INET6_ADDRSTRLEN, "*", 1) != EOK) {
            return;
        }
    }

    if (strlen(info->ipv6SubnetAddr) == 0) {
        if (strncpy_s(info->ipv6SubnetAddr, DHCP_INET6_ADDRSTRLEN, "*", 1) != EOK) {
            return;
        }
    }

    if (strlen(info->dnsAddr) == 0) {
        if (strncpy_s(info->dnsAddr, DHCP_INET6_ADDRSTRLEN, "*", 1) != EOK) {
            return;
        }
    }
}

void PublishDhcpIpv6ResultEvent(void)
{
    FormatIPV6Info(&g_DhcpIpv6Info);

    uint32_t curTime = (uint32_t)time(NULL);
    char strData[STRING_MAX_LEN] = {0};
    if (snprintf_s(strData, STRING_MAX_LEN, STRING_MAX_LEN - 1, "ipv6:%s,%u,%s,%s,%s,%s,%s,%s,%s",
        g_ifName, curTime, g_DhcpIpv6Info.linkIpv6Addr, g_DhcpIpv6Info.globalIpv6Addr,
        g_DhcpIpv6Info.globalIpv6Addr, g_DhcpIpv6Info.ipv6SubnetAddr,
        g_DhcpIpv6Info.routeAddr, g_DhcpIpv6Info.dnsAddr, DEFAULUT_BAK_DNS) < 0) {
            LOGE("PublishDhcpIpv6ResultEvent failed, snprintf_s failed");
        return;
    }
    if (!PublishDhcpIpv4ResultEvent(PUBLISH_CODE_SUCCESS, strData, g_ifName)) {
        LOGE("PublishDhcpIpv6ResultEvent %{public}s failed!", strData);
    }
}

static unsigned int ipv6AddrScope2Type(unsigned int scope)
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

static int getAddrType(const struct in6_addr *addr)
{
    if (!addr) {
        LOGE("getAddrType failed, data invalid.");
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

static int getAddrScope(const struct in6_addr *addr)
{
    if (!addr) {
        LOGE("getAddrType failed, data invalid.");
        return IPV6_ADDR_LINKLOCAL;
    }
    return getAddrType(addr) & IPV6_ADDR_SCOPE_MASK;
}

static void GetIpv6Prefix(const char* ipv6Addr, char* ipv6PrefixBuf, uint8_t prefixLen)
{
    if (!ipv6Addr || !ipv6PrefixBuf) {
        LOGE("GetIpv6Prefix failed, input invalid.");
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

static const char* getRouteFromIPV6Addr(const u_char *src, char* route, size_t size)
{
    if (!src || !route) {
        LOGE("getRouteFromIPV6Addr failed, input invalid.");
        return NULL;
    }
    char tmp[sizeof("ffff:ffff:ffff:ffff:ffff:255.255.255.255")] = {0};
    char *tp = NULL;
    char *ep = NULL;
    struct { int base, len;} best, cur;
    u_int words[IPV6_MASK_SZ/INT16SZ];
    int i;
    int advance;
    (void)memset_s(words, sizeof(words), 0, sizeof(words));
    for (i = 0; i < IPV6_MASK_SZ; i++) {
        words[i / MASK_HALF] |= (src[i] << ((1 - (i % MASK_HALF)) << MASK_THREE));
    }
    best.base = -1;
    cur.base = -1;
    for (i = 0; i < (IPV6_MASK_SZ / INT16SZ); i++) {
        if (words[i] == 0) {
            if (cur.base == -1) {
                cur.base = i;
                cur.len = i;
            } else {
                cur.len++;
            }
        } else {
            if (cur.base != -1) {
                if (best.base == -1 || cur.len > best.len) {
                    best = cur;
                }
                cur.base = -1;
            }
        }
    }
    if (cur.base != -1) {
        if (best.base == -1 || cur.len > best.len) {
            best = cur;
        }
    }
    if (best.base != -1 && best.len < MASK_HALF) {
        best.base = -1;
    }
    tp = tmp;
    ep = tmp + sizeof(tmp);
    for (i = 0; i < (IPV6_MASK_SZ / INT16SZ) && tp < ep; i++) {
        if (best.base != -1 && i >= best.base &&
            i < (best.base + best.len)) {
            if (i == best.base) {
                if (tp + 1 >= ep) {
                    errno = ENOSPC;
                    return NULL;
                }
                *tp++ =':';
            }
            continue;
        }
        if (i != 0) {
            if (tp + 1 >= ep) {
                errno = ENOSPC;
                return NULL;
            }
            *tp++ = ':';
        }
        advance = snprintf_s(tp, ep -tp, ep -tp - 1, "%x", words[i]);
        if (advance <= 0 || advance >= ep - tp) {
            errno = ENOSPC;
            return NULL;
        }
        tp += advance;
    }
    if (best.base != -1 && (best.base + best.len) == (IPV6_MASK_SZ / INT16SZ)) {
        if (tp + 1 >= ep) {
            errno = ENOSPC;
            return NULL;
        }
        *tp++ = ':';
    }
    if (tp + 1 >= ep) {
        errno = ENOSPC;
        return NULL;
    }
    *tp++ = '\0';
    size_t prefLen = (size_t)(tp - tmp);
    if (prefLen + MASK_THREE > size) {
        errno = ENOSPC;
        return NULL;
    }
    char strData[INET6_ADDRSTRLEN] = {0};
    strlcpy(strData, tmp, size);
    // append ::1
    if (snprintf_s(route, INET6_ADDRSTRLEN, INET6_ADDRSTRLEN - 1, "%s::1", strData) < 0) {
        LOGE("getRouteFromIPV6Addr failed, snprintf_s failed");
        return NULL;
    }
    return (route);
}

void readIPV6Address(const char* ifname)
{
    if (!ifname) {
        LOGE("readIPV6Address failed, ifname invalid.");
        return;
    }
    bool ipv6Notify = false;
    struct ifaddrs* ifAddrStruct = NULL;
    getifaddrs(&ifAddrStruct);
    while (ifAddrStruct != NULL) {
        if (strcmp(ifAddrStruct->ifa_name, ifname) != 0) {
            ifAddrStruct = ifAddrStruct->ifa_next;
            continue;
        }
        if (ifAddrStruct->ifa_addr == NULL) {
            ifAddrStruct = ifAddrStruct->ifa_next;
            continue;
        }
        if (ifAddrStruct->ifa_addr->sa_family != AF_INET6) {
            ifAddrStruct = ifAddrStruct->ifa_next;
            continue;
        }
        struct sockaddr_in6 *ipv6Addr = (struct sockaddr_in6*)ifAddrStruct->ifa_addr;
        char addr_str[INET6_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET6, &ipv6Addr->sin6_addr.s6_addr, addr_str, INET6_ADDRSTRLEN);
        int scope = getAddrScope(&ipv6Addr->sin6_addr);
        if (scope == 0) {
            (void)memcpy_s(g_DhcpIpv6Info.globalIpv6Addr, INET6_ADDRSTRLEN, addr_str, INET6_ADDRSTRLEN);
            if (!getRouteFromIPV6Addr(ipv6Addr->sin6_addr.s6_addr, g_DhcpIpv6Info.routeAddr, INET6_ADDRSTRLEN)) {
                LOGE("readIPV6Address get route failed.");
            }
            struct sockaddr_in6 *mask = (struct sockaddr_in6 *)ifAddrStruct->ifa_netmask;
            if (!mask) {
                (void)inet_ntop(AF_INET6, &mask->sin6_addr,
                    g_DhcpIpv6Info.ipv6SubnetAddr, DHCP_INET6_ADDRSTRLEN);
            }
            g_DhcpIpv6Info.status = IPV6_ALL_GETTED;
            (void)strncpy_s(g_DhcpIpv6Info.dnsAddr, DHCP_INET6_ADDRSTRLEN,
                DEFAULUT_BAK_DNS, sizeof(DEFAULUT_BAK_DNS));
            ipv6Notify = true;
            break;
        } else if (scope == IPV6_ADDR_LINKLOCAL) {
            (void)memcpy_s(g_DhcpIpv6Info.linkIpv6Addr, INET6_ADDRSTRLEN, addr_str, INET6_ADDRSTRLEN);
        }
        LOGI("readIPV6Address addr: %{private}s, max: %{private}s, scope: %{public}d",
            addr_str, g_DhcpIpv6Info.ipv6SubnetAddr, scope);
        ifAddrStruct = ifAddrStruct->ifa_next;
    }
    if (ipv6Notify) {
        PublishDhcpIpv6ResultEvent();
    }
}

void checkBroadIPV6Result(void)
{
    if (g_DhcpIpv6Info.status != IPV6_ALL_GETTED) {
        return;
    }
    PublishDhcpIpv6ResultEvent();
    pthread_mutex_lock(&g_ipv6Mutex);
    pthread_cond_signal(&g_ipv6WaitSignal);
    pthread_mutex_unlock(&g_ipv6Mutex);
}

void onIpv6AddressAddEvent(void* data, int prefixLen, int ifaIndex)
{
    int currIndex = if_nametoindex(g_ifName);
    if (currIndex != ifaIndex) {
        LOGE("address ifaindex invalid, %{public}d != %{public}d", currIndex, ifaIndex);
        return;
    }
    if (!data) {
        LOGE("onIpv6AddressAddEvent failed, data invalid.");
        return;
    }
    struct in6_addr *addr = (struct in6_addr*)data;
    char addr_str[INET6_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET6, addr, addr_str, INET6_ADDRSTRLEN);
    int scope = getAddrScope(addr);
    if (scope == 0) {
        (void)memset_s(g_DhcpIpv6Info.globalIpv6Addr, DHCP_INET6_ADDRSTRLEN,
            0, DHCP_INET6_ADDRSTRLEN);
        (void)memset_s(g_DhcpIpv6Info.routeAddr, DHCP_INET6_ADDRSTRLEN,
            0, DHCP_INET6_ADDRSTRLEN);
        (void)memset_s(g_DhcpIpv6Info.ipv6SubnetAddr, DHCP_INET6_ADDRSTRLEN,
            0, DHCP_INET6_ADDRSTRLEN);
        g_DhcpIpv6Info.status |= 1;
        (void)memcpy_s(g_DhcpIpv6Info.globalIpv6Addr, INET6_ADDRSTRLEN, addr_str, INET6_ADDRSTRLEN);
        if (!getRouteFromIPV6Addr(addr->s6_addr, g_DhcpIpv6Info.routeAddr, INET6_ADDRSTRLEN)) {
            LOGE("onIpv6AddressAddEvent get route failed.");
        }
        GetIpv6Prefix(DEFAULT_ROUTE, g_DhcpIpv6Info.ipv6SubnetAddr, prefixLen);
        checkBroadIPV6Result();
    } else if (scope == IPV6_ADDR_LINKLOCAL) {
        (void)memset_s(g_DhcpIpv6Info.linkIpv6Addr, DHCP_INET6_ADDRSTRLEN,
            0, DHCP_INET6_ADDRSTRLEN);
        (void)memcpy_s(g_DhcpIpv6Info.linkIpv6Addr, INET6_ADDRSTRLEN, addr_str, INET6_ADDRSTRLEN);
    }
    LOGI("onIpv6AddressAddEvent addr: %{private}s, max: %{private}s, route: %{private}s, scope: %{private}d",
        addr_str, g_DhcpIpv6Info.ipv6SubnetAddr, g_DhcpIpv6Info.routeAddr, scope);
}

void onIpv6DnsAddEvent(void* data, int len, int ifaIndex)
{
    int currIndex = if_nametoindex(g_ifName);
    if (currIndex != ifaIndex) {
        LOGE("dnsevent ifaindex invalid, %{public}d != %{public}d", currIndex, ifaIndex);
        return;
    }
    g_DhcpIpv6Info.status |= (1 << 1);
    (void)strncpy_s(g_DhcpIpv6Info.dnsAddr, DHCP_INET6_ADDRSTRLEN,
        DEFAULUT_BAK_DNS, sizeof(DEFAULUT_BAK_DNS));
    do {
        if (!data) {
            LOGE("onIpv6DnsAddEvent failed, data invalid.");
            break;
        }
        struct nd_opt_hdr *opthdr = (struct nd_opt_hdr *)(data);
        uint16_t optlen = opthdr->nd_opt_len;
        if (optlen * CHAR_BIT > len) {
            LOGE("dns len invalid optlen:%{public}d > len:%{public}d", optlen, len);
            break;
        }
        if (opthdr->nd_opt_type != ND_OPT_RDNSS) {
            LOGE("dns nd_opt_type invlid:%{public}d", opthdr->nd_opt_type);
            break;
        }
        if ((optlen < ND_OPT_MIN_LEN) || !(optlen & 0x1)) {
            LOGE("dns optLen invlid:%{public}d", optlen);
            break;
        }
        (void)memset_s(g_DhcpIpv6Info.dnsAddr, DHCP_INET6_ADDRSTRLEN,
            0, DHCP_INET6_ADDRSTRLEN);
        int numaddrs = (optlen - 1) / 2;
        struct nd_opt_rdnss *rndsopt = (struct nd_opt_rdnss *)opthdr;
        struct in6_addr *addrs = (struct in6_addr *)(rndsopt + 1);
        for (int i = 0; i < numaddrs; i++) {
            inet_ntop(AF_INET6, addrs + i, g_DhcpIpv6Info.dnsAddr, DHCP_INET6_ADDRSTRLEN);
            break;
        }
        LOGI("onIpv6DnsAddEvent addr: %{public}s", g_DhcpIpv6Info.dnsAddr);
    } while (false);
    checkBroadIPV6Result();
}

static int32_t createKernelSocket(void)
{
    int32_t sz = KERNEL_BUFF_SIZE;
    int32_t on = 1;
    int32_t sockFd = socket(AF_NETLINK, SOCK_RAW, 0);
    if (sockFd < 0) {
        LOGE("dhcp6 create socket failed.");
        return -1;
    }
    if (setsockopt(sockFd, SOL_SOCKET, SO_RCVBUFFORCE, &sz, sizeof(sz)) < 0) {
        LOGE("setsockopt socket SO_RCVBUFFORCE failed.");
        close(sockFd);
        return -1;
    }
    if (setsockopt(sockFd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz)) < 0) {
        LOGE("setsockopt socket SO_RCVBUF failed.");
        close(sockFd);
        return -1;
    }
    if (setsockopt(sockFd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) < 0) {
        LOGE("setsockopt socket SO_PASSCRED failed.");
        close(sockFd);
        return -1;
    }
    struct sockaddr saddr;
    (void)memset_s(&saddr, sizeof(saddr), 0, sizeof(saddr));
    setSocketFilter(&saddr);
    if (bind(sockFd, &saddr, sizeof(saddr)) < 0) {
        LOGE("bind kernel socket failed.");
        close(sockFd);
        return -1;
    }
    return sockFd;
}

int StartIpv6(const char *ifname)
{
    if (!ifname) {
        LOGE("StartIpv6 failed, ifname invalid.");
        return -1;
    }
    LOGI("StartIpv6 enter. %{public}s", ifname);
    if (strncpy_s(g_ifName, INFNAME_SIZE, ifname, strlen(ifname)) != EOK) {
        LOGE("StartIpv6 failed, strncpy_s faild.");
        return -1;
    }
    (void)memset_s(&g_DhcpIpv6Info, sizeof(g_DhcpIpv6Info), 0, sizeof(g_DhcpIpv6Info));
    readIPV6Address(ifname);
    if (g_DhcpIpv6Info.globalIpv6Addr[0] != '\0') {
        LOGI("StartIpv6 get an exist address.");
    }
    g_DhcpIpv6Info.status = 0;
    pthread_cond_init(&g_ipv6WaitSignal, NULL);
    pthread_mutex_init(&g_ipv6Mutex, NULL);
    g_runFlag = true;
    int32_t sockFd = createKernelSocket();
    if (sockFd < 0) {
        LOGE("StartIpv6 createKernelSocket failed.");
        g_runFlag = false;
        return -1;
    }
    uint8_t *buff = (uint8_t*)malloc(KERNEL_BUFF_SIZE * sizeof(uint8_t));
    if (buff == NULL) {
        LOGE("ipv6 malloc buff failed.");
        close(sockFd);
        g_runFlag = false;
        return -1;
    }
    
    while (g_runFlag) {
        (void)memset_s(buff, KERNEL_BUFF_SIZE * sizeof(uint8_t), 0,
            KERNEL_BUFF_SIZE * sizeof(uint8_t));
        int32_t len = recv(sockFd, buff, 8 *1024, 0);
        if (len < 0) {
            LOGE("recv kernel socket failed.");
            break;
        }
        handleKernelEvent(buff, len, onIpv6AddressAddEvent, onIpv6DnsAddEvent);
    }
    g_runFlag = false;
    free(buff);
    buff = NULL;
    return 0;
}

void *DhcpIPV6Start(void* param)
{
    if (!param) {
        LOGE("DhcpIPV6Start failed, param invalid.");
        return NULL;
    }
    int result = StartIpv6((char*)param);
    if (result < 0) {
        LOGE("dhcp6 run failed.");
    }
    return NULL;
}

void DhcpIPV6Stop(void)
{
    if (!g_runFlag || g_DhcpIpv6Info.globalIpv6Addr[0] != '\0') {
        g_runFlag = false;
        pthread_cond_destroy(&g_ipv6WaitSignal);
        pthread_mutex_destroy(&g_ipv6Mutex);
        return;
    }

    struct timespec abstime = {0};
    struct timeval now = {0};
    const long timeout = IPV6_WAIT_TIMEOUT;
    gettimeofday(&now, NULL);
    long nsec = now.tv_usec * IPV6_WAIT_THOUNSAND +
        (timeout % IPV6_WAIT_THOUNSAND) * IPV6_WAIT_USEC;
    abstime.tv_sec = now.tv_sec + nsec / IPV6_WAIT_NSEC + timeout / IPV6_WAIT_THOUNSAND;
    abstime.tv_nsec = nsec % IPV6_WAIT_NSEC;
    pthread_mutex_lock(&g_ipv6Mutex);
    if (pthread_cond_timedwait(&g_ipv6WaitSignal, &g_ipv6Mutex, &abstime) == ETIMEDOUT) {
        LOGI("g_ipv6WaitSignal, reason timeout %{public}d", (int)timeout);
    } else {
        LOGI("g_ipv6WaitSignal, is wakeup");
    }
    pthread_mutex_unlock(&g_ipv6Mutex);
    g_runFlag = false;

    pthread_cond_destroy(&g_ipv6WaitSignal);
    pthread_mutex_destroy(&g_ipv6Mutex);
}
