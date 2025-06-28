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
#include <csignal>
#include <pthread.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstdio>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <net/if.h>
#include <errno.h>
#include <fstream>
#include <thread>
#include "securec.h"
#include "dhcp_logger.h"
#include "dhcp_ipv6_client.h"
#include "dhcp_result.h"
#include "dhcp_thread.h"
#include "dhcp_function.h"
#include "dhcp_common_utils.h"

namespace OHOS {
namespace DHCP {
const char *DEFAULT_ROUTE = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
const std::string IPV6_ACCEPT_RA_CONFIG_PATH = "/proc/sys/net/ipv6/conf/";
const std::string ACCEPT_RA = "accept_ra";
const std::string ACCEPT_OVERRULE_FORWORGING = "2";
const int INDEX0 = 0;
const int INDEX1 = 1;
const int INDEX2 = 2;
const int INDEX3 = 3;
const int INDEX4 = 4;
const int INDEX5 = 5;
const int INDEX6 = 6;
const int INDEX7 = 7;
#ifndef ND_OPT_RDNSS
#define ND_OPT_RDNSS 25
struct nd_opt_rdnss {
    uint8_t nd_opt_rdnss_type;
    uint8_t nd_opt_rdnss_len;
    uint16_t nd_opt_rdnss_reserved;
    uint32_t nd_opt_rdnss_lifetime;
} _packed;
#endif
DEFINE_DHCPLOG_DHCP_LABEL("DhcpIpv6Client");
DhcpIpv6Client::DhcpIpv6Client(std::string ifname) : interfaceName(ifname)
{
    dhcpIpv6DnsRepository_ = std::make_unique<DnsServerRepository>();
    DHCP_LOGI("DhcpIpv6Client()");
}

DhcpIpv6Client::~DhcpIpv6Client()
{
    DHCP_LOGI("~DhcpIpv6Client()");
    if (dhcpIpv6DnsRepository_ != nullptr) {
        dhcpIpv6DnsRepository_.reset();
    }
}

bool DhcpIpv6Client::IsRunning()
{
    DHCP_LOGI("IsRunning()");
    return runFlag_.load();
}
void DhcpIpv6Client::SetCallback(std::function<void(const std::string ifname, DhcpIpv6Info &info)> callback)
{
    DHCP_LOGI("SetCallback()");
    std::lock_guard<std::mutex> lock(ipv6CallbackMutex_);
    onIpv6AddressChanged_ = callback;
}

void DhcpIpv6Client::RunIpv6ThreadFunc()
{
    pthread_setname_np(pthread_self(), "ipv6NetlinkThread");
    DhcpIpv6Start();
}

int DhcpIpv6Client::StartIpv6Thread(const std::string &ifname, bool isIpv6)
{
    DHCP_LOGI("StartIpv6Thread ifname:%{public}s bIpv6:%{public}d,runFlag:%{public}d", ifname.c_str(), isIpv6,
        runFlag_.load());

    if (!runFlag_.load()) {
        runFlag_ = true;
        interfaceName = ifname;
        if (ipv6Thread_ == nullptr) {
            ipv6Thread_ = std::make_unique<std::thread>(&DhcpIpv6Client::RunIpv6ThreadFunc, this);
        }
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

int DhcpIpv6Client::GetAddrType(const struct in6_addr *addr)
{
    if (!addr) {
        DHCP_LOGE("GetAddrType failed, data invalid.");
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

int DhcpIpv6Client::GetAddrScope(void *addr)
{
    if (!addr) {
        DHCP_LOGE("GetAddrType failed, data invalid.");
        return IPV6_ADDR_LINKLOCAL;
    }
    in6_addr *ipv6Addr = reinterpret_cast<in6_addr *>(addr);
    return static_cast<unsigned int>(GetAddrType(ipv6Addr)) & IPV6_ADDR_SCOPE_MASK;
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
    if (family != AF_INET6) {
        DHCP_LOGE("GetIpFromS6Address family failed");
        return -1;
    }
    if (!inet_ntop(family, (struct in6_addr*)addr, buf, buflen)) {
        DHCP_LOGE("GetIpFromS6Address failed");
        return -1;
    }
    return 0;
}

void DhcpIpv6Client::OnIpv6AddressUpdateEvent(char *addr, int addrlen, int prefixLen,
                                              int ifaIndex, int scope, bool isUpdate)
{
    int currIndex = static_cast<int>(if_nametoindex(interfaceName.c_str()));
    if (currIndex != ifaIndex) {
        DHCP_LOGE("address ifaindex invalid, %{public}d != %{public}d", currIndex, ifaIndex);
        return;
    }
    if (!addr) {
        DHCP_LOGE("OnIpv6AddressUpdateEvent failed, data invalid.");
        return;
    }
    AddrType type = AddrType::UNKNOW;
    if (scope == 0) {
        getIpv6RouteAddr();
        if (memset_s(dhcpIpv6Info.ipv6SubnetAddr, DHCP_INET6_ADDRSTRLEN,
            0, DHCP_INET6_ADDRSTRLEN) != EOK) {
            DHCP_LOGE("OnIpv6AddressUpdateEvent memset_s failed");
            return;
        }
        dhcpIpv6Info.status |= 1;
        GetIpv6Prefix(DEFAULT_ROUTE, dhcpIpv6Info.ipv6SubnetAddr, prefixLen);
        DHCP_LOGD("OnIpv6AddressUpdateEvent addr:%{private}s, subaddr:%{public}s, route:%{public}s, scope:%{public}d",
            addr, dhcpIpv6Info.ipv6SubnetAddr, dhcpIpv6Info.routeAddr, scope);
        type = AddIpv6Address(addr, INET6_ADDRSTRLEN);
    } else if (scope == IPV6_ADDR_LINKLOCAL) {
        type = AddrType::DEFAULT;
    } else {
        DHCP_LOGD("OnIpv6AddressUpdateEvent other scope:%{public}d", scope);
    }
    if (type == AddrType::UNKNOW) {
        return;
    }

    if (isUpdate ? DhcpIpv6InfoManager::UpdateAddr(dhcpIpv6Info, std::string(addr), type) :
        DhcpIpv6InfoManager::RemoveAddr(dhcpIpv6Info, std::string(addr))) {
        PublishIpv6Result();
    }
}

AddrType DhcpIpv6Client::AddIpv6Address(char *ipv6addr, int len)
{
    AddrType type = AddrType::UNKNOW;
    if (!ipv6addr) {
        DHCP_LOGE("AddIpv6Address ipv6addr is nullptr!");
        return type;
    }
    // get the local interface index and MAC address
    int ifaceIndex = 0;
    unsigned char ifaceMac[MAC_ADDR_LEN];
    if (GetLocalInterface(interfaceName.c_str(), &ifaceIndex, ifaceMac, nullptr) != DHCP_OPT_SUCCESS) {
        DHCP_LOGE("GetLocalInterface failed for interface: %{public}s", interfaceName.c_str());
        return type;
    }
    if (IsGlobalIpv6Address(ipv6addr, len)) {
        if (IsEui64ModeIpv6Address(ipv6addr, len, ifaceMac, MAC_ADDR_LEN)) {
            DHCP_LOGI("AddIpv6Address add globalAddr %{public}s", Ipv6Anonymize(ipv6addr).c_str());
            type = AddrType::GLOBAL;
        }  else {
            DHCP_LOGI("AddIpv6Address add randIpv6Addr %{public}s", Ipv6Anonymize(ipv6addr).c_str());
             type = AddrType::RAND;
        }
    } else if (IsUniqueLocalIpv6Address(ipv6addr, len)) {
        if (IsEui64ModeIpv6Address(ipv6addr, len, ifaceMac, MAC_ADDR_LEN)) {
            DHCP_LOGI("AddIpv6Address add uniqueLocalAddr1 %{public}s", Ipv6Anonymize(ipv6addr).c_str());
            type = AddrType::UNIQUE;
        }  else {
            DHCP_LOGI("AddIpv6Address add uniqueLocalAddr2 %{public}s", Ipv6Anonymize(ipv6addr).c_str());
            type = AddrType::UNIQUE2;
        }
    } else {
        DHCP_LOGI("AddIpv6Address add unknow %{public}s", Ipv6Anonymize(ipv6addr).c_str());
    }
    return type;
}

bool DhcpIpv6Client::IsEui64ModeIpv6Address(const char *ipv6addr, int len, const unsigned char *ifaceMac, int macLen)
{
    if (ipv6addr == nullptr || len <= 0 || len > DHCP_INET6_ADDRSTRLEN) {
        DHCP_LOGE("Invalid input: ipv6addr is null or len is non-positive");
        return false;
    }

    if (ifaceMac == nullptr || macLen != MAC_ADDR_LEN) {
        DHCP_LOGE("Invalid input: ifaceMac is null or macLen is not equal to MAC_ADDR_LEN");
        return false;
    }

    // normalize the IPv6 address
    struct in6_addr addr;
    if (inet_pton(AF_INET6, ipv6addr, &addr) != 1) {
        DHCP_LOGE("inet_pton failed for IPv6 address: %{public}s", Ipv6Anonymize(ipv6addr).c_str());
        return false;
    }

    // get last 64 bits of the IPv6 address
    const int LEN = 8;
    uint8_t ipv6Iid[LEN];
    if (memcpy_s(ipv6Iid, LEN, &addr.s6_addr[LEN], LEN) != EOK) {
        DHCP_LOGE("Failed to copy last 64 bits of IPv6 address: %{public}s", Ipv6Anonymize(ipv6addr).c_str());
        return false;
    }

    // check for EMU-64 format:
    const uint8_t EUI64_BIT_3ST = 0xFF;
    const uint8_t EUI64_BIT_4TH = 0XFE;
    if (ipv6Iid[INDEX3] != EUI64_BIT_3ST || ipv6Iid[INDEX4] != EUI64_BIT_4TH) {
        // EUI-64 format requires the IID to contain FF:FE at the 4th and 5th bytes
        DHCP_LOGE("IPv6 address %{public}s is not in EUI-64 format", Ipv6Anonymize(ipv6addr).c_str());
        return false;
    }

    // reconstruct the MAC address from the IPv6 IID
    uint8_t reconstructedMac[MAC_ADDR_LEN] = {0};
    const uint8_t U_L_BIT = 0x02;
    reconstructedMac[INDEX0] = ipv6Iid[INDEX0] ^ U_L_BIT; // 反转U/L位
    reconstructedMac[INDEX1] = ipv6Iid[INDEX1];
    reconstructedMac[INDEX2] = ipv6Iid[INDEX2];
    reconstructedMac[INDEX3] = ipv6Iid[INDEX5];
    reconstructedMac[INDEX4] = ipv6Iid[INDEX6];
    reconstructedMac[INDEX5] = ipv6Iid[INDEX7];

    // compare the reconstructed MAC address with the interface MAC address
    bool isMatch = (memcmp(ifaceMac, reconstructedMac, MAC_ADDR_LEN) == 0);

    DHCP_LOGI("IsEui64ModeIpv6Address EUI-64 check for %{public}s  %{public}s",
              Ipv6Anonymize(ipv6addr).c_str(), isMatch ? "match" : "mismatch");
    return isMatch;
}

void DhcpIpv6Client::onIpv6DnsAddEvent(void* data, int len, int ifaIndex)
{
    int currIndex = static_cast<int>(if_nametoindex(interfaceName.c_str()));
    if (currIndex != ifaIndex) {
        DHCP_LOGE("dnsevent ifaindex invalid, %{public}d != %{public}d", currIndex, ifaIndex);
        return;
    }
    dhcpIpv6Info.status |= (1 << 1);
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
        DHCP_LOGE("dns nd_opt_type invalid:%{public}d", opthdr->nd_opt_type);
        return;
    }
    if ((optlen < ND_OPT_MIN_LEN) || !(optlen & 0x1)) {
        DHCP_LOGE("dns optLen invalid:%{public}d", optlen);
        return;
    }
    int numaddrs = (optlen - 1) / 2;
    struct nd_opt_rdnss *rndsopt = (struct nd_opt_rdnss *)opthdr;
    //RDNSS Lifetime
    const uint32_t lifetime = ntohl(rndsopt->nd_opt_rdnss_lifetime);
    DHCP_LOGI("dns opt lifetime %{public}u", lifetime);
    struct in6_addr *addrs = (struct in6_addr *)(rndsopt + 1);
    std::vector<std::string> dnsAddrVector;
    for (int i = 0; i < numaddrs; i++) {
        char dnsAddr[DHCP_INET6_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET6, addrs + i, dnsAddr, DHCP_INET6_ADDRSTRLEN);
        dnsAddrVector.push_back(dnsAddr);

    }
    bool changed = dhcpIpv6DnsRepository_->AddServers(lifetime, dnsAddrVector);
    if (changed) {
        DHCP_LOGI("onIpv6DnsAddEvent dns servers changed");
        dhcpIpv6DnsRepository_->SetCurrentServers(dhcpIpv6Info);
        dhcpIpv6Info.lifetime = lifetime;
        PublishIpv6Result();
    }
}

void DhcpIpv6Client::OnIpv6RouteUpdateEvent(char* gateway, char* dst, int ifaIndex, bool isAdd)
{
    int currIndex = static_cast<int>(if_nametoindex(interfaceName.c_str()));
    if (currIndex != ifaIndex) {
        DHCP_LOGE("route ifaindex invalid, %{public}d != %{public}d", currIndex, ifaIndex);
        return;
    }
    DHCP_LOGI("OnIpv6RouteUpdateEvent gateway:%{private}s, dst:%{private}s, ifindex:%{public}d isAdd: %{public}d",
        gateway, dst, ifaIndex, isAdd ? 1:0);
    if (!gateway || !dst) {
        DHCP_LOGE("OnIpv6RouteUpdateEvent input invalid.");
        return;
    }
    bool isChanged = false;
    if (strlen(dst) == 0 && strlen(gateway) != 0) {
        if (isAdd) {
            isChanged = DhcpIpv6InfoManager::AddRoute(dhcpIpv6Info, std::string(gateway));
        } else {
            isChanged = DhcpIpv6InfoManager::RemoveRoute(dhcpIpv6Info, std::string(gateway));
        }
    }
    if (isChanged) {
        PublishIpv6Result();
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
    dhcpIpv6Info.Clear();
    dhcpIpv6DnsRepository_->Clear();
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
    Reset();
    ipv6SocketFd = createKernelSocket();
    if (ipv6SocketFd < 0) {
        runFlag_ = false;
        DHCP_LOGE("StartIpv6 ipv6SocketFd < 0 failed!");
        return -1;
    }
    uint8_t *buff = (uint8_t*)malloc(KERNEL_BUFF_SIZE * sizeof(uint8_t));
    if (buff == NULL) {
        DHCP_LOGE("StartIpv6 ipv6 malloc buff failed.");
        close(ipv6SocketFd);
        runFlag_ = false;
        return -1;
    }
    struct timeval timeout = {0};
    fd_set rSet;
    timeout.tv_sec = 0;
    timeout.tv_usec = SELECT_TIMEOUT_US;
    while (runFlag_.load()) {
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
            DHCP_LOGE("StartIpv6 recv kernel socket failed %{public}d.", errno);
            sleep(1);
            continue;
        } else if (len == 0) {
            continue;
        }
        handleKernelEvent(buff, len);
    }
    close(ipv6SocketFd);
    ipv6SocketFd = 0;
    free(buff);
    buff = NULL;
    DHCP_LOGI("DhcpIpv6Client thread exit.");
    return 0;
}

void *DhcpIpv6Client::DhcpIpv6Start()
{
    SetAcceptRa(ACCEPT_OVERRULE_FORWORGING);
    int result = StartIpv6();
    if (result < 0) {
        DHCP_LOGE("dhcp6 run failed.");
    }
    return NULL;
}

void DhcpIpv6Client::SetAcceptRa(const std::string &content)
{
    std::string fileName = IPV6_ACCEPT_RA_CONFIG_PATH + interfaceName + '/' + ACCEPT_RA;
    if (!IsValidPath(fileName)) {
        DHCP_LOGE("invalid path:%{public}s", fileName.c_str());
        return;
    }
    std::ofstream outf(fileName, std::ios::out);
    if (!outf) {
        DHCP_LOGE("SetAcceptRa, write content [%{public}s] to file [%{public}s] failed. error: %{public}d.",
            content.c_str(), fileName.c_str(), errno);
        return;
    }
    outf.write(content.c_str(), content.length());
    outf.close();
    DHCP_LOGI("SetAcceptRa, write content [%{public}s] to file [%{public}s] success.",
        content.c_str(), fileName.c_str());
}

void DhcpIpv6Client::PublishIpv6Result()
{
    std::lock_guard<std::mutex> lock(ipv6CallbackMutex_);
    if (onIpv6AddressChanged_ != nullptr) {
        onIpv6AddressChanged_(interfaceName, dhcpIpv6Info);
    }
}

void DhcpIpv6Client::DhcpIPV6Stop(void)
{
    DHCP_LOGI("DhcpIPV6Stop exit ipv6 thread, runFlag:%{public}d", runFlag_.load());
    if (!runFlag_.load()) {
        return;
    }
    runFlag_ = false;
    if (ipv6Thread_ && ipv6Thread_->joinable()) {
         ipv6Thread_->join();
         ipv6Thread_ = nullptr;
     }
    std::lock_guard<std::mutex> lock(ipv6CallbackMutex_);
    onIpv6AddressChanged_ = nullptr;
}

bool DhcpIpv6Client::IsGlobalIpv6Address(const char *ipv6addr, int len)
{
    if (ipv6addr == nullptr || len <= 0 || len > DHCP_INET6_ADDRSTRLEN) {
        DHCP_LOGE("IsGlobalIpv6Address ipv6addr is nullptr or len invalid!");
        return false;
    }
    struct in6_addr addr = IN6ADDR_ANY_INIT;
    if (inet_pton(AF_INET6, ipv6addr, &addr) != 1) {
        DHCP_LOGE("inet_pton failed for ipv6addr:%{public}s", Ipv6Anonymize(ipv6addr).c_str());
        return false;
    }

    // 2001:db8::/32 is documentation address, not global
    const uint8_t docAddrPrefix[4] = {0x20, 0x01, 0x0d, 0xb8};
    // Check if the first 4 bytes match the documentation address prefix
    if (memcmp(addr.s6_addr, docAddrPrefix, sizeof(docAddrPrefix)) == 0) {
        DHCP_LOGI("IsGlobalIpv6Address addr is documentation address.");
        return false;
    }
    const uint8_t globalUnicastPrefix = 0x20;
    const uint8_t mask =  0xE0; // 0b11100000
    // Check if the first byte matches the global unicast prefix
    // Global Unicast Address: 2000::/3 (0x20 ~ 0x3F)
    if ((addr.s6_addr[0] & mask) == globalUnicastPrefix) {
        DHCP_LOGI("IsGlobalIpv6Address addr:%{public}s is global address.", Ipv6Anonymize(ipv6addr).c_str());
        return true;
    }
    return false;
}

bool DhcpIpv6Client::IsUniqueLocalIpv6Address(const char *ipv6addr, int len)
{
    if (ipv6addr == nullptr || len <= 0 || len > DHCP_INET6_ADDRSTRLEN) {
        DHCP_LOGE("IsUniqueLocalIpv6Address ipv6addr is nullptr or len invalid!");
        return false;
    }
    struct in6_addr addr = IN6ADDR_ANY_INIT;
    if (inet_pton(AF_INET6, ipv6addr, &addr) != 1) {
        DHCP_LOGE("inet_pton failed for ipv6addr:%{public}s", Ipv6Anonymize(ipv6addr).c_str());
        return false;
    }
    // Unique Local Address: fc00::/7 (0xfc or 0xfd)
    const uint8_t uniqueLocalPrefix = 0xFC;
    const uint8_t mask = 0xFE; // 0b11111110
    if ((addr.s6_addr[0] & mask) == uniqueLocalPrefix) {
        return true;
    }
    DHCP_LOGI("IsUniqueLocalIpv6Address addr:%{public}s is not unique local address.",
        Ipv6Anonymize(ipv6addr).c_str());
    return false;
}
}  // namespace DHCP
}  // namespace OHOS