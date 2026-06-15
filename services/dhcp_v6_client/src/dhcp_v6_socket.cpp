/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "dhcp_v6_socket.h"
#include "dhcp_v6_constants.h"
#include "dhcp_common_utils.h"
#include "dhcp_logger.h"
#include <unistd.h>
#include <cstring>
#include <securec.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <cerrno>
#include <sys/time.h>

DEFINE_DHCPLOG_DHCP_LABEL("DhcpV6Socket");

namespace OHOS {
namespace DHCP {

const std::string MULTICAST_RELAY_AGENTS_AND_SERVERS = "ff02::1:2";

DhcpV6Socket::DhcpV6Socket(const std::string& iface) : iface_(iface), socketFd_(-1)
{
    errno_t err = memset_s(&serverAddr_, sizeof(serverAddr_), 0, sizeof(serverAddr_));
    if (err != EOK) {
        DHCP_LOGE("memset_s serverAddr_ failed, err=%{public}d", err);
    }
    err = memset_s(&clientAddr_, sizeof(clientAddr_), 0, sizeof(clientAddr_));
    if (err != EOK) {
        DHCP_LOGE("memset_s clientAddr_ failed, err=%{public}d", err);
    }
}

DhcpV6Socket::~DhcpV6Socket()
{
    Close();
}

int DhcpV6Socket::DhcpV6Init()
{
    socketFd_ = CreateUdpSocket();
    if (socketFd_ < 0) {
        DHCP_LOGE("Failed to create UDP socket");
        return ERR_GENERIC;
    }

    if (SetSocketOptions() < 0) {
        DHCP_LOGE("Failed to set socket options");
        Close();
        return ERR_GENERIC;
    }

    if (BindSocket(iface_) < 0) {
        DHCP_LOGE("Failed to bind socket");
        Close();
        return ERR_GENERIC;
    }

    if (JoinMulticastGroup(MULTICAST_RELAY_AGENTS_AND_SERVERS) < 0) {
        DHCP_LOGE("Failed to join multicast group");
        Close();
        return ERR_GENERIC;
    }

    DHCP_LOGI("[DHCPv6] Socket init OK for interface:%{public}s fd:%{public}d",
        iface_.c_str(), socketFd_);
    return 0;
}

int DhcpV6Socket::DhcpV6Send(const std::vector<uint8_t>& data)
{
    int fd;
    {
        std::lock_guard<std::mutex> lock(socketMutex_);
        if (socketFd_ < 0) {
            return ERR_GENERIC;
        }
        fd = socketFd_;
    }

    serverAddr_.sin6_family = AF_INET6;
    serverAddr_.sin6_port = htons(DHCPV6_SERVER_PORT);
    if (inet_pton(AF_INET6, MULTICAST_RELAY_AGENTS_AND_SERVERS.c_str(), &serverAddr_.sin6_addr) != 1) {
        DHCP_LOGE("Failed to convert multicast address: %{public}s",
            MULTICAST_RELAY_AGENTS_AND_SERVERS.c_str());
        return ERR_GENERIC;
    }
    serverAddr_.sin6_scope_id = clientAddr_.sin6_scope_id;

    ssize_t sent = sendto(fd, data.data(), data.size(), 0,
        reinterpret_cast<sockaddr*>(&serverAddr_), sizeof(serverAddr_));
    if (sent < 0) {
        DHCP_LOGE("Failed to send message: %{public}s", strerror(errno));
        return ERR_GENERIC;
    }

    if (sent != static_cast<ssize_t>(data.size())) {
        DHCP_LOGE("Partial send: %{public}zd of %{public}zu bytes",
            sent, data.size());
        return ERR_GENERIC;
    }

    DHCP_LOGI("[DHCPv6] DhcpV6Send bytes:%{public}d", static_cast<int>(sent));
    return 0;
}

int DhcpV6Socket::DhcpV6Receive(std::vector<uint8_t>& data, int timeoutMs)
{
    int fd;
    {
        std::lock_guard<std::mutex> lock(socketMutex_);
        if (socketFd_ < 0) {
            return ERR_GENERIC;
        }
        fd = socketFd_;
    }

    struct timeval tv;
    tv.tv_sec = timeoutMs / MS_PER_SECOND;
    tv.tv_usec = (timeoutMs % MS_PER_SECOND) * MS_PER_SECOND;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        DHCP_LOGW("[DHCPv6] Failed to set receive timeout: %{public}s", strerror(errno));
    }

    uint8_t buffer[DHCPV6_RECV_BUFFER_SIZE];
    struct sockaddr_in6 senderAddr;
    socklen_t senderAddrLen = sizeof(senderAddr);

    ssize_t received = recvfrom(fd, buffer, DHCPV6_RECV_BUFFER_SIZE, 0,
        reinterpret_cast<sockaddr*>(&senderAddr), &senderAddrLen);
    if (received < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            return SOCK_RECV_TIMEOUT;
        }
        DHCP_LOGE("[DHCPv6] DhcpV6Receive failed errno:%{public}d (%{public}s)",
            errno, strerror(errno));
        return ERR_GENERIC;
    }

    // RFC 3315: Servers send from DHCPV6_SERVER_PORT (547)
    if (senderAddr.sin6_port != htons(DHCPV6_SERVER_PORT)) {
        DHCP_LOGW("[DHCPv6] DhcpV6Receive: invalid source port %{public}d, expected %{public}d",
            ntohs(senderAddr.sin6_port), DHCPV6_SERVER_PORT);
        return ERR_GENERIC;
    }

    data.assign(buffer, buffer + received);
    DHCP_LOGI("[DHCPv6] DhcpV6Receive bytes:%{public}d", static_cast<int>(received));
    return 0;
}

void DhcpV6Socket::Close()
{
    std::lock_guard<std::mutex> lock(socketMutex_);
    if (socketFd_ >= 0) {
        shutdown(socketFd_, SHUT_RDWR);
        close(socketFd_);
        socketFd_ = -1;
    }
}

int DhcpV6Socket::CreateUdpSocket()
{
    int sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        DHCP_LOGE("Failed to create IPv6 UDP socket: %{public}s", strerror(errno));
        return ERR_GENERIC;
    }

    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        DHCP_LOGE("Failed to set SO_REUSEADDR: %{public}s", strerror(errno));
        close(sock);
        return ERR_GENERIC;
    }

    DHCP_LOGI("[DHCPv6] CreateUdpSocket: socket created fd=%{public}d", sock);
    return sock;
}

int DhcpV6Socket::BindSocket(const std::string& iface)
{
    unsigned int ifIndex = if_nametoindex(iface.c_str());
    if (ifIndex == 0) {
        DHCP_LOGE("Failed to get interface index for %{public}s", iface.c_str());
        return ERR_GENERIC;
    }

    errno_t err = memset_s(&clientAddr_, sizeof(clientAddr_), 0, sizeof(clientAddr_));
    if (err != EOK) {
        DHCP_LOGE("memset_s clientAddr_ failed, err=%{public}d", err);
        return ERR_GENERIC;
    }
    clientAddr_.sin6_family = AF_INET6;
    clientAddr_.sin6_port = htons(DHCPV6_CLIENT_PORT);
    clientAddr_.sin6_scope_id = ifIndex;
    clientAddr_.sin6_addr = in6addr_any;

    if (bind(socketFd_, reinterpret_cast<sockaddr*>(&clientAddr_), sizeof(clientAddr_)) < 0) {
        DHCP_LOGE("Failed to bind socket: %{public}s", strerror(errno));
        return ERR_GENERIC;
    }

    DHCP_LOGI("[DHCPv6] Bound socket to port %{public}d on interface %{public}s",
        DHCPV6_CLIENT_PORT, iface.c_str());
    return 0;
}

int DhcpV6Socket::JoinMulticastGroup(const std::string& multicastAddr)
{
    struct ipv6_mreq mreq;

    if (inet_pton(AF_INET6, multicastAddr.c_str(), &mreq.ipv6mr_multiaddr) != 1) {
        DHCP_LOGE("Invalid multicast address: %{public}s", Ipv6Anonymize(multicastAddr).c_str());
        return ERR_GENERIC;
    }

    mreq.ipv6mr_interface = clientAddr_.sin6_scope_id;

    if (setsockopt(socketFd_, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0) {
        DHCP_LOGE("Failed to join multicast group: %{public}s", strerror(errno));
        return ERR_GENERIC;
    }

    DHCP_LOGI("[DHCPv6] Joined multicast group %{public}s on ifindex:%{public}u",
        multicastAddr.c_str(), mreq.ipv6mr_interface);
    return 0;
}

int DhcpV6Socket::SetSocketOptions()
{
    int ipv6Only = 1;
    if (setsockopt(socketFd_, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6Only, sizeof(ipv6Only)) < 0) {
        DHCP_LOGE("Failed to set IPV6_V6ONLY, errno:%{public}d (%{public}s)", errno, strerror(errno));
        return ERR_GENERIC;
    }

    int hopLimit = DEFAULT_MULTICAST_HOP_LIMIT;
    if (setsockopt(socketFd_, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hopLimit, sizeof(hopLimit)) < 0) {
        DHCP_LOGW("[DHCPv6] Failed to set multicast hop limit, errno:%{public}d (%{public}s)",
            errno, strerror(errno));
    }

    int loopback = 1;
    if (setsockopt(socketFd_, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loopback, sizeof(loopback)) < 0) {
        DHCP_LOGW("[DHCPv6] Failed to set multicast loopback, errno:%{public}d (%{public}s)",
            errno, strerror(errno));
    }

    unsigned int ifIndex = if_nametoindex(iface_.c_str());
    if (ifIndex > 0) {
        if (setsockopt(socketFd_, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifIndex, sizeof(ifIndex)) < 0) {
            DHCP_LOGW("[DHCPv6] Failed to set IPV6_MULTICAST_IF, errno:%{public}d (%{public}s)",
                errno, strerror(errno));
        } else {
            DHCP_LOGI("[DHCPv6] Set IPV6_MULTICAST_IF ifindex:%{public}u for %{public}s",
                ifIndex, iface_.c_str());
        }
    }

    return 0;
}

} // namespace DHCP
} // namespace OHOS