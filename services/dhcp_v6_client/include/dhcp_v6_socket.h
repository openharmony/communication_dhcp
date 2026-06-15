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

#ifndef DHCP_V6_SOCKET_H
#define DHCP_V6_SOCKET_H

#include <string>
#include <vector>
#include <cstdint>
#include <mutex>
#include <netinet/in.h>
#include "dhcp_v6_constants.h"

namespace OHOS {
namespace DHCP {

class DhcpV6Socket {
public:
    explicit DhcpV6Socket(const std::string& iface);
    ~DhcpV6Socket();

    /**
     * @brief Initialize DHCPv6 socket
     * @return 0 on success, negative on failure
     * @details Creates UDP socket, sets options, binds to interface and joins multicast group
     */
    int DhcpV6Init();

    /**
     * @brief Send DHCPv6 message
     * @param data Message data to send
     * @return 0 on success, negative on failure
     */
    int DhcpV6Send(const std::vector<uint8_t>& data);

    /**
     * @brief Receive DHCPv6 message
     * @param data Output buffer for received data
     * @param timeoutMs Receive timeout in milliseconds
     * @return 0 on success, SOCK_RECV_TIMEOUT on timeout, negative on error
     */
    int DhcpV6Receive(std::vector<uint8_t>& data, int timeoutMs = DHCPV6_DEFAULT_RECV_TIMEOUT_MS);

    /**
     * @brief Close socket and release resources
     */
    void Close();

private:
    /**
     * @brief Create IPv6 UDP socket
     * @return Socket fd on success, negative on failure
     */
    int CreateUdpSocket();

    /**
     * @brief Bind socket to interface and port
     * @param iface Interface name
     * @return 0 on success, negative on failure
     */
    int BindSocket(const std::string& iface);

    /**
     * @brief Join multicast group for server discovery
     * @param multicastAddr Multicast address
     * @return 0 on success, negative on failure
     */
    int JoinMulticastGroup(const std::string& multicastAddr);

    /**
     * @brief Set socket options (IPv6 only, multicast, etc.)
     * @return 0 on success, negative on failure
     */
    int SetSocketOptions();

    std::string iface_;         // Interface name
    int socketFd_;             // UDP socket fd for DHCPv6
    mutable std::mutex socketMutex_; // Mutex to protect socketFd_ access
    struct sockaddr_in6 serverAddr_;  // Server address (multicast)
    struct sockaddr_in6 clientAddr_;   // Client address (bound to interface)
};

} // namespace DHCP
} // namespace OHOS

#endif // DHCP_V6_SOCKET_H
