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

#ifndef DHCP_V6_CONSTANTS_H
#define DHCP_V6_CONSTANTS_H

namespace OHOS {
namespace DHCP {

// Time constants
constexpr uint32_t MS_PER_SECOND = 1000;  // Milliseconds per second
constexpr uint32_t BASE_TIMEOUT_MS = 1000; // Base timeout for DHCPv6 message exchange (1 second)
constexpr uint32_t TIMEOUT_INCREMENT_MS = 1000; // Timeout increment for each retry (1 second)
constexpr uint32_t RECV_TIMEOUT_MS = 1000; // Socket receive timeout (1 second)
constexpr uint32_t DHCPV6_DEFAULT_RECV_TIMEOUT_MS = 5000; // Default receive timeout for DHCPv6 (5 seconds)

// Retry constants
constexpr int DEFAULT_MAX_RETRIES = 3;

// Error codes (business layer, distinct from socket return values)
// Note: -1 is shared (generic error), but -2 is socket timeout only
// Socket returns: 0=success, -1=error (ERR_GENERIC), -2=timeout (SOCK_RECV_TIMEOUT, for continue)
constexpr int ERR_GENERIC = -1;           // generic error
constexpr int ERR_DAD_FAILED = -3;        // DAD (Duplicate Address Detection) failed
constexpr int ERR_LEASE_EXPIRED = -4;     // DHCPv6 lease expired
constexpr int ERR_RETRY_EXCEEDED = -5;    // retry count exceeded
constexpr int SOCK_RECV_TIMEOUT = -2;    // non-blocking socket timeout (caller should continue loop)

// Lifetime ratio constants (T2 = 80% of valid lifetime)
constexpr uint32_t T2_LIFETIME_RATIO = 80;
constexpr uint32_t LIFETIME_RATIO_BASE = 100;

// T1 calculation: T1 = validLifetime / 2
constexpr uint32_t T1_DIVISOR = 2; // T1 is calculated as validLifetime / 2

// Network constants
constexpr uint16_t DHCPV6_SERVER_PORT = 547;
constexpr uint16_t DHCPV6_CLIENT_PORT = 546;
constexpr int DEFAULT_MULTICAST_HOP_LIMIT = 255;
constexpr int DHCPV6_RECV_BUFFER_SIZE = 4096;  // receive buffer size

// Address constants
constexpr uint32_t MAX_TRANSACTION_ID = 0xFFFFFF;  // 24-bit max
constexpr uint32_t DEFAULT_IAID = 1;
constexpr uint32_t INFINITE_LIFETIME = 0xFFFFFFFF; // special value meaning infinite lease lifetime
constexpr uint8_t IPV6_PREFIX_LEN = 128;           // IPv6 prefix length for address configuration
constexpr size_t DHCPV6_MAC_LEN = 6;
constexpr size_t MAC_INDEX_0 = 0;
constexpr size_t MAC_INDEX_1 = 1;
constexpr size_t MAC_INDEX_2 = 2;
constexpr size_t MAC_INDEX_3 = 3;
constexpr size_t MAC_INDEX_4 = 4;
constexpr size_t MAC_INDEX_5 = 5;

// Option length constants
constexpr size_t IA_NA_MIN_LEN = 12;
constexpr size_t IAADDR_MIN_LEN = 24;

} // namespace DHCP
} // namespace OHOS

#endif // DHCP_V6_CONSTANTS_H