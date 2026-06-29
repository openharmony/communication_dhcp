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

#ifndef DHCP_V6_MESSAGE_H
#define DHCP_V6_MESSAGE_H

#include <vector>
#include <cstdint>
#include <string>

namespace OHOS {
namespace DHCP {

// DHCPv6 Message Types (RFC 8415)
enum DhcpV6MessageType {
    SOLICIT = 1,
    ADVERTISE = 2,
    REQUEST = 3,
    CONFIRM = 4,
    RENEW = 5,
    REBIND = 6,
    REPLY = 7,
    RELEASE = 8,
    DECLINE = 9,
    RECONFIGURE = 10,
    INFORMATION_REQUEST = 11,
    RELAY_FORW = 12,
    RELAY_REPL = 13
};

// DHCPv6 Option Codes (RFC 8415)
enum DhcpV6OptionCode {
    OPTION_CLIENTID = 1,
    OPTION_SERVERID = 2,
    OPTION_IA_NA = 3,
    OPTION_IA_TA = 4,
    OPTION_IAADDR = 5,
    OPTION_ORO = 6,
    OPTION_PREFERENCE = 7,
    OPTION_ELAPSED_TIME = 8,
    OPTION_RELAY_MSG = 9,
    OPTION_AUTH = 11,
    OPTION_UNICAST = 12,
    OPTION_STATUS_CODE = 13,
    OPTION_RAPID_COMMIT = 14,
    OPTION_USER_CLASS = 15,
    OPTION_VENDOR_CLASS = 16,
    OPTION_VENDOR_OPTS = 17,
    OPTION_INTERFACE_ID = 18,
    OPTION_RECONF_MSG = 19,
    OPTION_RECONF_ACCEPT = 20,
    OPTION_DNS_SERVERS = 23,
    OPTION_DOMAIN_LIST = 24,
    OPTION_IA_PD = 25,
    OPTION_IAPREFIX = 26,
    OPTION_NIS_SERVERS = 27,
    OPTION_NISP_SERVERS = 28,
    OPTION_NIS_DOMAIN_NAME = 29,
    OPTION_NISP_DOMAIN_NAME = 30,
    OPTION_SNTP_SERVERS = 31,
    OPTION_INFORMATION_REFRESH_TIME = 32,
    OPTION_BCMCS_SERVER_D = 33,
    OPTION_BCMCS_SERVER_A = 34,
    OPTION_GEOCONF_CIVIC = 36,
    OPTION_REMOTE_ID = 37,
    OPTION_SUBSCRIBER_ID = 38,
    OPTION_CLIENT_FQDN = 39,
    OPTION_PANA_AGENT = 40,
    OPTION_NEW_POSIX_TIMEZONE = 41,
    OPTION_NEW_TZDB_TIMEZONE = 42,
    OPTION_ERO = 43,
    OPTION_LQ_QUERY = 44,
    OPTION_CLIENT_DATA = 45,
    OPTION_CLT_TIME = 46,
    OPTION_LQ_RELAY_DATA = 47,
    OPTION_LQ_CLIENT_LINK = 48
};

// Status Codes
enum DhcpV6StatusCode {
    STATUS_SUCCESS = 0,
    STATUS_UNSPEC_FAIL = 1,
    STATUS_NO_ADDRS_AVAIL = 2,
    STATUS_NO_BINDING = 3,
    STATUS_NOT_ON_LINK = 4,
    STATUS_USE_MULTICAST = 5,
    STATUS_NO_PREFIX_AVAIL = 6
};

struct DhcpV6Config {
    std::string clientId;
    std::string serverId;
    uint32_t transactionId = 0;
    std::vector<uint16_t> requestedOptions;
    bool stateless {false}; // true: Information-Request; false: Solicit/Request (IA_NA)
    // Fields for Renew/Rebind (RFC 8415 Section 18.10.3/18.10.4)
    std::vector<std::string> ipv6Addresses;
    uint32_t preferredLifetime {0};
    uint32_t validLifetime {0};
};

struct DhcpV6Advertise {
    std::string serverId;
    uint8_t preference = 0;
    std::vector<std::string> ipv6Addresses;
    uint32_t iaid {0};
    uint32_t t1 {0};
    uint32_t t2 {0};
    uint32_t preferredLifetime {0};
    uint32_t validLifetime {0};
    std::vector<std::string> dnsServers;
    uint16_t statusCode {STATUS_SUCCESS};
    std::string statusMessage;
};

struct DhcpV6Option {
    uint16_t code;
    uint16_t length;
    std::vector<uint8_t> data;
};

struct DhcpV6MessageInfo {
    uint8_t msgType;
    uint32_t transactionId;  // 24-bit, stored in 32-bit for convenience
    std::vector<DhcpV6Option> options;
};

class DhcpV6Message {
public:
    // Message building functions (client -> server)
    static std::vector<uint8_t> BuildSolicitMessage(const DhcpV6Config& config);  // Build Solicit message
    static std::vector<uint8_t> BuildRequestMessage(const DhcpV6Config& config,
        const DhcpV6Advertise& advertise);  // Build Request message after receiving Advertise
    static std::vector<uint8_t> BuildRenewMessage(const DhcpV6Config& config);  // Build Renew message (T1 timeout)
    static std::vector<uint8_t> BuildRebindMessage(const DhcpV6Config& config); // Build Rebind message (T2 timeout)
    static std::vector<uint8_t> BuildReleaseMessage(const DhcpV6Config& config); // Build Release message (stop)
    static std::vector<uint8_t> BuildDeclineMessage(const DhcpV6Config& config,
        const std::vector<std::string>& declinedAddrs); // Build Decline message (DAD conflict)
    static std::vector<uint8_t> BuildInformationRequestMessage(const DhcpV6Config& config);

    // Message parsing functions (server -> client)
    static bool ParseV6Message(const std::vector<uint8_t>& data, DhcpV6MessageInfo& message);
    static bool ParseV6Advertise(const std::vector<uint8_t>& data, DhcpV6Advertise& advertise);
    static bool ParseV6Reply(const std::vector<uint8_t>& data, DhcpV6Advertise& reply); // Parse Reply message

    // Option building functions
    static DhcpV6Option BuildClientIdOption(const std::string& duid); // Build Client Identifier option
    static DhcpV6Option BuildServerIdOption(const std::string& duid); // Build Server Identifier option
    static DhcpV6Option BuildIaNaOption(uint32_t iaid, uint32_t t1, uint32_t t2);
    static DhcpV6Option BuildIaNaOptionWithAddresses(uint32_t iaid, uint32_t t1, uint32_t t2,
        const std::vector<std::string>& addresses, uint32_t preferredLifetime,
        uint32_t validLifetime); // Build IA_NA option with addresses (for Renew/Rebind)
    static DhcpV6Option BuildIaAddrOption(const std::string& ipv6Addr,
        uint32_t preferredLifetime, uint32_t validLifetime); // Build IA Address option
    static DhcpV6Option BuildElapsedTimeOption(uint16_t elapsedTime); // Build Elapsed Time option
    static DhcpV6Option BuildOptionRequestOption(const std::vector<uint16_t>& optionCodes);

    // Option parsing functions
    static bool ParseClientIdOption(const DhcpV6Option& option, std::string& duid); // Parse Client Identifier option
    static bool ParseServerIdOption(const DhcpV6Option& option, std::string& duid); // Parse Server Identifier option
    static bool ParseIaAddrOption(const DhcpV6Option& option,
        std::string& ipv6Addr, uint32_t& preferredLifetime, uint32_t& validLifetime); // Parse IA Address option
    static bool ParseDnsServersOption(const DhcpV6Option& option,
        std::vector<std::string>& dnsServers); // Parse DNS Servers option
    static bool ParseStatusCodeOption(const DhcpV6Option& option,
        uint16_t& statusCode, std::string& statusMessage); // Parse Status Code option
    static bool ParseIaNaOption(const DhcpV6Option& option,
        DhcpV6Advertise& adv); // Parse IA_NA option
    static bool ParseIaNaSubOptions(const std::vector<uint8_t>& data,
        DhcpV6Advertise& adv); // Parse IA_NA sub-options (IAADDR)

    // Utility functions
    static uint32_t GenerateTransactionId(); // Generate random 24-bit transaction ID
    static std::string GenerateDuid(const std::string& iface = ""); // Generate DUID-LL based on interface MAC
    static const char* GetMsgTypeName(uint8_t msgType)
    {
        switch (msgType) {
            case SOLICIT: return "SOLICIT";
            case ADVERTISE: return "ADVERTISE";
            case REQUEST: return "REQUEST";
            case CONFIRM: return "CONFIRM";
            case RENEW: return "RENEW";
            case REBIND: return "REBIND";
            case REPLY: return "REPLY";
            case RELEASE: return "RELEASE";
            case DECLINE: return "DECLINE";
            case RECONFIGURE: return "RECONFIGURE";
            case INFORMATION_REQUEST: return "INFORMATION_REQUEST";
            case RELAY_FORW: return "RELAY_FORW";
            case RELAY_REPL: return "RELAY_REPL";
            default: return "UNKNOWN";
        }
    }

private:
    static void UpdateMinLifetime(uint32_t& current, uint32_t candidate); // Update minimum lifetime
    static std::vector<uint8_t> BuildMessage(uint8_t msgType,
        uint32_t transactionId, const std::vector<DhcpV6Option>& options); // Internal message builder
};

} // namespace DHCP
} // namespace OHOS

#endif // DHCP_V6_MESSAGE_H