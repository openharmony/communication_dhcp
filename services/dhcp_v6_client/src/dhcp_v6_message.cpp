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

#include "dhcp_v6_message.h"
#include "dhcp_v6_constants.h"
#include "dhcp_logger.h"
#include "dhcp_common_utils.h"
#include <random>
#include <chrono>
#include <arpa/inet.h>
#include <cstring>
#include "securec.h"

namespace OHOS {
namespace DHCP {

DEFINE_DHCPLOG_DHCP_LABEL("DhcpV6Message");

// DHCPv6 message structure constants
static constexpr size_t DHCPV6_MSG_HEADER_LEN = 4;       // msgType(1) + transactionId(3)
static constexpr size_t DHCPV6_OPTION_HDR_LEN = 4;         // code(2) + length(2)
static constexpr size_t DHCPV6_IA_NA_HDR_LEN = 12;        // IAID(4) + T1(4) + T2(4)
static constexpr size_t DHCPV6_IAADDR_LEN = 24;           // IPv6 addr(16) + lifetimes(8)
static constexpr size_t DHCPV6_IPV6_ADDR_LEN = 16;        // IPv6 address size
static constexpr size_t DHCPV6_DEFAULT_IAID = 1;         // default IAID value

// 16-bit value length constants
static constexpr size_t DHCPV6_OPTION_CODE_LEN = 2;        // each option code occupies 2 bytes in ORO option
static constexpr size_t DHCPV6_ELAPSED_TIME_LEN = 2;       // elapsed time option length
static constexpr size_t DHCPV6_STATUS_CODE_HDR_LEN = 2;    // status code option header

// Index offsets for parsing options from byte arrays
static constexpr size_t DHCPV6_OPTION_CODE_OFFSET = 2;   // offset to option code in option header
static constexpr size_t DHCPV6_OPTION_CODE_SECOND_BYTE_OFFSET = 1; // second byte offset for 16-bit values
static constexpr size_t DHCPV6_OPTION_LEN_SECOND_BYTE_OFFSET = 3; // second byte offset for length field
static constexpr size_t DHCPV6_IA_NA_HDR_IAID_IDX = 0;  // IAID starts at index 0 in IA_NA header
static constexpr size_t DHCPV6_IA_NA_HDR_T1_IDX = 4;     // T1 starts at index 4 in IA_NA header
static constexpr size_t DHCPV6_IA_NA_HDR_T2_IDX = 8;     // T2 starts at index 8 in IA_NA header
static constexpr size_t DHCPV6_IAADDR_PREF_LIFETIME_IDX = DHCPV6_IPV6_ADDR_LEN;
static constexpr size_t DHCPV6_IAADDR_VALID_LIFETIME_IDX = DHCPV6_IPV6_ADDR_LEN + 4;
static constexpr size_t DHCPV6_IAADDR_LIFETIME_SECOND_BYTE_OFFSET = 1; // second byte of 32-bit lifetime
static constexpr size_t DHCPV6_IAADDR_LIFETIME_THIRD_BYTE_OFFSET = 2;  // third byte of 32-bit lifetime
static constexpr size_t DHCPV6_IAADDR_LIFETIME_FOURTH_BYTE_OFFSET = 3; // fourth byte of 32-bit lifetime

// DHCPv6 message header field offsets
static constexpr size_t DHCPV6_MSGTYPE_OFFSET = 0;       // message type is first byte
static constexpr size_t DHCPV6_TRANSACTION_ID_OFFSET = 1; // transaction ID starts at offset 1 (3 bytes)
static constexpr size_t DHCPV6_TRANSACTION_ID_SECOND_BYTE_OFFSET = 2; // second byte of transaction ID
static constexpr size_t DHCPV6_TRANSACTION_ID_THIRD_BYTE_OFFSET = 3;  // third byte of transaction ID

// Elapsed time option field offsets
static constexpr size_t DHCPV6_ELAPSED_TIME_OFFSET = 0; // elapsed time value offset

// Status code option field offsets
static constexpr size_t DHCPV6_STATUS_CODE_OFFSET = 0;   // status code offset in status option

// DUID constants
static constexpr uint8_t DUID_TYPE_LLT = 1;              // DUID-Link-Layer Address Plus Time
static constexpr uint16_t HARDWARE_TYPE_ETHERNET = 1;    // Ethernet hardware type

// Byte mask
static constexpr uint8_t BYTE_MASK = 0xFF;

// Number of bytes for parsing values
static constexpr size_t UINT32_NUM_BYTES = 4;

// Bit shift for parsing 32-bit values from byte array
static constexpr int SHIFT_8 = 8;
static constexpr int SHIFT_16 = 16;
static constexpr int SHIFT_24 = 24;

// Helper function to parse uint32 from big-endian byte array
static inline uint32_t ParseUint32FromBytes(const std::vector<uint8_t>& data, size_t offset)
{
    if (offset + UINT32_NUM_BYTES > data.size()) {
        return 0;
    }
    return (static_cast<uint32_t>(data[offset]) << SHIFT_24) |
           (static_cast<uint32_t>(data[offset + DHCPV6_IAADDR_LIFETIME_SECOND_BYTE_OFFSET]) << SHIFT_16) |
           (static_cast<uint32_t>(data[offset + DHCPV6_IAADDR_LIFETIME_THIRD_BYTE_OFFSET]) << SHIFT_8) |
           static_cast<uint32_t>(data[offset + DHCPV6_IAADDR_LIFETIME_FOURTH_BYTE_OFFSET]);
}

std::vector<uint8_t> DhcpV6Message::BuildSolicitMessage(const DhcpV6Config& config)
{
    std::vector<DhcpV6Option> options;

    options.push_back(BuildClientIdOption(config.clientId.empty() ? GenerateDuid() : config.clientId));
    options.push_back(BuildElapsedTimeOption(0));

    if (!config.stateless) {
        options.push_back(BuildIaNaOption(DHCPV6_DEFAULT_IAID, 0, 0));
    }

    std::vector<uint16_t> requestedOptions = {OPTION_DNS_SERVERS, OPTION_DOMAIN_LIST};
    options.push_back(BuildOptionRequestOption(requestedOptions));

    return BuildMessage(SOLICIT, config.transactionId ? config.transactionId : GenerateTransactionId(), options);
}

std::vector<uint8_t> DhcpV6Message::BuildRequestMessage(const DhcpV6Config& config, const DhcpV6Advertise& advertise)
{
    std::vector<DhcpV6Option> options;

    options.push_back(BuildClientIdOption(config.clientId.empty() ? GenerateDuid() : config.clientId));
    options.push_back(BuildServerIdOption(advertise.serverId));
    options.push_back(BuildElapsedTimeOption(0));
    options.push_back(BuildIaNaOptionWithAddresses(DHCPV6_DEFAULT_IAID, advertise.t1, advertise.t2,
        advertise.ipv6Addresses, advertise.preferredLifetime, advertise.validLifetime));

    std::vector<uint16_t> requestedOptions = {OPTION_DNS_SERVERS, OPTION_DOMAIN_LIST};
    options.push_back(BuildOptionRequestOption(requestedOptions));

    return BuildMessage(REQUEST, config.transactionId ? config.transactionId : GenerateTransactionId(), options);
}

std::vector<uint8_t> DhcpV6Message::BuildRenewMessage(const DhcpV6Config& config)
{
    std::vector<DhcpV6Option> options;

    options.push_back(BuildClientIdOption(config.clientId.empty() ? GenerateDuid() : config.clientId));
    options.push_back(BuildServerIdOption(config.serverId));
    options.push_back(BuildElapsedTimeOption(0));
    // RFC 8415 Section 18.10.3: Renew message MUST include IA addresses to renew
    options.push_back(BuildIaNaOptionWithAddresses(DHCPV6_DEFAULT_IAID, 0, 0,
        config.ipv6Addresses, config.preferredLifetime, config.validLifetime));

    return BuildMessage(RENEW, config.transactionId ? config.transactionId : GenerateTransactionId(), options);
}

std::vector<uint8_t> DhcpV6Message::BuildRebindMessage(const DhcpV6Config& config)
{
    std::vector<DhcpV6Option> options;
    options.push_back(BuildClientIdOption(config.clientId.empty() ? GenerateDuid() : config.clientId));
    options.push_back(BuildElapsedTimeOption(0));
    // RFC 8415 Section 18.10.4: Rebind message MUST include IA addresses to renew
    // Note: Rebind MUST NOT carry Server Identifier option
    options.push_back(BuildIaNaOptionWithAddresses(DHCPV6_DEFAULT_IAID, 0, 0,
        config.ipv6Addresses, config.preferredLifetime, config.validLifetime));
    return BuildMessage(REBIND, config.transactionId ? config.transactionId : GenerateTransactionId(), options);
}

std::vector<uint8_t> DhcpV6Message::BuildReleaseMessage(const DhcpV6Config& config)
{
    std::vector<DhcpV6Option> options;

    options.push_back(BuildClientIdOption(config.clientId.empty() ? GenerateDuid() : config.clientId));
    options.push_back(BuildServerIdOption(config.serverId));
    options.push_back(BuildIaNaOption(DHCPV6_DEFAULT_IAID, 0, 0));

    return BuildMessage(RELEASE, config.transactionId ? config.transactionId : GenerateTransactionId(), options);
}

std::vector<uint8_t> DhcpV6Message::BuildDeclineMessage(const DhcpV6Config& config,
    const std::vector<std::string>& declinedAddrs)
{
    std::vector<DhcpV6Option> options;
    options.push_back(BuildClientIdOption(config.clientId.empty() ? GenerateDuid() : config.clientId));
    options.push_back(BuildServerIdOption(config.serverId));

    DhcpV6Option iaNaOpt;
    iaNaOpt.code = OPTION_IA_NA;
    std::vector<uint8_t> iaNaData;
    // RFC 8415: IA_NA header is 12 bytes: IAID(4) + T1(4) + T2(4)
    iaNaData.push_back(0);
    iaNaData.push_back(0);
    iaNaData.push_back(0);
    iaNaData.push_back(DHCPV6_DEFAULT_IAID);
    // T1 and T2 should be 0 for Decline/Release (RFC 8415 Section 18.11 and 18.12)
    iaNaData.push_back(0);
    iaNaData.push_back(0);
    iaNaData.push_back(0);
    iaNaData.push_back(0);
    iaNaData.push_back(0);
    iaNaData.push_back(0);
    iaNaData.push_back(0);
    iaNaData.push_back(0);

    for (const auto& addr : declinedAddrs) {
        DhcpV6Option iaAddrOpt = BuildIaAddrOption(addr, 0, 0);
        uint8_t subOptCode[DHCPV6_OPTION_CODE_LEN] = {
            static_cast<uint8_t>((iaAddrOpt.code >> SHIFT_8) & BYTE_MASK),
            static_cast<uint8_t>(iaAddrOpt.code & BYTE_MASK)
        };
        uint8_t subOptLen[DHCPV6_OPTION_CODE_LEN] = {
            static_cast<uint8_t>((iaAddrOpt.length >> SHIFT_8) & BYTE_MASK),
            static_cast<uint8_t>(iaAddrOpt.length & BYTE_MASK)
        };
        iaNaData.insert(iaNaData.end(), subOptCode, subOptCode + DHCPV6_OPTION_CODE_LEN);
        iaNaData.insert(iaNaData.end(), subOptLen, subOptLen + DHCPV6_OPTION_CODE_LEN);
        iaNaData.insert(iaNaData.end(), iaAddrOpt.data.begin(), iaAddrOpt.data.end());
    }

    iaNaOpt.length = static_cast<uint16_t>(iaNaData.size());
    iaNaOpt.data = iaNaData;
    options.push_back(iaNaOpt);

    return BuildMessage(DECLINE, GenerateTransactionId(), options);
}

std::vector<uint8_t> DhcpV6Message::BuildInformationRequestMessage(const DhcpV6Config& config)
{
    std::vector<DhcpV6Option> options;
    options.push_back(BuildClientIdOption(config.clientId.empty() ? GenerateDuid() : config.clientId));
    options.push_back(BuildElapsedTimeOption(0));
    std::vector<uint16_t> requestedOptions = {OPTION_DNS_SERVERS, OPTION_DOMAIN_LIST};
    options.push_back(BuildOptionRequestOption(requestedOptions));
    uint32_t txId = config.transactionId ? config.transactionId : GenerateTransactionId();
    return BuildMessage(INFORMATION_REQUEST, txId, options);
}

bool DhcpV6Message::ParseV6Message(const std::vector<uint8_t>& data, DhcpV6MessageInfo& message)
{
    // Basic size check for message header
    if (data.size() < DHCPV6_MSG_HEADER_LEN) {
        DHCP_LOGE("[DHCPv6] ParseV6Message: data too short, size=%{public}zu, need=%{public}zu",
            data.size(), DHCPV6_MSG_HEADER_LEN);
        return false;
    }

    // Validate msgType is within valid DHCPv6 range (1-14 for client messages, 23-24 for relay)
    uint8_t msgType = data[DHCPV6_MSGTYPE_OFFSET];
    if (msgType == 0 || msgType > RELAY_REPL) {
        DHCP_LOGE("[DHCPv6] ParseV6Message: invalid msgType=%{public}u", msgType);
        return false;
    }

    message.msgType = msgType;
    message.transactionId = (data[DHCPV6_TRANSACTION_ID_OFFSET] << SHIFT_16) |
        (data[DHCPV6_TRANSACTION_ID_SECOND_BYTE_OFFSET] << SHIFT_8) |
        data[DHCPV6_TRANSACTION_ID_THIRD_BYTE_OFFSET];
    message.options.clear();

    size_t offset = DHCPV6_MSG_HEADER_LEN;
    while (offset + DHCPV6_OPTION_HDR_LEN <= data.size()) {
        DhcpV6Option option;
        option.code = (data[offset] << SHIFT_8) | data[offset + DHCPV6_OPTION_CODE_SECOND_BYTE_OFFSET];
        size_t lenOffset = offset + DHCPV6_OPTION_CODE_OFFSET;
        option.length = (data[lenOffset] << SHIFT_8) | data[lenOffset + DHCPV6_OPTION_CODE_SECOND_BYTE_OFFSET];
        offset += DHCPV6_OPTION_HDR_LEN;

        if (option.length > data.size() || offset > data.size() - option.length) {
            DHCP_LOGE("[DHCPv6] ParseV6Message: option length exceeds buffer, "
                "code=%{public}u, len=%{public}u, remaining=%{public}zu",
                option.code, option.length, data.size() - offset + DHCPV6_OPTION_HDR_LEN);
            return false;
        }

        option.data.assign(data.begin() + offset, data.begin() + offset + option.length);
        message.options.push_back(option);
        offset += option.length;
    }

    // Reject truncated/malformed packets with trailing bytes
    if (offset != data.size()) {
        DHCP_LOGW("[DHCPv6] ParseV6Message: trailing bytes detected, "
            "offset=%{public}zu, size=%{public}zu, dropping packet",
            offset, data.size());
        return false;
    }

    return true;
}

// Maximum number of options to prevent DoS attacks
static constexpr size_t MAX_OPTIONS_PER_MESSAGE = 64;

static void ParseReplyOptions(const std::vector<DhcpV6Option>& options,
    DhcpV6Advertise& adv)
{
    size_t optionCount = 0;
    for (const auto& opt : options) {
        // Prevent DoS: limit number of options processed
        if (++optionCount > MAX_OPTIONS_PER_MESSAGE) {
            DHCP_LOGW("[DHCPv6] ParseReplyOptions: too many options (%{public}zu), stopping", optionCount);
            break;
        }
        switch (opt.code) {
            case OPTION_SERVERID:
                DhcpV6Message::ParseServerIdOption(opt, adv.serverId);
                break;
            case OPTION_PREFERENCE:
                if (opt.data.size() >= 1) {
                    adv.preference = opt.data[0];
                }
                break;
            case OPTION_IA_NA:
                if (!DhcpV6Message::ParseIaNaOption(opt, adv)) {
                    DHCP_LOGE("[DHCPv6] ParseReplyOptions: IA_NA parse failed");
                    adv.statusCode = STATUS_UNSPEC_FAIL;
                }
                break;
            case OPTION_DNS_SERVERS:
                DhcpV6Message::ParseDnsServersOption(opt, adv.dnsServers);
                break;
            case OPTION_STATUS_CODE:
                DhcpV6Message::ParseStatusCodeOption(opt, adv.statusCode, adv.statusMessage);
                break;
            default:
                break;
        }
    }
}

bool DhcpV6Message::ParseV6Advertise(const std::vector<uint8_t>& data,
    DhcpV6Advertise& advertise)
{
    DhcpV6MessageInfo info;
    if (!ParseV6Message(data, info) || info.msgType != ADVERTISE) {
        DHCP_LOGE("[DHCPv6] ParseV6Advertise: parse failed or wrong msgType %{public}d (%{public}s)",
            info.msgType, GetMsgTypeName(info.msgType));
        return false;
    }

    ParseReplyOptions(info.options, advertise);

    if (advertise.statusCode != STATUS_SUCCESS) {
        DHCP_LOGE("[DHCPv6] ParseV6Advertise: server returned "
            "status %{public}d", advertise.statusCode);
        return false;
    }
    return true;
}

bool DhcpV6Message::ParseV6Reply(const std::vector<uint8_t>& data,
    DhcpV6Advertise& reply)
{
    DhcpV6MessageInfo info;
    if (!ParseV6Message(data, info)) {
        DHCP_LOGE("[DHCPv6] ParseV6Reply: ParseV6Message failed, data.size=%{public}zu", data.size());
        return false;
    }
    DHCP_LOGI("[DHCPv6] ParseV6Reply: msgType=%{public}d (%{public}s), transactionId=%{public}u",
        info.msgType, GetMsgTypeName(info.msgType), info.transactionId);
    if (info.msgType != REPLY) {
        DHCP_LOGE("[DHCPv6] ParseV6Reply: wrong msgType %{public}d (%{public}s), expected REPLY(7)",
            info.msgType, GetMsgTypeName(info.msgType));
        return false;
    }

    ParseReplyOptions(info.options, reply);

    DHCP_LOGI("[DHCPv6] ParseV6Reply: statusCode=%{public}d, validLifetime=%{public}u, preferredLifetime=%{public}u, "
        "t1=%{public}u, t2=%{public}u, ipv6Addresses=%{public}zu, dnsServers=%{public}zu",
        reply.statusCode, reply.validLifetime, reply.preferredLifetime, reply.t1, reply.t2,
        reply.ipv6Addresses.size(), reply.dnsServers.size());
    for (const auto& addr : reply.ipv6Addresses) {
        DHCP_LOGI("[DHCPv6] ParseV6Reply: IPv6 address: %{public}s", Ipv6Anonymize(addr).c_str());
    }
    for (const auto& dns : reply.dnsServers) {
        DHCP_LOGI("[DHCPv6] ParseV6Reply: DNS server: %{public}s", Ipv6Anonymize(dns).c_str());
    }
    if (reply.statusCode != STATUS_SUCCESS) {
        DHCP_LOGE("[DHCPv6] ParseV6Reply: server returned "
            "status %{public}d", reply.statusCode);
        return false;
    }
    return true;
}

static DhcpV6Option BuildIdOption(uint16_t code, const std::string& duid)
{
    DhcpV6Option option;
    option.code = code;
    option.length = static_cast<uint16_t>(duid.size());
    option.data.assign(duid.begin(), duid.end());
    return option;
}

DhcpV6Option DhcpV6Message::BuildClientIdOption(const std::string& duid)
{
    return BuildIdOption(OPTION_CLIENTID, duid);
}

DhcpV6Option DhcpV6Message::BuildServerIdOption(const std::string& duid)
{
    return BuildIdOption(OPTION_SERVERID, duid);
}

DhcpV6Option DhcpV6Message::BuildIaNaOption(uint32_t iaid, uint32_t t1, uint32_t t2)
{
    DhcpV6Option option;
    option.code = OPTION_IA_NA;
    option.data.resize(DHCPV6_IA_NA_HDR_LEN);

    option.data[DHCPV6_IA_NA_HDR_IAID_IDX] = static_cast<uint8_t>((iaid >> SHIFT_24) & BYTE_MASK);
    option.data[DHCPV6_IA_NA_HDR_IAID_IDX + DHCPV6_IAADDR_LIFETIME_SECOND_BYTE_OFFSET] =
        static_cast<uint8_t>((iaid >> SHIFT_16) & BYTE_MASK);
    option.data[DHCPV6_IA_NA_HDR_IAID_IDX + DHCPV6_IAADDR_LIFETIME_THIRD_BYTE_OFFSET] =
        static_cast<uint8_t>((iaid >> SHIFT_8) & BYTE_MASK);
    option.data[DHCPV6_IA_NA_HDR_IAID_IDX + DHCPV6_IAADDR_LIFETIME_FOURTH_BYTE_OFFSET] =
        static_cast<uint8_t>(iaid & BYTE_MASK);

    option.data[DHCPV6_IA_NA_HDR_T1_IDX] = static_cast<uint8_t>((t1 >> SHIFT_24) & BYTE_MASK);
    option.data[DHCPV6_IA_NA_HDR_T1_IDX + DHCPV6_IAADDR_LIFETIME_SECOND_BYTE_OFFSET] =
        static_cast<uint8_t>((t1 >> SHIFT_16) & BYTE_MASK);
    option.data[DHCPV6_IA_NA_HDR_T1_IDX + DHCPV6_IAADDR_LIFETIME_THIRD_BYTE_OFFSET] =
        static_cast<uint8_t>((t1 >> SHIFT_8) & BYTE_MASK);
    option.data[DHCPV6_IA_NA_HDR_T1_IDX + DHCPV6_IAADDR_LIFETIME_FOURTH_BYTE_OFFSET] =
        static_cast<uint8_t>(t1 & BYTE_MASK);

    option.data[DHCPV6_IA_NA_HDR_T2_IDX] = static_cast<uint8_t>((t2 >> SHIFT_24) & BYTE_MASK);
    option.data[DHCPV6_IA_NA_HDR_T2_IDX + DHCPV6_IAADDR_LIFETIME_SECOND_BYTE_OFFSET] =
        static_cast<uint8_t>((t2 >> SHIFT_16) & BYTE_MASK);
    option.data[DHCPV6_IA_NA_HDR_T2_IDX + DHCPV6_IAADDR_LIFETIME_THIRD_BYTE_OFFSET] =
        static_cast<uint8_t>((t2 >> SHIFT_8) & BYTE_MASK);
    option.data[DHCPV6_IA_NA_HDR_T2_IDX + DHCPV6_IAADDR_LIFETIME_FOURTH_BYTE_OFFSET] =
        static_cast<uint8_t>(t2 & BYTE_MASK);

    option.length = option.data.size();
    return option;
}

DhcpV6Option DhcpV6Message::BuildIaNaOptionWithAddresses(uint32_t iaid, uint32_t t1, uint32_t t2,
    const std::vector<std::string>& addresses, uint32_t preferredLifetime, uint32_t validLifetime)
{
    DhcpV6Option option = BuildIaNaOption(iaid, t1, t2);

    for (const auto& addr : addresses) {
        DhcpV6Option iaAddrOpt = BuildIaAddrOption(addr, preferredLifetime, validLifetime);
        option.data.push_back((iaAddrOpt.code >> SHIFT_8) & BYTE_MASK);
        option.data.push_back(iaAddrOpt.code & BYTE_MASK);
        option.data.push_back((iaAddrOpt.length >> SHIFT_8) & BYTE_MASK);
        option.data.push_back(iaAddrOpt.length & BYTE_MASK);
        option.data.insert(option.data.end(), iaAddrOpt.data.begin(), iaAddrOpt.data.end());
    }

    option.length = option.data.size();
    return option;
}

DhcpV6Option DhcpV6Message::BuildIaAddrOption(const std::string& ipv6Addr,
    uint32_t preferredLifetime, uint32_t validLifetime)
{
    DhcpV6Option option;
    option.code = OPTION_IAADDR;
    option.data.resize(DHCPV6_IAADDR_LEN);

    struct in6_addr addr;
    if (inet_pton(AF_INET6, ipv6Addr.c_str(), &addr) == 1) {
        errno_t err = memcpy_s(option.data.data(), option.data.size(), &addr, DHCPV6_IPV6_ADDR_LEN);
        if (err != EOK) {
            DHCP_LOGE("BuildIaAddrOption: memcpy_s failed, err=%{public}d", err);
        }
    }

    option.data[DHCPV6_IAADDR_PREF_LIFETIME_IDX] =
        static_cast<uint8_t>((preferredLifetime >> SHIFT_24) & BYTE_MASK);
    option.data[DHCPV6_IAADDR_PREF_LIFETIME_IDX + DHCPV6_IAADDR_LIFETIME_SECOND_BYTE_OFFSET] =
        static_cast<uint8_t>((preferredLifetime >> SHIFT_16) & BYTE_MASK);
    option.data[DHCPV6_IAADDR_PREF_LIFETIME_IDX + DHCPV6_IAADDR_LIFETIME_THIRD_BYTE_OFFSET] =
        static_cast<uint8_t>((preferredLifetime >> SHIFT_8) & BYTE_MASK);
    option.data[DHCPV6_IAADDR_PREF_LIFETIME_IDX + DHCPV6_IAADDR_LIFETIME_FOURTH_BYTE_OFFSET] =
        static_cast<uint8_t>(preferredLifetime & BYTE_MASK);

    option.data[DHCPV6_IAADDR_VALID_LIFETIME_IDX] =
        static_cast<uint8_t>((validLifetime >> SHIFT_24) & BYTE_MASK);
    option.data[DHCPV6_IAADDR_VALID_LIFETIME_IDX + DHCPV6_IAADDR_LIFETIME_SECOND_BYTE_OFFSET] =
        static_cast<uint8_t>((validLifetime >> SHIFT_16) & BYTE_MASK);
    option.data[DHCPV6_IAADDR_VALID_LIFETIME_IDX + DHCPV6_IAADDR_LIFETIME_THIRD_BYTE_OFFSET] =
        static_cast<uint8_t>((validLifetime >> SHIFT_8) & BYTE_MASK);
    option.data[DHCPV6_IAADDR_VALID_LIFETIME_IDX + DHCPV6_IAADDR_LIFETIME_FOURTH_BYTE_OFFSET] =
        static_cast<uint8_t>(validLifetime & BYTE_MASK);

    option.length = option.data.size();
    return option;
}

DhcpV6Option DhcpV6Message::BuildElapsedTimeOption(uint16_t elapsedTime)
{
    DhcpV6Option option;
    option.code = OPTION_ELAPSED_TIME;
    option.data.resize(DHCPV6_ELAPSED_TIME_LEN);
    option.data[DHCPV6_ELAPSED_TIME_OFFSET] = static_cast<uint8_t>((elapsedTime >> SHIFT_8) & BYTE_MASK);
    option.data[DHCPV6_ELAPSED_TIME_OFFSET + DHCPV6_ELAPSED_TIME_LEN - 1] =
        static_cast<uint8_t>(elapsedTime & BYTE_MASK);
    option.length = option.data.size();
    return option;
}

DhcpV6Option DhcpV6Message::BuildOptionRequestOption(const std::vector<uint16_t>& optionCodes)
{
    DhcpV6Option option;
    option.code = OPTION_ORO;
    size_t optionCodeCount = optionCodes.size();
    option.data.resize(optionCodeCount * DHCPV6_OPTION_CODE_LEN);

    for (size_t i = 0; i < optionCodeCount; ++i) {
        option.data[i * DHCPV6_OPTION_CODE_LEN] = (optionCodes[i] >> SHIFT_8) & BYTE_MASK;
        option.data[i * DHCPV6_OPTION_CODE_LEN + DHCPV6_OPTION_CODE_LEN - 1] = optionCodes[i] & BYTE_MASK;
    }

    option.length = option.data.size();
    return option;
}

// Maximum DUID length according to RFC 3315 (128 bytes is sufficient for all DUID types)
static constexpr size_t MAX_DUID_LENGTH = 128;

bool DhcpV6Message::ParseClientIdOption(const DhcpV6Option& option, std::string& duid)
{
    if (option.data.size() > MAX_DUID_LENGTH) {
        DHCP_LOGE("[DHCPv6] ParseClientIdOption: DUID too long, size=%{public}zu, max=%{public}zu",
            option.data.size(), MAX_DUID_LENGTH);
        return false;
    }
    duid.assign(option.data.begin(), option.data.end());
    return true;
}

bool DhcpV6Message::ParseServerIdOption(const DhcpV6Option& option, std::string& duid)
{
    if (option.data.size() > MAX_DUID_LENGTH) {
        DHCP_LOGE("[DHCPv6] ParseServerIdOption: DUID too long, size=%{public}zu, max=%{public}zu",
            option.data.size(), MAX_DUID_LENGTH);
        return false;
    }
    duid.assign(option.data.begin(), option.data.end());
    return true;
}

// Maximum number of IA_NA options to prevent DoS attacks
static constexpr size_t MAX_IA_NA_OPTIONS = 8;

bool DhcpV6Message::ParseIaNaSubOptions(const std::vector<uint8_t>& data, DhcpV6Advertise& adv)
{
    size_t offset = DHCPV6_IA_NA_HDR_LEN;
    size_t addrCount = 0;
    while (offset + DHCPV6_OPTION_HDR_LEN <= data.size()) {
        uint16_t subCode = (data[offset] << SHIFT_8) | data[offset + DHCPV6_OPTION_CODE_SECOND_BYTE_OFFSET];
        uint16_t subLen = (data[offset + DHCPV6_OPTION_CODE_OFFSET] << SHIFT_8) |
            data[offset + DHCPV6_OPTION_LEN_SECOND_BYTE_OFFSET];
        offset += DHCPV6_OPTION_HDR_LEN;
        if (offset + subLen > data.size()) {
            DHCP_LOGE("[DHCPv6] ParseIaNaSubOptions: sub-option length exceeds, subLen=%{public}u", subLen);
            return false;
        }
        if (subCode == OPTION_IAADDR && subLen >= IAADDR_MIN_LEN) {
            if (addrCount >= MAX_IA_NA_OPTIONS) {
                DHCP_LOGW("[DHCPv6] ParseIaNaSubOptions: too many addresses, stopping");
                break;
            }
            DhcpV6Option iaaddrOpt;
            iaaddrOpt.code = OPTION_IAADDR;
            iaaddrOpt.length = subLen;
            iaaddrOpt.data.assign(data.begin() + offset, data.begin() + offset + subLen);
            std::string ip;
            uint32_t pref = 0;
            uint32_t valid = 0;
            if (ParseIaAddrOption(iaaddrOpt, ip, pref, valid)) {
                adv.ipv6Addresses.push_back(ip);
                UpdateMinLifetime(adv.preferredLifetime, pref);
                UpdateMinLifetime(adv.validLifetime, valid);
                ++addrCount;
            }
        }
        offset += subLen;
    }
    // Check for trailing bytes
    if (offset != data.size()) {
        DHCP_LOGW("[DHCPv6] ParseIaNaSubOptions: trailing bytes detected");
    }
    return true;
}

bool DhcpV6Message::ParseIaNaOption(const DhcpV6Option& option, DhcpV6Advertise& adv)
{
    if (option.data.size() < DHCPV6_IA_NA_HDR_LEN) {
        DHCP_LOGE("[DHCPv6] ParseIaNaOption: data too short, size=%{public}zu, need=%{public}zu",
            option.data.size(), DHCPV6_IA_NA_HDR_LEN);
        return false;
    }
    adv.iaid = ParseUint32FromBytes(option.data, DHCPV6_IA_NA_HDR_IAID_IDX);
    adv.t1 = ParseUint32FromBytes(option.data, DHCPV6_IA_NA_HDR_T1_IDX);
    adv.t2 = ParseUint32FromBytes(option.data, DHCPV6_IA_NA_HDR_T2_IDX);
    adv.preferredLifetime = 0;
    adv.validLifetime = 0;
    DHCP_LOGI("[DHCPv6] ParseIaNaOption: iaid=%{public}u t1=%{public}u t2=%{public}u, parsing sub-options",
        adv.iaid, adv.t1, adv.t2);

    if (!ParseIaNaSubOptions(option.data, adv)) {
        return false;
    }
    DHCP_LOGI("[DHCPv6] ParseIaNaOption: done, found %{public}zu addresses", adv.ipv6Addresses.size());
    return true;
}

void DhcpV6Message::UpdateMinLifetime(uint32_t& current, uint32_t candidate)
{
    if (current == 0 || candidate < current) {
        current = candidate;
    }
}

bool DhcpV6Message::ParseIaAddrOption(const DhcpV6Option& option,
    std::string& ipv6Addr, uint32_t& preferredLifetime, uint32_t& validLifetime)
{
    if (option.data.size() < DHCPV6_IAADDR_LEN) {
        return false;
    }

    char addrStr[INET6_ADDRSTRLEN];
    struct in6_addr addr;
    errno_t err = memcpy_s(&addr, sizeof(addr), option.data.data(), DHCPV6_IPV6_ADDR_LEN);
    if (err == EOK && inet_ntop(AF_INET6, &addr, addrStr, INET6_ADDRSTRLEN)) {
        ipv6Addr = addrStr;
    }

    preferredLifetime = ParseUint32FromBytes(option.data, DHCPV6_IAADDR_PREF_LIFETIME_IDX);
    validLifetime = ParseUint32FromBytes(option.data, DHCPV6_IAADDR_VALID_LIFETIME_IDX);

    return true;
}

// Maximum number of DNS servers to prevent DoS attacks
static constexpr size_t MAX_DNS_SERVERS = 16;

bool DhcpV6Message::ParseDnsServersOption(const DhcpV6Option& option, std::vector<std::string>& dnsServers)
{
    // RFC 3646 DHCPv6 DNS Servers Option format (Option Code 23):
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |         OPTION_DNS_SERVERS    |         option-len            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                                                               |
    // |                 DNS server 1 IPv6 address                     |
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // ... (each address is 16 bytes, no header or lifetime field)

    // Parse DNS server addresses directly from byte 0 (no header in DHCPv6 DNS option)
    size_t offset = 0;
    size_t serverCount = 0;
    while (offset + DHCPV6_IPV6_ADDR_LEN <= option.data.size()) {
        // Prevent DoS: limit number of DNS servers
        if (serverCount >= MAX_DNS_SERVERS) {
            DHCP_LOGW("[DHCPv6] ParseDnsServersOption: too many DNS servers (%{public}zu), stopping",
                serverCount);
            break;
        }
        char addrStr[INET6_ADDRSTRLEN];
        struct in6_addr addr;
        errno_t err = memcpy_s(&addr, sizeof(addr), &option.data[offset], DHCPV6_IPV6_ADDR_LEN);
        if (err == EOK && inet_ntop(AF_INET6, &addr, addrStr, INET6_ADDRSTRLEN)) {
            dnsServers.push_back(addrStr);
            ++serverCount;
        }
        offset += DHCPV6_IPV6_ADDR_LEN;
    }
    return true;
}

// Maximum status message length (1KB is sufficient)
static constexpr size_t MAX_STATUS_MESSAGE_LENGTH = 1024;

bool DhcpV6Message::ParseStatusCodeOption(const DhcpV6Option& option,
    uint16_t& statusCode, std::string& statusMessage)
{
    if (option.data.size() < DHCPV6_STATUS_CODE_HDR_LEN) {
        DHCP_LOGE("[DHCPv6] ParseStatusCodeOption: data too short, size=%{public}zu, need=%{public}zu",
            option.data.size(), DHCPV6_STATUS_CODE_HDR_LEN);
        return false;
    }

    statusCode = (option.data[DHCPV6_STATUS_CODE_OFFSET] << SHIFT_8) |
        option.data[DHCPV6_STATUS_CODE_OFFSET + 1];
    // Only copy status message if present and not too long
    if (option.data.size() > DHCPV6_STATUS_CODE_HDR_LEN) {
        size_t msgLen = option.data.size() - DHCPV6_STATUS_CODE_HDR_LEN;
        if (msgLen > MAX_STATUS_MESSAGE_LENGTH) {
            DHCP_LOGW("[DHCPv6] ParseStatusCodeOption: status message too long (%{public}zu), truncating",
                msgLen);
            msgLen = MAX_STATUS_MESSAGE_LENGTH;
        }
        statusMessage.assign(reinterpret_cast<const char*>(&option.data[DHCPV6_STATUS_CODE_HDR_LEN]), msgLen);
    }
    return true;
}

std::vector<uint8_t> DhcpV6Message::BuildMessage(uint8_t msgType,
    uint32_t transactionId, const std::vector<DhcpV6Option>& options)
{
    std::vector<uint8_t> message;

    message.push_back(msgType);
    message.push_back((transactionId >> SHIFT_16) & BYTE_MASK);
    message.push_back((transactionId >> SHIFT_8) & BYTE_MASK);
    message.push_back(transactionId & BYTE_MASK);

    for (const auto& option : options) {
        message.push_back((option.code >> SHIFT_8) & BYTE_MASK);
        message.push_back(option.code & BYTE_MASK);
        message.push_back((option.length >> SHIFT_8) & BYTE_MASK);
        message.push_back(option.length & BYTE_MASK);
        message.insert(message.end(), option.data.begin(), option.data.end());
    }

    return message;
}

uint32_t DhcpV6Message::GenerateTransactionId()
{
    thread_local std::random_device rd;
    thread_local std::mt19937 gen(rd());
    thread_local std::uniform_int_distribution<uint32_t> dis(1, MAX_TRANSACTION_ID);
    return dis(gen);
}

std::string DhcpV6Message::GenerateDuid(const std::string& iface)
{
    std::vector<uint8_t> duid;

    // DUID-LLT: type(1) + hardware type(2) + time(4) + link layer address(variable)
    duid.push_back(DUID_TYPE_LLT);
    duid.push_back(static_cast<uint8_t>((HARDWARE_TYPE_ETHERNET >> SHIFT_8) & BYTE_MASK));
    duid.push_back(static_cast<uint8_t>(HARDWARE_TYPE_ETHERNET & BYTE_MASK));

    uint32_t time = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    duid.push_back((time >> SHIFT_24) & BYTE_MASK);
    duid.push_back((time >> SHIFT_16) & BYTE_MASK);
    duid.push_back((time >> SHIFT_8) & BYTE_MASK);
    duid.push_back(time & BYTE_MASK);

    std::string macStr;
    if (!iface.empty() && GetLocalMac(iface, macStr) == 0) {
        std::vector<uint8_t> macAddr;
        unsigned int bytes[DHCPV6_MAC_LEN] = {0};
        if (sscanf_s(macStr.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
            &bytes[MAC_INDEX_0], &bytes[MAC_INDEX_1], &bytes[MAC_INDEX_2],
            &bytes[MAC_INDEX_3], &bytes[MAC_INDEX_4], &bytes[MAC_INDEX_5]) == DHCPV6_MAC_LEN) {
            for (size_t i = 0; i < DHCPV6_MAC_LEN; ++i) {
                macAddr.push_back(static_cast<uint8_t>(bytes[i]));
            }
            duid.insert(duid.end(), macAddr.begin(), macAddr.end());
            return std::string(duid.begin(), duid.end());
        }
    }

    // Fallback: generate random MAC if interface MAC unavailable
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, BYTE_MASK);
    for (size_t i = 0; i < DHCPV6_MAC_LEN; ++i) {
        duid.push_back(dis(gen));
    }

    return std::string(duid.begin(), duid.end());
}
} // namespace DHCP
} // namespace OHOS
