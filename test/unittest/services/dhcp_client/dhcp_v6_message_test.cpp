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

#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "securec.h"
#include "dhcp_v6_message.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpV6MessageTest");

using namespace testing::ext;
using namespace OHOS::DHCP;

namespace OHOS {
class DhcpV6MessageTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {}
    virtual void TearDown()
    {}
};

HWTEST_F(DhcpV6MessageTest, BuildSolicitMessage_SUCCESS, TestSize.Level1)
{
    DhcpV6Config config;
    config.transactionId = 0x123456;
    config.stateless = false;

    std::vector<uint8_t> message = DhcpV6Message::BuildSolicitMessage(config);
    EXPECT_GT(message.size(), 4);

    DhcpV6MessageInfo info;
    EXPECT_TRUE(DhcpV6Message::ParseV6Message(message, info));
    EXPECT_EQ(info.msgType, SOLICIT);
    EXPECT_EQ(info.transactionId, 0x123456);
}

HWTEST_F(DhcpV6MessageTest, BuildSolicitMessage_Stateless_SUCCESS, TestSize.Level1)
{
    DhcpV6Config config;
    config.stateless = true;

    std::vector<uint8_t> message = DhcpV6Message::BuildSolicitMessage(config);
    EXPECT_GT(message.size(), 4);

    DhcpV6MessageInfo info;
    EXPECT_TRUE(DhcpV6Message::ParseV6Message(message, info));
    EXPECT_EQ(info.msgType, SOLICIT);
}

HWTEST_F(DhcpV6MessageTest, BuildRequestMessage_SUCCESS, TestSize.Level1)
{
    DhcpV6Config config;
    config.transactionId = 0x123456;
    config.serverId = "test-server-duid";

    DhcpV6Advertise advertise;
    advertise.serverId = "test-server-duid";
    advertise.t1 = 100;
    advertise.t2 = 200;
    advertise.ipv6Addresses = {"2001:db8::1"};

    std::vector<uint8_t> message = DhcpV6Message::BuildRequestMessage(config, advertise);
    EXPECT_GT(message.size(), 4);

    DhcpV6MessageInfo info;
    EXPECT_TRUE(DhcpV6Message::ParseV6Message(message, info));
    EXPECT_EQ(info.msgType, REQUEST);
}

HWTEST_F(DhcpV6MessageTest, BuildRenewMessage_SUCCESS, TestSize.Level1)
{
    DhcpV6Config config;
    config.serverId = "test-server-duid";
    config.ipv6Addresses = {"2001:db8::1"};

    std::vector<uint8_t> message = DhcpV6Message::BuildRenewMessage(config);
    EXPECT_GT(message.size(), 4);

    DhcpV6MessageInfo info;
    EXPECT_TRUE(DhcpV6Message::ParseV6Message(message, info));
    EXPECT_EQ(info.msgType, RENEW);
}

HWTEST_F(DhcpV6MessageTest, BuildRebindMessage_SUCCESS, TestSize.Level1)
{
    DhcpV6Config config;
    config.ipv6Addresses = {"2001:db8::1", "2001:db8::2"};

    std::vector<uint8_t> message = DhcpV6Message::BuildRebindMessage(config);
    EXPECT_GT(message.size(), 4);

    DhcpV6MessageInfo info;
    EXPECT_TRUE(DhcpV6Message::ParseV6Message(message, info));
    EXPECT_EQ(info.msgType, REBIND);
}

HWTEST_F(DhcpV6MessageTest, BuildReleaseMessage_SUCCESS, TestSize.Level1)
{
    DhcpV6Config config;
    config.serverId = "test-server-duid";

    std::vector<uint8_t> message = DhcpV6Message::BuildReleaseMessage(config);
    EXPECT_GT(message.size(), 4);

    DhcpV6MessageInfo info;
    EXPECT_TRUE(DhcpV6Message::ParseV6Message(message, info));
    EXPECT_EQ(info.msgType, RELEASE);
}

HWTEST_F(DhcpV6MessageTest, BuildDeclineMessage_SUCCESS, TestSize.Level1)
{
    DhcpV6Config config;
    config.serverId = "test-server-duid";

    std::vector<std::string> declinedAddrs = {"2001:db8::1"};

    std::vector<uint8_t> message = DhcpV6Message::BuildDeclineMessage(config, declinedAddrs);
    EXPECT_GT(message.size(), 4);

    DhcpV6MessageInfo info;
    EXPECT_TRUE(DhcpV6Message::ParseV6Message(message, info));
    EXPECT_EQ(info.msgType, DECLINE);
}

HWTEST_F(DhcpV6MessageTest, BuildDeclineMessage_MultipleAddresses_SUCCESS, TestSize.Level1)
{
    DhcpV6Config config;
    config.serverId = "test-server-duid";

    std::vector<std::string> declinedAddrs = {"2001:db8::1", "2001:db8::2", "2001:db8::3"};

    std::vector<uint8_t> message = DhcpV6Message::BuildDeclineMessage(config, declinedAddrs);
    EXPECT_GT(message.size(), 4);
}

HWTEST_F(DhcpV6MessageTest, BuildInformationRequestMessage_SUCCESS, TestSize.Level1)
{
    DhcpV6Config config;

    std::vector<uint8_t> message = DhcpV6Message::BuildInformationRequestMessage(config);
    EXPECT_GT(message.size(), 4);

    DhcpV6MessageInfo info;
    EXPECT_TRUE(DhcpV6Message::ParseV6Message(message, info));
    EXPECT_EQ(info.msgType, INFORMATION_REQUEST);
}

HWTEST_F(DhcpV6MessageTest, ParseV6Message_SUCCESS, TestSize.Level1)
{
    std::vector<uint8_t> data = {
        0x02, 0x12, 0x34, 0x56,  // ADVERTISE message with transaction ID
        0x00, 0x01, 0x00, 0x04, 'A', 'B', 'C', 'D'  // Client ID option
    };

    DhcpV6MessageInfo info;
    EXPECT_TRUE(DhcpV6Message::ParseV6Message(data, info));
    EXPECT_EQ(info.msgType, ADVERTISE);
    EXPECT_EQ(info.transactionId, 0x123456);
    EXPECT_EQ(info.options.size(), 1);
}

HWTEST_F(DhcpV6MessageTest, ParseV6Message_EmptyData_FAILED, TestSize.Level1)
{
    std::vector<uint8_t> data;

    DhcpV6MessageInfo info;
    EXPECT_FALSE(DhcpV6Message::ParseV6Message(data, info));
}

HWTEST_F(DhcpV6MessageTest, ParseV6Message_TooShortData_FAILED, TestSize.Level1)
{
    std::vector<uint8_t> data = {0x01, 0x02};

    DhcpV6MessageInfo info;
    EXPECT_FALSE(DhcpV6Message::ParseV6Message(data, info));
}

HWTEST_F(DhcpV6MessageTest, ParseV6Message_InvalidOptionLength_FAILED, TestSize.Level1)
{
    std::vector<uint8_t> data = {
        0x02, 0x12, 0x34, 0x56,  // ADVERTISE message
        0x00, 0x01, 0xFF, 0xFF   // Option with very long length
    };

    DhcpV6MessageInfo info;
    EXPECT_FALSE(DhcpV6Message::ParseV6Message(data, info));
}

HWTEST_F(DhcpV6MessageTest, BuildClientIdOption_SUCCESS, TestSize.Level1)
{
    std::string duid = "client-duid-data";

    DhcpV6Option option = DhcpV6Message::BuildClientIdOption(duid);
    EXPECT_EQ(option.code, OPTION_CLIENTID);
    EXPECT_EQ(option.length, duid.size());
    EXPECT_EQ(option.data.size(), duid.size());
}

HWTEST_F(DhcpV6MessageTest, BuildServerIdOption_SUCCESS, TestSize.Level1)
{
    std::string duid = "server-duid-data";

    DhcpV6Option option = DhcpV6Message::BuildServerIdOption(duid);
    EXPECT_EQ(option.code, OPTION_SERVERID);
    EXPECT_EQ(option.length, duid.size());
}

HWTEST_F(DhcpV6MessageTest, BuildIaNaOption_SUCCESS, TestSize.Level1)
{
    DhcpV6Option option = DhcpV6Message::BuildIaNaOption(12345, 100, 200);
    EXPECT_EQ(option.code, OPTION_IA_NA);
    EXPECT_EQ(option.length, 12);  // IAID(4) + T1(4) + T2(4)
}

HWTEST_F(DhcpV6MessageTest, BuildIaNaOptionWithAddresses_SUCCESS, TestSize.Level1)
{
    std::vector<std::string> addresses = {"2001:db8::1"};
    DhcpV6Option option = DhcpV6Message::BuildIaNaOptionWithAddresses(
        12345, 100, 200, addresses, 300, 400);
    EXPECT_EQ(option.code, OPTION_IA_NA);
    EXPECT_GT(option.length, 12);
}

HWTEST_F(DhcpV6MessageTest, BuildIaAddrOption_SUCCESS, TestSize.Level1)
{
    DhcpV6Option option = DhcpV6Message::BuildIaAddrOption("2001:db8::1", 100, 200);
    EXPECT_EQ(option.code, OPTION_IAADDR);
    EXPECT_EQ(option.length, 24);  // IPv6(16) + preferred(4) + valid(4)
}

HWTEST_F(DhcpV6MessageTest, BuildElapsedTimeOption_SUCCESS, TestSize.Level1)
{
    DhcpV6Option option = DhcpV6Message::BuildElapsedTimeOption(1234);
    EXPECT_EQ(option.code, OPTION_ELAPSED_TIME);
    EXPECT_EQ(option.length, 2);
}

HWTEST_F(DhcpV6MessageTest, BuildOptionRequestOption_SUCCESS, TestSize.Level1)
{
    std::vector<uint16_t> optionCodes = {OPTION_DNS_SERVERS, OPTION_DOMAIN_LIST};

    DhcpV6Option option = DhcpV6Message::BuildOptionRequestOption(optionCodes);
    EXPECT_EQ(option.code, OPTION_ORO);
    EXPECT_EQ(option.length, 4);  // 2 codes * 2 bytes each
}

HWTEST_F(DhcpV6MessageTest, ParseClientIdOption_SUCCESS, TestSize.Level1)
{
    DhcpV6Option option;
    option.code = OPTION_CLIENTID;
    std::string duidData = "test-duid";
    option.data.assign(duidData.begin(), duidData.end());

    std::string duid;
    EXPECT_TRUE(DhcpV6Message::ParseClientIdOption(option, duid));
    EXPECT_EQ(duid, duidData);
}

HWTEST_F(DhcpV6MessageTest, ParseServerIdOption_SUCCESS, TestSize.Level1)
{
    DhcpV6Option option;
    option.code = OPTION_SERVERID;
    std::string serverDuid = "server-duid";
    option.data.assign(serverDuid.begin(), serverDuid.end());

    std::string duid;
    EXPECT_TRUE(DhcpV6Message::ParseServerIdOption(option, duid));
    EXPECT_EQ(duid, serverDuid);
}

HWTEST_F(DhcpV6MessageTest, ParseIaAddrOption_SUCCESS, TestSize.Level1)
{
    DhcpV6Option option;
    option.code = OPTION_IAADDR;
    option.data.resize(24);

    // Build IAADDR option with IPv6 address and lifetimes
    struct in6_addr addr;
    inet_pton(AF_INET6, "2001:db8::1", &addr);
    errno_t err = memcpy_s(option.data.data(), option.data.size(), &addr, sizeof(addr));
    EXPECT_EQ(err, EOK);

    option.data[16] = 0; option.data[17] = 0; option.data[18] = 0; option.data[19] = 100;  // preferred
    option.data[20] = 0; option.data[21] = 0; option.data[22] = 0; option.data[23] = 200;  // valid

    std::string ip;
    uint32_t preferred = 0;
    uint32_t valid = 0;
    EXPECT_TRUE(DhcpV6Message::ParseIaAddrOption(option, ip, preferred, valid));
    EXPECT_EQ(ip, "2001:db8::1");
    EXPECT_EQ(preferred, 100);
    EXPECT_EQ(valid, 200);
}

HWTEST_F(DhcpV6MessageTest, ParseIaAddrOption_TooShort_FAILED, TestSize.Level1)
{
    DhcpV6Option option;
    option.code = OPTION_IAADDR;
    option.data = {0x01, 0x02};  // Too short

    std::string ip;
    uint32_t preferred = 0;
    uint32_t valid = 0;
    EXPECT_FALSE(DhcpV6Message::ParseIaAddrOption(option, ip, preferred, valid));
}

HWTEST_F(DhcpV6MessageTest, ParseDnsServersOption_SUCCESS, TestSize.Level1)
{
    DhcpV6Option option;
    option.code = OPTION_DNS_SERVERS;

    // Add two IPv6 addresses
    struct in6_addr addr1, addr2;
    inet_pton(AF_INET6, "2001:db8::53", &addr1);
    inet_pton(AF_INET6, "2001:db8::54", &addr2);
    option.data.insert(option.data.end(), addr1.s6_addr, addr1.s6_addr + 16);
    option.data.insert(option.data.end(), addr2.s6_addr, addr2.s6_addr + 16);

    std::vector<std::string> dnsServers;
    EXPECT_TRUE(DhcpV6Message::ParseDnsServersOption(option, dnsServers));
    EXPECT_EQ(dnsServers.size(), 2);
}

HWTEST_F(DhcpV6MessageTest, ParseStatusCodeOption_SUCCESS, TestSize.Level1)
{
    DhcpV6Option option;
    option.code = OPTION_STATUS_CODE;
    option.data = {0x00, 0x00, 'O', 'K'};  // Status code 0 with message

    uint16_t statusCode = 0;
    std::string statusMessage;
    EXPECT_TRUE(DhcpV6Message::ParseStatusCodeOption(option, statusCode, statusMessage));
    EXPECT_EQ(statusCode, STATUS_SUCCESS);
}

HWTEST_F(DhcpV6MessageTest, ParseStatusCodeOption_TooShort_FAILED, TestSize.Level1)
{
    DhcpV6Option option;
    option.code = OPTION_STATUS_CODE;
    option.data = {0x00};  // Only 1 byte, need at least 2

    uint16_t statusCode = 0;
    std::string statusMessage;
    EXPECT_FALSE(DhcpV6Message::ParseStatusCodeOption(option, statusCode, statusMessage));
}

HWTEST_F(DhcpV6MessageTest, ParseIaNaOption_SUCCESS, TestSize.Level1)
{
    DhcpV6Option option;
    option.code = OPTION_IA_NA;
    option.data.resize(12);

    // Build IA_NA with IAID, T1, T2
    option.data[0] = 0; option.data[1] = 0; option.data[2] = 0; option.data[3] = 1;  // IAID = 1
    option.data[4] = 0; option.data[5] = 0; option.data[6] = 0; option.data[7] = 100;  // T1 = 100
    option.data[8] = 0; option.data[9] = 0; option.data[10] = 0; option.data[11] = 200;  // T2 = 200

    DhcpV6Advertise adv;
    EXPECT_TRUE(DhcpV6Message::ParseIaNaOption(option, adv));
    EXPECT_EQ(adv.iaid, 1);
    EXPECT_EQ(adv.t1, 100);
    EXPECT_EQ(adv.t2, 200);
}

HWTEST_F(DhcpV6MessageTest, ParseIaNaOption_TooShort_FAILED, TestSize.Level1)
{
    DhcpV6Option option;
    option.code = OPTION_IA_NA;
    option.data = {0x01, 0x02, 0x03};  // Too short

    DhcpV6Advertise adv;
    EXPECT_FALSE(DhcpV6Message::ParseIaNaOption(option, adv));
}

HWTEST_F(DhcpV6MessageTest, GenerateTransactionId_SUCCESS, TestSize.Level1)
{
    uint32_t txId = DhcpV6Message::GenerateTransactionId();
    EXPECT_GT(txId, 0);
    EXPECT_LE(txId, 0xFFFFFF);  // 24-bit value
}

HWTEST_F(DhcpV6MessageTest, GenerateDuid_NoIface_SUCCESS, TestSize.Level1)
{
    std::string duid = DhcpV6Message::GenerateDuid();
    EXPECT_GT(duid.size(), 0);

    // DUID-LLT should be at least 7 bytes (type + hwtype + time + mac)
    EXPECT_GE(duid.size(), 7);
}

HWTEST_F(DhcpV6MessageTest, GenerateDuid_EmptyIface_SUCCESS, TestSize.Level1)
{
    std::string duid = DhcpV6Message::GenerateDuid("");
    EXPECT_GT(duid.size(), 0);
    EXPECT_GE(duid.size(), 7);
}

HWTEST_F(DhcpV6MessageTest, GenerateDuid_InvalidIface_Fallback_SUCCESS, TestSize.Level1)
{
    std::string duid = DhcpV6Message::GenerateDuid("invalid_iface_that_does_not_exist_12345");
    EXPECT_GT(duid.size(), 0);
    EXPECT_GE(duid.size(), 7);
}

HWTEST_F(DhcpV6MessageTest, ParseV6Advertise_NotAdvertiseMessage_FAILED, TestSize.Level1)
{
    // Build a SOLICIT message (not ADVERTISE) to test rejection
    DhcpV6Config config;
    config.serverId = "test-server";
    config.transactionId = 0x123456;
    std::vector<uint8_t> message = DhcpV6Message::BuildSolicitMessage(config);

    DhcpV6Advertise advertise;
    EXPECT_FALSE(DhcpV6Message::ParseV6Advertise(message, advertise));
}

HWTEST_F(DhcpV6MessageTest, ParseV6Reply_SUCCESS, TestSize.Level1)
{
    std::vector<uint8_t> data = {
        0x07, 0x12, 0x34, 0x56  // REPLY message with transaction ID
    };

    DhcpV6Advertise reply;
    EXPECT_TRUE(DhcpV6Message::ParseV6Reply(data, reply));  // Corrected expectation
}

HWTEST_F(DhcpV6MessageTest, ParseV6Reply_NotReply_FAILED, TestSize.Level1)
{
    std::vector<uint8_t> data = {
        0x02, 0x12, 0x34, 0x56  // ADVERTISE, not REPLY
    };

    DhcpV6Advertise reply;
    EXPECT_FALSE(DhcpV6Message::ParseV6Reply(data, reply));
}
}  // namespace OHOS
