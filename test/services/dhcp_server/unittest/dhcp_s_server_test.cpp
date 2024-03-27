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

#include <gtest/gtest.h>
#include <cstdint>
#include <cstdbool>
#include <cstdlib>
#include <cstdio>
#include <thread>
#include "dhcp_s_server.h"
#include "address_utils.h"
#include "dhcp_option.h"
#include "dhcp_logger.h"
#include "system_func_mock.h"
#include "securec.h"

using namespace testing::ext;
using namespace std;
using namespace OHOS::DHCP;

DEFINE_DHCPLOG_DHCP_LABEL("DhcpServerTest");

struct ServerContext {
    int broadCastFlagEnable;
    DhcpAddressPool addressPool;
    DhcpServerCallback callback;
    DhcpConfig config;
    int serverFd;
    int looperState;
    int initialized;
};

namespace OHOS {
namespace DHCP {
class DhcpServerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {}
    virtual void TearDown()
    {
        SystemFuncMock::GetInstance().SetMockFlag(false);
    }

    int InitServerConfig(DhcpConfig *config);
    int FreeServerConfig(DhcpConfig *config);

private:
    DhcpServerContext *m_pServerCtx = nullptr;
    DhcpConfig m_serverConfg;
};

int DhcpServerTest::InitServerConfig(DhcpConfig *config)
{
    if (!config) {
        return RET_FAILED;
    }
    const char* testIfaceName = "test_if0";
    uint32_t serverId = ParseIpAddr("192.168.189.254");
    uint32_t netmask = ParseIpAddr("255.255.255.0");
    uint32_t beginIp = ParseIpAddr("192.168.189.100");
    uint32_t endIp = ParseIpAddr("192.168.189.200");
    if (serverId == 0 || netmask == 0 || beginIp == 0 || endIp == 0) {
        printf("failed to parse address.\n");
        return RET_FAILED;
    }
    if (memset_s(config, sizeof(DhcpConfig), 0, sizeof(DhcpConfig)) != EOK) {
        return RET_FAILED;
    }
    if (memset_s(config->ifname, sizeof(config->ifname), '\0', sizeof(config->ifname)) != EOK) {
        return RET_FAILED;
    }
    if (strncpy_s(config->ifname, sizeof(config->ifname), testIfaceName, strlen(testIfaceName)) != EOK) {
        return RET_FAILED;
    }
    config->serverId = serverId;
    config->netmask = netmask;
    config->pool.beginAddress = beginIp;
    config->pool.endAddress = endIp;
    config->broadcast = 1;
    if (InitOptionList(&config->options) != RET_SUCCESS) {
        return RET_FAILED;
    }
    return RET_SUCCESS;
}

int DhcpServerTest::FreeServerConfig(DhcpConfig *config)
{
    if (!config) {
        return RET_FAILED;
    }
    FreeOptionList(&config->options);
    return RET_SUCCESS;
}

HWTEST_F(DhcpServerTest, StartServerTest, TestSize.Level1)
{
    DhcpServerContext SerCtx;
    EXPECT_EQ(RET_FAILED, StartDhcpServer(nullptr));
    ASSERT_TRUE(memset_s(SerCtx.ifname, sizeof(IFACE_NAME_SIZE), 0, sizeof(IFACE_NAME_SIZE)) == EOK);
    EXPECT_EQ(RET_FAILED, StartDhcpServer(&SerCtx));
}

HWTEST_F(DhcpServerTest, InitializeServerTest, TestSize.Level1)
{
    DHCP_LOGE("enter InitializeServerTest");
    DhcpConfig config;
    PDhcpServerContext ctx = InitializeServer(nullptr);
    EXPECT_TRUE(ctx == nullptr);
    ASSERT_TRUE(memset_s(&config, sizeof(DhcpConfig), 0, sizeof(DhcpConfig)) == EOK);
    ctx = InitializeServer(&config);
    EXPECT_TRUE(ctx == nullptr);
    EXPECT_TRUE(strcpy_s(config.ifname, sizeof(config.ifname), "test_if0") == EOK);
    ctx = InitializeServer(&config);
    EXPECT_TRUE(ctx == nullptr);

    EXPECT_EQ(RET_SUCCESS, InitServerConfig(&config));
    ctx = InitializeServer(&config);
    ASSERT_TRUE(ctx != nullptr);

    EXPECT_EQ(RET_SUCCESS, FreeServerConfig(&config));
    EXPECT_EQ(RET_SUCCESS, FreeServerContext(&ctx));
}

HWTEST_F(DhcpServerTest, ReceiveDhcpMessageFailedTest, TestSize.Level1)
{
    SystemFuncMock::GetInstance().SetMockFlag(true);
    EXPECT_CALL(SystemFuncMock::GetInstance(), select(_, _, _, _, _)).WillRepeatedly(Return(0));
    ON_CALL(SystemFuncMock::GetInstance(), recvfrom(_, _, _, _, _, _))
        .WillByDefault(Return((int)sizeof(DhcpMsgInfo)));
    DhcpMsgInfo msgInfo = {{0}, 0, {0}};
    const uint8_t testMac1[DHCP_HWADDR_LENGTH] = {0x00, 0x0e, 0x3c, 0x65, 0x3a, 0x09, 0};

    int ret = ReceiveDhcpMessage(1, &msgInfo); // failed to select isset.
    EXPECT_TRUE(ret == RET_SELECT_TIME_OUT || ret == RET_ERROR || ret == RET_FAILED);
    ret = ReceiveDhcpMessage(1, &msgInfo); // message length error
    EXPECT_TRUE(ret == RET_SELECT_TIME_OUT || ret == RET_ERROR || ret == RET_FAILED);
    ret = ReceiveDhcpMessage(1, &msgInfo); // dhcp message type error
    EXPECT_TRUE(ret == RET_SELECT_TIME_OUT || ret == RET_ERROR || ret == RET_FAILED);
    msgInfo.packet.hlen = 128;
    ret = ReceiveDhcpMessage(1, &msgInfo); // hlen error
    EXPECT_TRUE(ret == RET_SELECT_TIME_OUT || ret == RET_ERROR || ret == RET_FAILED);
    msgInfo.packet.hlen = 16;
    msgInfo.packet.op = BOOTREPLY;
    ret = ReceiveDhcpMessage(1, &msgInfo); // client op type error
    EXPECT_TRUE(ret == RET_SELECT_TIME_OUT || ret == RET_ERROR || ret == RET_FAILED);
    msgInfo.packet.op = BOOTREQUEST;
    ret = ReceiveDhcpMessage(1, &msgInfo); // client hardware address error
    EXPECT_TRUE(ret == RET_SELECT_TIME_OUT || ret == RET_ERROR || ret == RET_FAILED);
    for (int i = 0; i < MAC_ADDR_LENGTH; ++i) {
        msgInfo.packet.chaddr[i] = testMac1[i];
    }
    ret = ReceiveDhcpMessage(1, &msgInfo);
    EXPECT_TRUE(ret == RET_SELECT_TIME_OUT || ret == RET_ERROR || ret == RET_FAILED);
}

HWTEST_F(DhcpServerTest, GetServerStatusTest, TestSize.Level1)
{
    EXPECT_EQ(-1, GetServerStatus(nullptr));
}

HWTEST_F(DhcpServerTest, StopDhcpServerTest, TestSize.Level1)
{
    EXPECT_EQ(RET_FAILED, StopDhcpServer(nullptr));
}

HWTEST_F(DhcpServerTest, FreeServerContextTest, TestSize.Level1)
{
    EXPECT_EQ(RET_FAILED, FreeServerContext(nullptr));
}

HWTEST_F(DhcpServerTest, SaveLeaseFailedTest, TestSize.Level1)
{
    DhcpServerContext tempCtx;
    tempCtx.instance = nullptr;
    ASSERT_TRUE(memset_s(&tempCtx, sizeof(DhcpServerContext), 0, sizeof(DhcpServerContext)) == EOK);
    EXPECT_EQ(RET_FAILED, SaveLease(nullptr));
    EXPECT_EQ(RET_FAILED, SaveLease(&tempCtx));
}

HWTEST_F(DhcpServerTest, GetVendorIdentifierOptionTest, TestSize.Level1)
{
    DhcpMsgInfo received;
    ASSERT_TRUE(memset_s(&received, sizeof(PDhcpMsgInfo), 0, sizeof(PDhcpMsgInfo)) == EOK);
    EXPECT_EQ(REPLY_NAK, GetVendorIdentifierOption(&received));
}

HWTEST_F(DhcpServerTest, GetHostNameOptionTest, TestSize.Level1)
{
    PDhcpMsgInfo received;
    ASSERT_TRUE(memset_s(&received, sizeof(PDhcpMsgInfo), 0, sizeof(PDhcpMsgInfo)) == EOK);
    EXPECT_EQ(REPLY_NONE, GetHostNameOption(received, nullptr));
}
}
}
