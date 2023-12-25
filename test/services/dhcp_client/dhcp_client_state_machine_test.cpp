/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
1
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "mock_system_func.h"
#include "mock_custom_func.h"
#include "dhcp_logger.h"
#include "dhcp_client_state_machine.h"
#include "dhcp_client_def.h"
#include "dhcp_function.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpClientStateMachineTest");

using namespace testing::ext;
using namespace OHOS::Wifi;
namespace OHOS {
namespace Wifi {
class DhcpClientStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        std::string ifnametest = "wlan0";
        dhcpClient = std::make_unique<OHOS::Wifi::DhcpClientStateMachine>(ifnametest);
    }
    virtual void TearDown()
    {
        if (dhcpClient != nullptr) {
            dhcpClient.reset(nullptr);
        }
    }
public:
    std::unique_ptr<OHOS::Wifi::DhcpClientStateMachine> dhcpClient;
};

HWTEST_F(DhcpClientStateMachineTest, ExecDhcpRenew_SUCCESS, TestSize.Level1)
{
    DHCP_LOGE("enter ExecDhcpRenew_SUCCESS");
    MockSystemFunc::SetMockFlag(true);

    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_)).WillRepeatedly(Return(0));

    dhcpClient->SetIpv4State(DHCP_STATE_INIT);
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->ExecDhcpRenew());
    dhcpClient->SetIpv4State(DHCP_STATE_REQUESTING);
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->ExecDhcpRenew());
    dhcpClient->SetIpv4State(DHCP_STATE_BOUND);
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->ExecDhcpRenew());
    dhcpClient->SetIpv4State(DHCP_STATE_RENEWING);
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->ExecDhcpRenew());
    dhcpClient->SetIpv4State(DHCP_STATE_INITREBOOT);
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->ExecDhcpRenew());
    MockSystemFunc::SetMockFlag(false);
}

HWTEST_F(DhcpClientStateMachineTest, TEST_FAILED, TestSize.Level1)
{
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->SetIpv4State(-1));
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->GetPacketHeaderInfo(NULL, 0));
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->GetPacketCommonInfo(NULL));
}
/**
 * @tc.name: PublishDhcpResultEvent_Fail1
 * @tc.desc: PublishDhcpResultEvent()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, PublishDhcpResultEvent_Fail1, TestSize.Level1)
{
    DhcpIpResult result;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->PublishDhcpResultEvent(nullptr, PUBLISH_CODE_SUCCESS, &result));
}
/**
 * @tc.name: PublishDhcpResultEvent_Fail2
 * @tc.desc: PublishDhcpResultEvent()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, PublishDhcpResultEvent_Fail2, TestSize.Level1)
{
    DhcpIpResult result;
    char ifname[] = "testcode//";
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->PublishDhcpResultEvent(ifname, DHCP_HWADDR_LENGTH, &result));
}
/**
 * @tc.name: PublishDhcpResultEvent_Fail3
 * @tc.desc: PublishDhcpResultEvent()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, PublishDhcpResultEvent_Fail3, TestSize.Level1)
{
    DhcpIpResult *result = NULL;
    char ifname[] = "testcode//";
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->PublishDhcpResultEvent(ifname, PUBLISH_CODE_SUCCESS, result));
}
/**
 * @tc.name: PublishDhcpResultEvent_Fail4
 * @tc.desc: PublishDhcpResultEvent()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, PublishDhcpResultEvent_Fail4, TestSize.Level1)
{
    DhcpIpResult result;
    char ifname[] = "testcode//";
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->PublishDhcpResultEvent(ifname, PUBLISH_CODE_SUCCESS, &result));
}
/**
 * @tc.name: PublishDhcpResultEvent_Fail5
 * @tc.desc: PublishDhcpResultEvent()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, PublishDhcpResultEvent_Fail5, TestSize.Level1)
{
    DhcpIpResult result;
    char ifname[] = "testcode//";
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->PublishDhcpResultEvent(ifname, PUBLISH_CODE_FAILED, &result));
}

HWTEST_F(DhcpClientStateMachineTest, GetDHCPServerHostName_Fail3, TestSize.Level1)
{
    struct DhcpPacket *packet = nullptr;
    DhcpIpResult *result = nullptr;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->GetDHCPServerHostName(packet, result));
}

HWTEST_F(DhcpClientStateMachineTest, SetSocketModeTest, TestSize.Level1)
{
    DHCP_LOGE("SetSocketModeTest enter!");
    dhcpClient->SetSocketMode(1);
}

HWTEST_F(DhcpClientStateMachineTest, SendRebootTest, TestSize.Level1)
{
    DHCP_LOGE("SendRebootTest enter!");
    dhcpClient->SendReboot(nullptr, 1);
}

HWTEST_F(DhcpClientStateMachineTest, GetPacketReadSockFdTest, TestSize.Level1)
{
    DHCP_LOGE("GetPacketReadSockFdTest enter!");
    dhcpClient->GetPacketReadSockFd();
}

HWTEST_F(DhcpClientStateMachineTest, GetSigReadSockFdTest, TestSize.Level1)
{
    DHCP_LOGE("GetSigReadSockFdTest enter!");
    dhcpClient->GetSigReadSockFd();
}

HWTEST_F(DhcpClientStateMachineTest, GetDhcpTransIDTest, TestSize.Level1)
{
    DHCP_LOGE("GetDhcpTransIDTest enter!");
    dhcpClient->GetDhcpTransID();
}

HWTEST_F(DhcpClientStateMachineTest, GetPacketHeaderInfoTest, TestSize.Level1)
{
    struct DhcpPacket packet;
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->GetPacketHeaderInfo(&packet, DHCP_NAK));
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->GetPacketHeaderInfo(&packet, DHCP_FORCERENEW));
}
}
}
