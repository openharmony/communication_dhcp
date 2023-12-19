/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include <sys/stat.h>
#include <fcntl.h>

#include "mock_system_func.h"
#include "mock_custom_func.h"
#include "dhcp_logger.h"
#include "dhcp_client_state_machine.h"
#include "dhcp_client_def.h"
#include "dhcp_function.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpIpv4Test");
1
using namespace testing::ext;
using namespace OHOS::Wifi;
namespace OHOS {
namespace Wifi {
class DhcpIpv4Test : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {}
    virtual void TearDown()
    {}
public:
    std::unique_ptr<OHOS::Wifi::DhcpClientStateMachine> dhcpClient;
};

HWTEST_F(DhcpIpv4Test, ExecDhcpRenew_SUCCESS, TestSize.Level1)
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

HWTEST_F(DhcpIpv4Test, ExecDhcpRelease_SUCCESS, TestSize.Level1)
{
    MockSystemFunc::SetMockFlag(true);

    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _)).WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), setsockopt(_, _, _, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), open(_, _)).WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), read(_, _, _)).WillRepeatedly(Return(500));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), connect(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), write(_, _, _)).WillRepeatedly(Return(1));

    dhcpClient->SetIpv4State(DHCP_STATE_BOUND);
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->ExecDhcpRelease());
    dhcpClient->SetIpv4State(DHCP_STATE_REBINDING);
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->ExecDhcpRelease());

    MockSystemFunc::SetMockFlag(false);
}

HWTEST_F(DhcpIpv4Test, TEST_FAILED, TestSize.Level1)
{
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->SetIpv4State(-1));
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->GetPacketHeaderInfo(NULL, 0));
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->GetPacketCommonInfo(NULL));
}
/**
 * @tc.name: DhcpRenew_FAILED
 * @tc.desc: DhcpRenew()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, DhcpRenew_FAILED, TestSize.Level1)
{
    EXPECT_NE(SOCKET_OPT_ERROR, dhcpClient->DhcpRenew(1, 0, 0));
}
/**
 * @tc.name: DhcpRenew_SUCCESS
 * @tc.desc: DhcpRenew()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, DhcpRenew_SUCCESS, TestSize.Level1)
{
    EXPECT_EQ(SOCKET_OPT_FAILED, dhcpClient->DhcpRenew(1, 0, 1));
}
/**
 * @tc.name: DhcpRequest_SUCCESS
 * @tc.desc: DhcpRequest()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, DhcpRequest_SUCCESS, TestSize.Level1)
{
    EXPECT_NE(SOCKET_OPT_ERROR, dhcpClient->DhcpRequest(1, 0, 1));
}
/**
 * @tc.name: DhcpDiscover_SUCCESS
 * @tc.desc: DhcpDiscover()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, DhcpDiscover_SUCCESS, TestSize.Level1)
{
    EXPECT_NE(SOCKET_OPT_ERROR, dhcpClient->DhcpDiscover(1, 0));
}
/**
 * @tc.name: DhcpDiscover_SUCCESS2
 * @tc.desc: DhcpDiscover()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, DhcpDiscover_SUCCESS2, TestSize.Level1)
{
    EXPECT_NE(SOCKET_OPT_ERROR, dhcpClient->DhcpDiscover(0, 1));
}
/**
 * @tc.name: PublishDhcpResultEvent_Fail1
 * @tc.desc: PublishDhcpResultEvent()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, PublishDhcpResultEvent_Fail1, TestSize.Level1)
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
HWTEST_F(DhcpIpv4Test, PublishDhcpResultEvent_Fail2, TestSize.Level1)
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
HWTEST_F(DhcpIpv4Test, PublishDhcpResultEvent_Fail3, TestSize.Level1)
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
HWTEST_F(DhcpIpv4Test, PublishDhcpResultEvent_Fail4, TestSize.Level1)
{
    DhcpIpResult result;
    char ifname[] = "testcode//";
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->PublishDhcpResultEvent(ifname, PUBLISH_CODE_SUCCESS, &result));
}
/**
 * @tc.name: PublishDhcpResultEvent_Fail5
 * @tc.desc: PublishDhcpResultEvent()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, PublishDhcpResultEvent_Fail5, TestSize.Level1)
{
    DhcpIpResult result;
    char ifname[] = "testcode//";
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->PublishDhcpResultEvent(ifname, PUBLISH_CODE_FAILED, &result));
}
/**
 * @tc.name: SyncDhcpResult_Fail1
 * @tc.desc: SyncDhcpResult()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, SyncDhcpResult_Fail1, TestSize.Level1)
{
    struct DhcpPacket *packet = nullptr;
    DhcpIpResult result;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->SyncDhcpResult(packet, &result));
}
/**
 * @tc.name: SyncDhcpResult_Fail2
 * @tc.desc: SyncDhcpResult()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, SyncDhcpResult_Fail2, TestSize.Level1)
{
    struct DhcpPacket packet;
    DhcpIpResult *result = nullptr;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->SyncDhcpResult(&packet, result));
}
/**
 * @tc.name: SyncDhcpResult_Fail3
 * @tc.desc: SyncDhcpResult()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, SyncDhcpResult_Fail3, TestSize.Level1)
{
    struct DhcpPacket *packet = nullptr;
    DhcpIpResult *result = nullptr;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->SyncDhcpResult(packet, result));
}

/**
 * @tc.name: GetDHCPServerHostName_Fail1
 * @tc.desc: GetDHCPServerHostName()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, GetDHCPServerHostName_Fail1, TestSize.Level1)
{
    struct DhcpPacket *packet = nullptr;
    DhcpIpResult result;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->GetDHCPServerHostName(packet, &result));
}

/**
 * @tc.name: GetDHCPServerHostName_Fail2
 * @tc.desc: GetDHCPServerHostName()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, GetDHCPServerHostName_Fail2, TestSize.Level1)
{
    struct DhcpPacket packet;
    DhcpIpResult *result = nullptr;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->GetDHCPServerHostName(&packet, result));
}

/**
 * @tc.name: GetDHCPServerHostName_Fail3
 * @tc.desc: GetDHCPServerHostName()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, GetDHCPServerHostName_Fail3, TestSize.Level1)
{
    struct DhcpPacket *packet = nullptr;
    DhcpIpResult *result = nullptr;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->GetDHCPServerHostName(packet, result));
}

HWTEST_F(DhcpIpv4Test, SetSocketModeTest, TestSize.Level1)
{
    DHCP_LOGE("SetSocketModeTest enter!");
    dhcpClient->SetSocketMode(1);
}

HWTEST_F(DhcpIpv4Test, DhcpReleaseTest, TestSize.Level1)
{
    DHCP_LOGE("DhcpReleaseTest enter!");
    int result = dhcpClient->DhcpRelease(1, 1);
    DHCP_LOGE("DhcpReleaseTest result(%{public}d)", result);
    EXPECT_NE(result, DHCP_OPT_SUCCESS);
}

HWTEST_F(DhcpIpv4Test, StartIpv4Test, TestSize.Level1)
{
    DHCP_LOGE("StartIpv4Test enter!");
    int result = dhcpClient->StartIpv4();
    DHCP_LOGE("StartIpv4Test result(%{public}d)", result);
    EXPECT_EQ(result, DHCP_OPT_SUCCESS);
}

HWTEST_F(DhcpIpv4Test, SendRebootTest, TestSize.Level1)
{
    DHCP_LOGE("SendRebootTest enter!");
    dhcpClient->SendReboot(nullptr, 1);
}

HWTEST_F(DhcpIpv4Test, GetPacketReadSockFdTest, TestSize.Level1)
{
    DHCP_LOGE("GetPacketReadSockFdTest enter!");
    dhcpClient->GetPacketReadSockFd();
}

HWTEST_F(DhcpIpv4Test, GetSigReadSockFdTest, TestSize.Level1)
{
    DHCP_LOGE("GetSigReadSockFdTest enter!");
    dhcpClient->GetSigReadSockFd();
}

HWTEST_F(DhcpIpv4Test, GetDhcpTransIDTest, TestSize.Level1)
{
    DHCP_LOGE("GetDhcpTransIDTest enter!");
    dhcpClient->GetDhcpTransID();
}

HWTEST_F(DhcpIpv4Test, GetPacketHeaderInfoTest, TestSize.Level1)
{
    struct DhcpPacket packet;
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->GetPacketHeaderInfo(&packet, DHCP_NAK));
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->GetPacketHeaderInfo(&packet, DHCP_FORCERENEW));
}
}
}
