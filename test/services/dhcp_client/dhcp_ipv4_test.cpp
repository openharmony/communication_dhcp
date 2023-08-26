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
#include "wifi_log.h"
#include "dhcp_ipv4.h"
#include "dhcp_client.h"
#include "dhcp_function.h"

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
};

HWTEST_F(DhcpIpv4Test, ExecDhcpRenew_SUCCESS, TestSize.Level1)
{
    MockSystemFunc::SetMockFlag(true);

    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_)).WillRepeatedly(Return(0));

    SetIpv4State(DHCP_STATE_INIT);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ExecDhcpRenew());
    SetIpv4State(DHCP_STATE_REQUESTING);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ExecDhcpRenew());
    SetIpv4State(DHCP_STATE_BOUND);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ExecDhcpRenew());
    SetIpv4State(DHCP_STATE_RENEWING);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ExecDhcpRenew());

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

    SetIpv4State(DHCP_STATE_BOUND);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ExecDhcpRelease());

    MockSystemFunc::SetMockFlag(false);
}

HWTEST_F(DhcpIpv4Test, TEST_FAILED, TestSize.Level1)
{
    EXPECT_EQ(DHCP_OPT_FAILED, SetIpv4State(-1));
    EXPECT_EQ(DHCP_OPT_FAILED, GetPacketHeaderInfo(NULL, 0));
    EXPECT_EQ(DHCP_OPT_FAILED, GetPacketCommonInfo(NULL));
}
/**
 * @tc.name: DhcpRenew_FAILED
 * @tc.desc: DhcpRenew()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, DhcpRenew_FAILED, TestSize.Level1)
{
    EXPECT_EQ(SOCKET_OPT_FAILED, DhcpRenew(1, 0, 0));
}
/**
 * @tc.name: DhcpRenew_SUCCESS
 * @tc.desc: DhcpRenew()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, DhcpRenew_SUCCESS, TestSize.Level1)
{
    EXPECT_EQ(SOCKET_OPT_FAILED, DhcpRenew(1, 0, 1));
}
/**
 * @tc.name: DhcpRequest_SUCCESS
 * @tc.desc: DhcpRequest()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, DhcpRequest_SUCCESS, TestSize.Level1)
{
    EXPECT_EQ(SOCKET_OPT_FAILED, DhcpRequest(1, 0, 1));
}
/**
 * @tc.name: DhcpDiscover_SUCCESS
 * @tc.desc: DhcpDiscover()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, DhcpDiscover_SUCCESS, TestSize.Level1)
{
    EXPECT_EQ(SOCKET_OPT_FAILED, DhcpDiscover(1, 0));
}
/**
 * @tc.name: DhcpDiscover_SUCCESS2
 * @tc.desc: DhcpDiscover()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, DhcpDiscover_SUCCESS2, TestSize.Level1)
{
    EXPECT_EQ(SOCKET_OPT_FAILED, DhcpDiscover(0, 1));
}
/**
 * @tc.name: PublishDhcpResultEvent_Fail1
 * @tc.desc: PublishDhcpResultEvent()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, PublishDhcpResultEvent_Fail1, TestSize.Level1)
{
    DhcpResult result;
    EXPECT_EQ(DHCP_OPT_FAILED, PublishDhcpResultEvent(nullptr, PUBLISH_CODE_SUCCESS, &result));
}
/**
 * @tc.name: PublishDhcpResultEvent_Fail2
 * @tc.desc: PublishDhcpResultEvent()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, PublishDhcpResultEvent_Fail2, TestSize.Level1)
{
    DhcpResult result;
    char ifname[] = "testcode//";
    EXPECT_EQ(DHCP_OPT_FAILED, PublishDhcpResultEvent(ifname, DHCP_HWADDR_LENGTH, &result));
}
/**
 * @tc.name: PublishDhcpResultEvent_Fail3
 * @tc.desc: PublishDhcpResultEvent()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, PublishDhcpResultEvent_Fail3, TestSize.Level1)
{
    DhcpResult *result = NULL;
    char ifname[] = "testcode//";
    EXPECT_EQ(DHCP_OPT_FAILED, PublishDhcpResultEvent(ifname, PUBLISH_CODE_SUCCESS, result));
}
/**
 * @tc.name: PublishDhcpResultEvent_Fail4
 * @tc.desc: PublishDhcpResultEvent()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, PublishDhcpResultEvent_Fail4, TestSize.Level1)
{
    DhcpResult result;
    char ifname[] = "testcode//";
    EXPECT_EQ(DHCP_OPT_SUCCESS, PublishDhcpResultEvent(ifname, PUBLISH_CODE_SUCCESS, &result));
}
/**
 * @tc.name: PublishDhcpResultEvent_Fail5
 * @tc.desc: PublishDhcpResultEvent()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpIpv4Test, PublishDhcpResultEvent_Fail5, TestSize.Level1)
{
    DhcpResult result;
    char ifname[] = "testcode//";
    EXPECT_EQ(DHCP_OPT_SUCCESS, PublishDhcpResultEvent(ifname, PUBLISH_CODE_FAILED, &result));
}

HWTEST_F(DhcpIpv4Test, SetSocketModeTest, TestSize.Level1)
{
    LOGE("SetSocketModeTest enter!");
    SetSocketMode(1);
}

HWTEST_F(DhcpIpv4Test, InitSignalHandleTest, TestSize.Level1)
{
    LOGE("InitSignalHandleTest enter!");
    int result = InitSignalHandle();
    LOGE("InitSignalHandleTest result(%{public}d)", result);
    EXPECT_EQ(result, DHCP_OPT_SUCCESS);
}

HWTEST_F(DhcpIpv4Test, DhcpReleaseTest, TestSize.Level1)
{
    LOGE("DhcpReleaseTest enter!");
    int result = DhcpRelease(1, 1);
    LOGE("DhcpReleaseTest result(%{public}d)", result);
    EXPECT_EQ(result, DHCP_OPT_FAILED);
}

HWTEST_F(DhcpIpv4Test, StartIpv4Test, TestSize.Level1)
{
    LOGE("StartIpv4Test enter!");
    int result = StartIpv4();
    LOGE("StartIpv4Test result(%{public}d)", result);
    EXPECT_EQ(result, DHCP_OPT_SUCCESS);
}

HWTEST_F(DhcpIpv4Test, SendRebootTest, TestSize.Level1)
{
    LOGE("SendRebootTest enter!");
    SendReboot(nullptr, 1);
}

HWTEST_F(DhcpIpv4Test, GetPacketReadSockFdTest, TestSize.Level1)
{
    LOGE("GetPacketReadSockFdTest enter!");
    GetPacketReadSockFd();
}

HWTEST_F(DhcpIpv4Test, GetSigReadSockFdTest, TestSize.Level1)
{
    LOGE("GetSigReadSockFdTest enter!");
    GetSigReadSockFd();
}

HWTEST_F(DhcpIpv4Test, GetDhcpTransIDTest, TestSize.Level1)
{
    LOGE("GetDhcpTransIDTest enter!");
    GetDhcpTransID();
}
}
}
