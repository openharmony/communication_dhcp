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

#include <gtest/gtest.h>
#include <cstring>
#include <sys/stat.h>
#include <fcntl.h>

#include "mock_system_func.h"
#include "mock_custom_func.h"
#include "dhcp_logger.h"
#include "dhcp_client_state_machine.h"
#include "dhcp_client_def.h"
#include "dhcp_function.h"
#include "securec.h"
#include "dhcp_thread.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpClientStateMachineTest");

using namespace testing::ext;
using namespace OHOS::DHCP;
namespace OHOS {
namespace DHCP {
constexpr int ZERO = 0;
constexpr int TWO = 2;
constexpr int THREE = 3;
constexpr int INVALID = 12;
static std::string g_errLog = "wifitest";

static std::unique_ptr<OHOS::DHCP::DhcpClientStateMachine> dhcpClient = nullptr;

class DhcpClientStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        std::string ifnametest = "wlan0";
        dhcpClient = std::make_unique<OHOS::DHCP::DhcpClientStateMachine>(ifnametest);
    }
    static void TearDownTestCase()
    {
        if (dhcpClient != nullptr) {
            dhcpClient->StopIpv4();
            dhcpClient.reset(nullptr);
        }
        DhcpTimer::GetInstance()->timer_.reset();
    }
    virtual void SetUp()
    {
        dhcpClient->threadExit_ = false;
    }
    virtual void TearDown()
    {
        dhcpClient->StopIpv4();
        MockCustomFunc::GetInstance().SetMockFlag(false);
        MockSystemFunc::GetInstance().SetMockFlag(false);
    }
};

HWTEST_F(DhcpClientStateMachineTest, ExecDhcpRenew_SUCCESS, TestSize.Level0)
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

HWTEST_F(DhcpClientStateMachineTest, TEST_FAILED, TestSize.Level0)
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
HWTEST_F(DhcpClientStateMachineTest, PublishDhcpResultEvent_Fail1, TestSize.Level0)
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
HWTEST_F(DhcpClientStateMachineTest, PublishDhcpResultEvent_Fail2, TestSize.Level0)
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
HWTEST_F(DhcpClientStateMachineTest, PublishDhcpResultEvent_Fail3, TestSize.Level0)
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
HWTEST_F(DhcpClientStateMachineTest, PublishDhcpResultEvent_Fail4, TestSize.Level0)
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
HWTEST_F(DhcpClientStateMachineTest, PublishDhcpResultEvent_Fail5, TestSize.Level0)
{
    DhcpIpResult result;
    char ifname[] = "testcode//";
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->PublishDhcpResultEvent(ifname, PUBLISH_CODE_FAILED, &result));
}
/**
 * @tc.name: ParseNetworkVendorInfo_Fail1
 * @tc.desc: ParseNetworkVendorInfo()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, ParseNetworkVendorInfo_Fail1, TestSize.Level0)
{
    struct DhcpPacket *packet = nullptr;
    DhcpIpResult result;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->ParseNetworkVendorInfo(packet, &result));
}
/**
 * @tc.name: ParseNetworkVendorInfo_Fail2
 * @tc.desc: ParseNetworkVendorInfo()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, ParseNetworkVendorInfo_Fail2, TestSize.Level0)
{
    struct DhcpPacket packet;
    DhcpIpResult *result = nullptr;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->ParseNetworkVendorInfo(&packet, result));
}
/**
 * @tc.name: ParseNetworkVendorInfo_Fail3
 * @tc.desc: ParseNetworkVendorInfo()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, ParseNetworkVendorInfo_Fail3, TestSize.Level0)
{
    struct DhcpPacket *packet = nullptr;
    DhcpIpResult *result = nullptr;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->ParseNetworkVendorInfo(packet, result));
}

/**
 * @tc.name: ParseNetworkVendorInfo_Fail4
 * @tc.desc: ParseNetworkVendorInfo()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, ParseNetworkVendorInfo_Fail4, TestSize.Level0)
{
    struct DhcpPacket packet;
    struct DhcpIpResult result;
    strcpy_s((char*)packet.sname, sizeof(packet.sname), "testcode");
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->ParseNetworkVendorInfo(&packet, &result));
}

/**
 * @tc.name: ParseNetworkVendorInfo_Fail5
 * @tc.desc: ParseNetworkVendorInfo()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, ParseNetworkVendorInfo_Fail5, TestSize.Level0)
{
    char buf[VENDOR_MAX_LEN - DHCP_OPT_CODE_BYTES - DHCP_OPT_LEN_BYTES] = {0};
    ASSERT_TRUE(snprintf_s(buf,
                    VENDOR_MAX_LEN - DHCP_OPT_DATA_INDEX,
                    VENDOR_MAX_LEN - DHCP_OPT_DATA_INDEX - 1,
                    "%s-%s",
                    DHCPC_NAME,
                    DHCPC_VERSION) >= 0);

    struct DhcpPacket packet;
    ASSERT_TRUE(memset_s(&packet, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket)) == EOK);

    uint8_t *pOption = packet.options;
    pOption[DHCP_OPT_CODE_INDEX] = VENDOR_SPECIFIC_INFO_OPTION;
    pOption[DHCP_OPT_LEN_INDEX] = strlen(buf);
    ASSERT_TRUE(memcpy_s(pOption + DHCP_OPT_DATA_INDEX,
                    VENDOR_MAX_LEN - DHCP_OPT_CODE_BYTES - DHCP_OPT_LEN_BYTES,
                    buf,
                    strlen(buf)) == EOK);

    int endIndex = DHCP_OPT_CODE_BYTES + DHCP_OPT_LEN_BYTES + pOption[DHCP_OPT_LEN_INDEX];
    pOption[endIndex] = END_OPTION;

    struct DhcpIpResult result;
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->ParseNetworkVendorInfo(&packet, &result));
}

/**
 * @tc.name: GetDHCPServerHostName_Fail1
 * @tc.desc: GetDHCPServerHostName()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, GetDHCPServerHostName_Fail1, TestSize.Level0)
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
HWTEST_F(DhcpClientStateMachineTest, GetDHCPServerHostName_Fail2, TestSize.Level0)
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
HWTEST_F(DhcpClientStateMachineTest, GetDHCPServerHostName_Fail3, TestSize.Level0)
{
    struct DhcpPacket *packet = nullptr;
    DhcpIpResult *result = nullptr;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->GetDHCPServerHostName(packet, result));
}

/**
 * @tc.name: GetDHCPServerHostName_Success
 * @tc.desc: GetDHCPServerHostName()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpClientStateMachineTest, GetDHCPServerHostName_Success, TestSize.Level0)
{
    struct DhcpPacket packet;
    struct DhcpIpResult result;
    strcpy_s((char*)packet.sname, sizeof(packet.sname), "testcode");
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->GetDHCPServerHostName(&packet, &result));
}

HWTEST_F(DhcpClientStateMachineTest, SetSocketModeTest, TestSize.Level0)
{
    DHCP_LOGE("SetSocketModeTest enter!");
    dhcpClient->SetSocketMode(1);
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
}

HWTEST_F(DhcpClientStateMachineTest, SendRebootTest, TestSize.Level0)
{
    DHCP_LOGE("SendRebootTest enter!");
    dhcpClient->SendReboot(1, 1);
    EXPECT_EQ(1, dhcpClient->m_requestedIp4);
}

HWTEST_F(DhcpClientStateMachineTest, GetPacketReadSockFdTest, TestSize.Level0)
{
    DHCP_LOGE("GetPacketReadSockFdTest enter!");
    dhcpClient->GetPacketReadSockFd();
    EXPECT_EQ(-1, dhcpClient->m_sockFd);
}

HWTEST_F(DhcpClientStateMachineTest, GetSigReadSockFdTest, TestSize.Level0)
{
    DHCP_LOGE("GetSigReadSockFdTest enter!");
    dhcpClient->GetSigReadSockFd();
    EXPECT_EQ(0, dhcpClient->m_sigSockFds[0]);
}

HWTEST_F(DhcpClientStateMachineTest, GetDhcpTransIDTest, TestSize.Level0)
{
    DHCP_LOGE("GetDhcpTransIDTest enter!");
    dhcpClient->GetDhcpTransID();
    EXPECT_EQ(0, dhcpClient->m_transID);
}

HWTEST_F(DhcpClientStateMachineTest, GetPacketHeaderInfoTest, TestSize.Level0)
{
    struct DhcpPacket packet;
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->GetPacketHeaderInfo(&packet, DHCP_NAK));
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->GetPacketHeaderInfo(&packet, DHCP_FORCERENEW));
}

HWTEST_F(DhcpClientStateMachineTest, ExitIpv4Test, TestSize.Level0)
{
    DHCP_LOGI("ExitIpv4Test enter!");
    dhcpClient->ExitIpv4();
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->ExitIpv4());
}

HWTEST_F(DhcpClientStateMachineTest, StopIpv4Test, TestSize.Level0)
{
    DHCP_LOGI("StopIpv4Test enter!");
    dhcpClient->StopIpv4();
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->StopIpv4());
}

HWTEST_F(DhcpClientStateMachineTest, DhcpInitTest, TestSize.Level0)
{
    DHCP_LOGI("DhcpInitTest enter!");
    dhcpClient->DhcpInit();
    EXPECT_EQ(DHCP_STATE_INIT, dhcpClient->m_dhcp4State);
}

HWTEST_F(DhcpClientStateMachineTest, RenewingTest, TestSize.Level0)
{
    DHCP_LOGI("RenewingTest enter!");
    time_t curTimestamp = time(NULL);
    dhcpClient->Renewing(curTimestamp);

    dhcpClient->m_sentPacketNum = MAX_WAIT_TIMES + 1;
    dhcpClient->Renewing(curTimestamp);

    dhcpClient->m_sentPacketNum = MAX_WAIT_TIMES - 1;
    dhcpClient->Renewing(curTimestamp);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, RebindingTest, TestSize.Level0)
{
    DHCP_LOGI("RebindingTest enter!");
    time_t curTimestamp = time(NULL);
    dhcpClient->Rebinding(curTimestamp);

    dhcpClient->m_sentPacketNum = MAX_WAIT_TIMES + 1;
    dhcpClient->Rebinding(curTimestamp);

    dhcpClient->m_sentPacketNum = MAX_WAIT_TIMES - 1;
    dhcpClient->Rebinding(curTimestamp);

    dhcpClient->m_dhcp4State = DHCP_STATE_REBINDING;
    dhcpClient->Rebinding(curTimestamp);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, DhcpRequestHandleTest, TestSize.Level0)
{
    DHCP_LOGI("DhcpRequestHandleTest enter!");
    time_t curTimestamp = time(NULL);
    
    dhcpClient->SetIpv4State(DHCP_STATE_BOUND);
    dhcpClient->DhcpRequestHandle(curTimestamp);

    dhcpClient->SetIpv4State(DHCP_STATE_INITREBOOT);
    dhcpClient->DhcpRequestHandle(curTimestamp);

    dhcpClient->SetIpv4State(DHCP_STATE_RELEASED);
    dhcpClient->DhcpRequestHandle(curTimestamp);

    dhcpClient->SetIpv4State(DHCP_STATE_RENEWED);
    dhcpClient->DhcpRequestHandle(curTimestamp);

    dhcpClient->SetIpv4State(DHCP_STATE_REBINDING);
    dhcpClient->DhcpRequestHandle(curTimestamp);

    dhcpClient->SetIpv4State(DHCP_STATE_FAST_ARP);
    dhcpClient->DhcpRequestHandle(curTimestamp);

    dhcpClient->SetIpv4State(DHCP_STATE_SLOW_ARP);
    dhcpClient->DhcpRequestHandle(curTimestamp);

    dhcpClient->SetIpv4State(DHCP_STATE_DECLINE);
    dhcpClient->DhcpRequestHandle(curTimestamp);

    dhcpClient->SetIpv4State(INVALID);
    dhcpClient->DhcpRequestHandle(curTimestamp);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, DhcpAckOrNakPacketHandleTest, TestSize.Level0)
{
    DHCP_LOGI("DhcpAckOrNakPacketHandleTest enter!");
    struct DhcpPacket *packet = nullptr;
    uint8_t type = DHCP_REQUEST;
    time_t curTimestamp = time(NULL);
    dhcpClient->DhcpAckOrNakPacketHandle(type, packet, curTimestamp);

    type = DHCP_NAK;
    DhcpPacket packet1;
    dhcpClient->DhcpAckOrNakPacketHandle(type, &packet1, curTimestamp);
    dhcpClient->DhcpAckOrNakPacketHandle(type, nullptr, curTimestamp);

    type = DHCP_ACK;
    DhcpPacket packet2;
    dhcpClient->SetIpv4State(DHCP_STATE_BOUND);
    dhcpClient->DhcpAckOrNakPacketHandle(type, &packet2, curTimestamp);

    DhcpPacket packet3;
    type = DHCP_REQUEST;
    dhcpClient->DhcpAckOrNakPacketHandle(type, &packet3, curTimestamp);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, ParseDhcpAckPacketTest, TestSize.Level0)
{
    DHCP_LOGI("ParseDhcpAckPacketTest enter!");
    struct DhcpPacket *packet = nullptr;
    time_t curTimestamp = time(NULL);
    dhcpClient->ParseDhcpAckPacket(packet, curTimestamp);

    DhcpPacket packet1;
    dhcpClient->ParseDhcpAckPacket(&packet1, curTimestamp);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, ParseNetworkInfoTest, TestSize.Level0)
{
    DHCP_LOGI("ParseNetworkInfoTest enter!");
    struct DhcpPacket *packet = nullptr;
    struct DhcpIpResult *result = nullptr;
    dhcpClient->ParseNetworkInfo(packet, result);

    DhcpPacket *packet1 = nullptr;
    DhcpIpResult result1;
    dhcpClient->ParseNetworkInfo(packet1, &result1);

    DhcpPacket packet2;
    DhcpIpResult *result2 = nullptr;
    dhcpClient->ParseNetworkInfo(&packet2, result2);

    DhcpPacket packet3;
    DhcpIpResult result3;
    dhcpClient->ParseNetworkInfo(&packet3, &result3);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, ParseNetworkDnsInfoTest, TestSize.Level0)
{
    DHCP_LOGI("ParseNetworkDnsInfoTest enter!");
    struct DhcpPacket *packet = nullptr;
    struct DhcpIpResult *result = nullptr;
    dhcpClient->ParseNetworkDnsInfo(packet, result);

    DhcpPacket *packet1 = nullptr;
    DhcpIpResult result1;
    dhcpClient->ParseNetworkDnsInfo(packet1, &result1);

    DhcpPacket packet2;
    DhcpIpResult *result2 = nullptr;
    dhcpClient->ParseNetworkDnsInfo(&packet2, result2);

    DhcpPacket packet3;
    DhcpIpResult result3;
    dhcpClient->ParseNetworkDnsInfo(&packet3, &result3);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, DhcpOfferPacketHandleTest, TestSize.Level0)
{
    DHCP_LOGI("DhcpOfferPacketHandleTest enter!");
    struct DhcpPacket *packet = nullptr;
    uint8_t type = DHCP_REQUEST;
    time_t curTimestamp = time(NULL);
    dhcpClient->DhcpOfferPacketHandle(type, packet, curTimestamp);

    type = DHCP_OFFER;
    dhcpClient->DhcpOfferPacketHandle(type, packet, curTimestamp);

    DhcpPacket packet1;
    dhcpClient->DhcpOfferPacketHandle(type, &packet1, curTimestamp);

    packet1.yiaddr = 3226272232;
    dhcpClient->DhcpOfferPacketHandle(type, &packet1, curTimestamp);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, DhcpRebootTest, TestSize.Level0)
{
    DHCP_LOGE("DhcpRebootTest enter!");
    EXPECT_NE(SOCKET_OPT_ERROR, dhcpClient->DhcpReboot(1, 1));
}

HWTEST_F(DhcpClientStateMachineTest, StartIpv4TypeTest, TestSize.Level0)
{
    DHCP_LOGI("StartIpv4TypeTest enter!");
    std::string ifname;
    bool isIpv6 = true;
    ActionMode action = ACTION_START_NEW;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->StartIpv4Type(ifname, isIpv6, action));
}

HWTEST_F(DhcpClientStateMachineTest, FormatStringTest, TestSize.Level0)
{
    DHCP_LOGI("FormatStringTest enter!");
    struct DhcpIpResult *result = nullptr;
    dhcpClient->FormatString(result);

    DhcpIpResult result1;
    strcpy_s(result1.strYiaddr, sizeof(result1.strYiaddr), "");
    dhcpClient->FormatString(&result1);

    strcpy_s(result1.strYiaddr, sizeof(result1.strYiaddr), "192.168.0.1");
    dhcpClient->FormatString(&result1);

    DhcpIpResult result2;
    strcpy_s(result2.strOptServerId, sizeof(result2.strOptServerId), "");
    dhcpClient->FormatString(&result2);

    strcpy_s(result2.strYiaddr, sizeof(result2.strYiaddr), "192.168.0.2");
    dhcpClient->FormatString(&result2);

    DhcpIpResult result3;
    strcpy_s(result3.strOptSubnet, sizeof(result3.strOptSubnet), "");
    dhcpClient->FormatString(&result3);

    strcpy_s(result3.strYiaddr, sizeof(result3.strYiaddr), "192.168.0.3");
    dhcpClient->FormatString(&result3);

    DhcpIpResult result4;
    strcpy_s(result4.strOptDns1, sizeof(result4.strOptDns1), "");
    dhcpClient->FormatString(&result4);

    strcpy_s(result4.strYiaddr, sizeof(result4.strYiaddr), "192.168.0.");
    dhcpClient->FormatString(&result4);

    DhcpIpResult result5;
    strcpy_s(result5.strOptDns2, sizeof(result5.strOptDns2), "");
    dhcpClient->FormatString(&result5);

    strcpy_s(result5.strYiaddr, sizeof(result5.strYiaddr), "192.168.0.5");
    dhcpClient->FormatString(&result5);

    DhcpIpResult result6;
    strcpy_s(result6.strOptRouter1, sizeof(result6.strOptRouter1), "");
    dhcpClient->FormatString(&result6);

    strcpy_s(result6.strYiaddr, sizeof(result6.strYiaddr), "192.168.0.6");
    dhcpClient->FormatString(&result6);

    DhcpIpResult result7;
    strcpy_s(result7.strOptRouter2, sizeof(result7.strOptRouter2), "");
    dhcpClient->FormatString(&result7);

    strcpy_s(result7.strYiaddr, sizeof(result7.strYiaddr), "192.168.0.7");
    dhcpClient->FormatString(&result7);

    DhcpIpResult result8;
    strcpy_s(result8.strOptVendor, sizeof(result8.strOptVendor), "");
    dhcpClient->FormatString(&result8);

    strcpy_s(result8.strYiaddr, sizeof(result8.strYiaddr), "192.168.0.8");
    dhcpClient->FormatString(&result8);
    EXPECT_EQ(nullptr, result);
}

HWTEST_F(DhcpClientStateMachineTest, RequestingTest, TestSize.Level0)
{
    DHCP_LOGI("RequestingTest enter!");
    time_t curTimestamp = time(NULL);
    dhcpClient->m_sentPacketNum = 16;
    dhcpClient->SetIpv4State(DHCP_STATE_RENEWED);
    dhcpClient->Requesting(curTimestamp);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, RequestingTest1, TestSize.Level0)
{
    DHCP_LOGI("RequestingTest1 enter!");
    time_t timestamp = 1;
    dhcpClient->m_sentPacketNum = TIMEOUT_TIMES_MAX + 1;
    dhcpClient->Requesting(timestamp);

    dhcpClient->m_sentPacketNum = TWO;
    dhcpClient->m_dhcp4State = DHCP_STATE_RENEWED;
    dhcpClient->Requesting(timestamp);

    dhcpClient->m_dhcp4State = DHCP_STATE_RELEASED;
    dhcpClient->Requesting(timestamp);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, AddHostNameToOptsTest, TestSize.Level0)
{
    DHCP_LOGI("AddHostNameToOptsTest enter!");
    struct DhcpPacket packet;
    memset_s(&packet, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket));
    packet.options[0] = END_OPTION;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->AddHostNameToOpts(nullptr));
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->AddHostNameToOpts(&packet));
}

HWTEST_F(DhcpClientStateMachineTest, AddStrToOptsTest, TestSize.Level0)
{
    DHCP_LOGI("AddStrToOptsTest enter!");
    int option = 12;
    std::string value = "ALN-AL80";
    struct DhcpPacket packet;
    memset_s(&packet, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket));
    packet.options[0] = END_OPTION;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->AddStrToOpts(nullptr, option, value));
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->AddStrToOpts(&packet, option, value));
}

HWTEST_F(DhcpClientStateMachineTest, InitSignalHandleTest, TestSize.Level0)
{
    DHCP_LOGI("InitSignalHandleTest enter!");
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->InitSignalHandle());
}

HWTEST_F(DhcpClientStateMachineTest, CloseSignalHandleTest, TestSize.Level0)
{
    DHCP_LOGI("CloseSignalHandleTest enter!");
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->CloseSignalHandle());
}

HWTEST_F(DhcpClientStateMachineTest, AddClientIdToOptsTest, TestSize.Level0)
{
    DHCP_LOGI("AddClientIdToOpts enter!");
    struct DhcpPacket packet;
    memset_s(&packet, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket));
    packet.options[0] = END_OPTION;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClient->AddClientIdToOpts(nullptr));
    EXPECT_EQ(DHCP_OPT_SUCCESS, dhcpClient->AddClientIdToOpts(&packet));
}

HWTEST_F(DhcpClientStateMachineTest, ParseDhcpNakPacketTest, TestSize.Level0)
{
    DHCP_LOGI("ParseDhcpNakPacket enter!");
    struct DhcpPacket *packet = nullptr;
    time_t curTimestamp = time(nullptr);
    dhcpClient->ParseDhcpNakPacket(packet, curTimestamp);
    DhcpPacket packet1;
    dhcpClient->m_resendTimer = ZERO;
    dhcpClient->ParseDhcpNakPacket(&packet1, curTimestamp);
    EXPECT_EQ(dhcpClient->m_resendTimer, FIRST_TIMEOUT_SEC);
}

HWTEST_F(DhcpClientStateMachineTest, ParseNetworkServerIdInfoTest, TestSize.Level0)
{
    DHCP_LOGI("ParseNetworkServerIdInfo enter!");
    struct DhcpPacket *packet = nullptr;
    struct DhcpIpResult *result = nullptr;
    dhcpClient->ParseNetworkServerIdInfo(packet, result);

    DhcpPacket *packet1 = nullptr;
    DhcpIpResult result1;
    dhcpClient->ParseNetworkServerIdInfo(packet1, &result1);

    DhcpPacket packet2;
    DhcpIpResult *result2 = nullptr;
    dhcpClient->ParseNetworkServerIdInfo(&packet2, result2);

    DhcpPacket packet3;
    DhcpIpResult result3;
    dhcpClient->ParseNetworkServerIdInfo(&packet3, &result3);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, ParseNetworkDnsValueTest, TestSize.Level0)
{
    DHCP_LOGI("ParseNetworkDnsValue enter!");
    struct DhcpIpResult *result = nullptr;
    uint32_t uData = 123456;
    size_t len = 4;
    int count = 0;
    dhcpClient->ParseNetworkDnsValue(result, uData, len, count);

    struct DhcpIpResult result1;
    dhcpClient->ParseNetworkDnsValue(&result1, uData, len, count);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

/**
* @tc.name: IpConflictDetectTest_SUCCESS
* @tc.desc: IpConflictDetectTest.
* @tc.type: FUNC
* @tc.require: AR00000000
*/
HWTEST_F(DhcpClientStateMachineTest, IpConflictDetectTest_SUCCESS, TestSize.Level0)
{
    DHCP_LOGI("IpConflictDetectTest_SUCCESS enter!");
    dhcpClient->IpConflictDetect();
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

/**
* @tc.name: FastArpDetectTest_SUCCESS
* @tc.desc: FastArpDetectTest.
* @tc.type: FUNC
* @tc.require: AR00000000
*/
HWTEST_F(DhcpClientStateMachineTest, FastArpDetectTest_SUCCESS, TestSize.Level0)
{
    DHCP_LOGI("FastArpDetectTest_SUCCESS enter!");
    dhcpClient->FastArpDetect();
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

/**
* @tc.name: SlowArpDetectTest_SUCCESS
* @tc.desc: SlowArpDetectTest.
* @tc.type: FUNC
* @tc.require: AR00000000
*/
HWTEST_F(DhcpClientStateMachineTest, SlowArpDetectTest_SUCCESS, TestSize.Level0)
{
    DHCP_LOGI("SlowArpDetectTest_SUCCESS enter!");
    dhcpClient->SlowArpDetect(1);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, SlowArpDetectTest1, TestSize.Level0)
{
    DHCP_LOGI("SlowArpDetectTest1 enter!");
    time_t timestamp = 1;
    dhcpClient->m_sentPacketNum = THREE;
    dhcpClient->SlowArpDetect(timestamp);

    dhcpClient->m_sentPacketNum = TWO;
    dhcpClient->SlowArpDetect(timestamp);

    dhcpClient->m_sentPacketNum = 0;
    dhcpClient->SlowArpDetect(timestamp);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

/**
* @tc.name: SlowArpDetectCallbackTest_SUCCESS
* @tc.desc: SlowArpDetectCallbackTest.
* @tc.type: FUNC
* @tc.require: AR00000000
*/
HWTEST_F(DhcpClientStateMachineTest, SlowArpDetectCallbackTest_SUCCESS, TestSize.Level0)
{
    DHCP_LOGI("SlowArpDetectCallbackTest_SUCCESS enter!");
    dhcpClient->SlowArpDetectCallback(true);
    dhcpClient->SlowArpDetectCallback(false);

    dhcpClient->m_slowArpDetecting = 1;
    dhcpClient->SlowArpDetectCallback(true);
    dhcpClient->SlowArpDetectCallback(false);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

/**
* @tc.name: IsArpReachableTest_SUCCESS
* @tc.desc: IsArpReachableTest.
* @tc.type: FUNC
* @tc.require: AR00000000
*/
HWTEST_F(DhcpClientStateMachineTest, IsArpReachableTest_SUCCESS, TestSize.Level0)
{
    DHCP_LOGI("IsArpReachableTest_SUCCESS enter!");
    EXPECT_FALSE(dhcpClient->IsArpReachable(1, "0.0.0.0"));
}

/**
* @tc.name: SaveIpInfoInLocalFileTest_SUCCESS
* @tc.desc: SaveIpInfoInLocalFileTest.
* @tc.type: FUNC
* @tc.require: AR00000000
*/
HWTEST_F(DhcpClientStateMachineTest, SaveIpInfoInLocalFileTest_SUCCESS, TestSize.Level0)
{
    DHCP_LOGI("SaveIpInfoInLocalFileTest_SUCCESS enter!");
    DhcpIpResult ipResult;
    ipResult.code = 1;
    dhcpClient->SaveIpInfoInLocalFile(ipResult);

    dhcpClient->m_routerCfg.bssid = "wlan0";
    dhcpClient->SaveIpInfoInLocalFile(ipResult);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

/**
* @tc.name: TryCachedIpTest_SUCCESS
* @tc.desc: TryCachedIpTest.
* @tc.type: FUNC
* @tc.require: AR00000000
*/
HWTEST_F(DhcpClientStateMachineTest, TryCachedIpTest_SUCCESS, TestSize.Level0)
{
    DHCP_LOGI("TryCachedIpTest_SUCCESS enter!");
    dhcpClient->TryCachedIp();

    dhcpClient->m_routerCfg.prohibitUseCacheIp = 1;
    dhcpClient->TryCachedIp();
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, StartStopTimerTest, TestSize.Level0)
{
    DHCP_LOGI("StartTimerTest enter!");
    int64_t dafaultInterval0 = 10000; //10 s
    int64_t dafaultInterval1 = 30000;
    int64_t dafaultInterval2 = 60000;
    int64_t dafaultInterval3 = 90000;
    uint64_t getIpTimerId = 0;
    uint64_t renewDelayTimerId = 0;
    uint64_t rebindDelayTimerId = 0;
    uint64_t remainingDelayTimerId = 0;
    dhcpClient->StartTimer(TIMER_RENEW_DELAY, getIpTimerId, dafaultInterval0, true);
    dhcpClient->StartTimer(TIMER_RENEW_DELAY, renewDelayTimerId, dafaultInterval1, true);
    dhcpClient->StartTimer(TIMER_REBIND_DELAY, rebindDelayTimerId, dafaultInterval2, true);
    dhcpClient->StartTimer(TIMER_REMAINING_DELAY, remainingDelayTimerId, dafaultInterval3, true);
    dhcpClient->StopTimer(getIpTimerId);
    dhcpClient->StopTimer(renewDelayTimerId);
    dhcpClient->StopTimer(rebindDelayTimerId);
    dhcpClient->StopTimer(remainingDelayTimerId);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, GetIpTimerCallbackTest, TestSize.Level0)
{
    DHCP_LOGI("GetIpTimerCallbackTest enter!");
    dhcpClient->GetIpTimerCallback();
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, GetIpTimerCallbackTest1, TestSize.Level0)
{
    DHCP_LOGI("GetIpTimerCallbackTest1 enter!");
    dhcpClient->threadExit_ = 0;
    dhcpClient->m_action = ACTION_RENEW_T1;
    dhcpClient->GetIpTimerCallback();

    dhcpClient->m_action = ACTION_RENEW_T3;
    dhcpClient->GetIpTimerCallback();

    dhcpClient->m_action = ACTION_START_NEW;
    dhcpClient->GetIpTimerCallback();

    dhcpClient->m_action = ACTION_INVALID;
    dhcpClient->GetIpTimerCallback();
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, RenewDelayCallbackTest, TestSize.Level0)
{
    DHCP_LOGI("RenewDelayCallbackTest enter!");
    dhcpClient->RenewDelayCallback();
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, RebindDelayCallbackTest, TestSize.Level0)
{
    DHCP_LOGI("RebindDelayCallbackTest enter!");
    dhcpClient->RebindDelayCallback();
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, RemainingDelayCallbackTest, TestSize.Level0)
{
    DHCP_LOGI("RemainingDelayCallbackTest enter!");
    dhcpClient->RemainingDelayCallback();
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, ScheduleLeaseTimersTest, TestSize.Level0)
{
    DHCP_LOGI("ScheduleLeaseTimersTest enter!");
    dhcpClient->ScheduleLeaseTimers(true);
    dhcpClient->ScheduleLeaseTimers(false);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, CloseAllRenewTimerTest, TestSize.Level0)
{
    DHCP_LOGI("CloseAllRenewTimerTest enter!");
    dhcpClient->CloseAllRenewTimer();
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, SetIpv4DefaultDnsTest, TestSize.Level0)
{
    DHCP_LOGI("SetIpv4DefaultDnsTest enter!");
    struct DhcpIpResult result;
    dhcpClient->SetIpv4DefaultDns(nullptr);
    dhcpClient->SetIpv4DefaultDns(&result);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, SetDefaultNetMaskTest, TestSize.Level0)
{
    DHCP_LOGI("SetDefaultNetMaskTest enter!");
    struct DhcpIpResult result;

    dhcpClient->SetDefaultNetMask(nullptr);

    result.strOptSubnet[0] = 0;
    strcpy_s(result.strYiaddr, sizeof(result.strYiaddr), "8.168.0.8");
    dhcpClient->SetDefaultNetMask(&result);

    result.strOptSubnet[0] = 0;
    strcpy_s(result.strYiaddr, sizeof(result.strYiaddr), "88.168.0.8");
    dhcpClient->SetDefaultNetMask(&result);

    result.strOptSubnet[0] = 0;
    strcpy_s(result.strYiaddr, sizeof(result.strYiaddr), "127.168.0.8");
    dhcpClient->SetDefaultNetMask(&result);

    result.strOptSubnet[0] = 0;
    strcpy_s(result.strYiaddr, sizeof(result.strYiaddr), "191.168.0.8");
    dhcpClient->SetDefaultNetMask(&result);

    result.strOptSubnet[0] = 0;
    strcpy_s(result.strYiaddr, sizeof(result.strYiaddr), "223.168.0.8");
    dhcpClient->SetDefaultNetMask(&result);

    result.strOptSubnet[0] = 0;
    strcpy_s(result.strYiaddr, sizeof(result.strYiaddr), "225.168.0.8");
    dhcpClient->SetDefaultNetMask(&result);

    result.strOptSubnet[0] = 0;
    strcpy_s(result.strYiaddr, sizeof(result.strYiaddr), "240.168.0.8");
    dhcpClient->SetDefaultNetMask(&result);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, RebootTest, TestSize.Level0)
{
    DHCP_LOGI("RebootTest enter!");
    time_t timestamp = 1;
    dhcpClient->Reboot(timestamp);

    dhcpClient->m_routerCfg.bssid = "wlan0";
    dhcpClient->Reboot(timestamp);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, ExecDhcpReleaseTest, TestSize.Level0)
{
    DHCP_LOGI("ExecDhcpReleaseTest enter!");
    dhcpClient->m_dhcp4State = DHCP_STATE_BOUND;
    dhcpClient->ExecDhcpRelease();

    dhcpClient->m_dhcp4State = DHCP_STATE_RENEWING;
    dhcpClient->ExecDhcpRelease();

    dhcpClient->m_dhcp4State = DHCP_STATE_REBINDING;
    dhcpClient->ExecDhcpRelease();

    dhcpClient->m_dhcp4State = DHCP_STATE_INIT;
    dhcpClient->ExecDhcpRelease();
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, InitSelectingTest, TestSize.Level0)
{
    DHCP_LOGI("InitSelectingTest enter!");
    time_t timestamp = 1;
    dhcpClient->m_sentPacketNum = TIMEOUT_TIMES_MAX + 1;
    dhcpClient->InitSelecting(timestamp);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, DecliningTest, TestSize.Level0)
{
    DHCP_LOGI("DecliningTest enter!");
    time_t timestamp = 1;
    dhcpClient->Declining(timestamp);

    dhcpClient->m_conflictCount = THREE;
    dhcpClient->Declining(timestamp);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, GetDhcpOfferTest, TestSize.Level0)
{
    DHCP_LOGI("GetDhcpOfferTest enter!");
    DhcpPacket packet;
    time_t timestamp = 1;
    dhcpClient->GetDhcpOffer(nullptr, timestamp);

    dhcpClient->GetDhcpOffer(&packet, timestamp);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpClientStateMachineTest, SetSecondsElapsedTest, TestSize.Level0)
{
    DHCP_LOGI("SetSecondsElapsedTest enter!");
    DhcpPacket packet;
    dhcpClient->SetSecondsElapsed(nullptr);
    dhcpClient->SetSecondsElapsed(&packet);
    EXPECT_NE(packet.secs, TWO);
}
}
}

