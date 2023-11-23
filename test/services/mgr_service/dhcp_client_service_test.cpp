/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "dhcp_client_service_impl.h"
#include "dhcp_result_notify.h"
#include "mock_system_func.h"
#include "dhcp_func.h"
#include "securec.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Wifi;
namespace OHOS {
namespace Wifi {
constexpr int ADDRESS_ARRAY_SIZE = 12;
class DhcpClientServiceTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        pClientService = std::make_unique<DhcpClientServiceImpl>();
    }
    virtual void TearDown()
    {
        if (pClientService != nullptr) {
            pClientService.reset(nullptr);
        }
    }
public:
    std::unique_ptr<DhcpClientServiceImpl> pClientService;
};

HWTEST_F(DhcpClientServiceTest, DhcpClientService_Test2, TestSize.Level1)
{
    ASSERT_TRUE(pClientService != nullptr);

    MockSystemFunc::SetMockFlag(true);

    EXPECT_CALL(MockSystemFunc::GetInstance(), vfork())
        .WillRepeatedly(Return(-1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), waitpid(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), open(_, _)).WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(_, _, _)).Times(testing::AtLeast(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _)).Times(testing::AtLeast(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), select(_, _, _, _, _)).Times(testing::AtLeast(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), setsockopt(_, _, _, _, _)).Times(testing::AtLeast(0));

    std::string ifname = "wlan0";
    std::string strFile4 = DHCP_WORK_DIR + ifname + DHCP_RESULT_FILETYPE;
    std::string strData4 = "IP4 0 * * * * * * * * 0";
    ASSERT_TRUE(DhcpFunc::CreateFile(strFile4, strData4));
    DhcpResultNotify dhcpResultNotify;
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->GetDhcpResult("", &dhcpResultNotify, 0));
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->GetDhcpResult(ifname, nullptr, 0));
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->GetDhcpResult(ifname, &dhcpResultNotify, 0));
    DhcpResultNotify dhcpResultNotify1;
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->GetDhcpResult(ifname, &dhcpResultNotify1, 10));
    DhcpResultNotify dhcpResultNotify2;
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->GetDhcpResult(ifname, &dhcpResultNotify2, 20));
    DhcpResultNotify dhcpResultNotify3;
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->GetDhcpResult("wlan1", &dhcpResultNotify3, 30));

    sleep(DHCP_NUM_ONE);

    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->StopDhcpClient(ifname, true));
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->StopDhcpClient(ifname, true));
    ASSERT_TRUE(DhcpFunc::RemoveFile(strFile4));

    MockSystemFunc::SetMockFlag(false);
}

HWTEST_F(DhcpClientServiceTest, DhcpClientService_Test3, TestSize.Level1)
{
    ASSERT_TRUE(pClientService != nullptr);

    MockSystemFunc::SetMockFlag(true);

    EXPECT_CALL(MockSystemFunc::GetInstance(), vfork()).WillRepeatedly(Return(-1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), waitpid(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), kill(_, _))
        .WillOnce(Return(-1)).WillOnce(Return(0))
        .WillOnce(Return(-1)).WillOnce(Return(0))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), open(_, _)).WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(_, _, _)).Times(testing::AtLeast(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _)).Times(testing::AtLeast(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), select(_, _, _, _, _)).Times(testing::AtLeast(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), setsockopt(_, _, _, _, _)).Times(testing::AtLeast(0));

    std::string ifname;
    DhcpServiceInfo dhcp;
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->RenewDhcpClient(ifname));
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->ReleaseDhcpClient(ifname));
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->GetDhcpInfo(ifname, dhcp));

    ifname = "wlan0";
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->GetDhcpInfo(ifname, dhcp));
    EXPECT_EQ(0, pClientService->GetDhcpClientProPid(""));
    EXPECT_EQ(0, pClientService->GetDhcpClientProPid(ifname));

    std::string strFile4 = DHCP_WORK_DIR + ifname + DHCP_RESULT_FILETYPE;
    std::string strData4 = "IP4 0 * * * * * * * * 0";
    ASSERT_TRUE(DhcpFunc::CreateFile(strFile4, strData4));
    bool bIpv6 = true;
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->StopDhcpClient(ifname, bIpv6));
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->StartDhcpClient(ifname, bIpv6));

    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->RenewDhcpClient(ifname));
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->RenewDhcpClient(ifname));
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->ReleaseDhcpClient(ifname));
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->ReleaseDhcpClient(ifname));

    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->StopDhcpClient(ifname, bIpv6));
    ASSERT_TRUE(DhcpFunc::RemoveFile(strFile4));

    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->StartDhcpClient("wlan1", false));

    MockSystemFunc::SetMockFlag(false);
}

HWTEST_F(DhcpClientServiceTest, UnsubscribeDhcpEventTest, TestSize.Level1)
{
    ASSERT_TRUE(pClientService != nullptr);
    std::string strAction;
    EXPECT_EQ(DHCP_OPT_ERROR, pClientService->UnsubscribeDhcpEvent(strAction));
    strAction = "action";
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->UnsubscribeDhcpEvent(strAction));
}

HWTEST_F(DhcpClientServiceTest, RemoveDhcpResultTest, TestSize.Level1)
{
    ASSERT_TRUE(pClientService != nullptr);
    IDhcpResultNotify *pResultNotify = nullptr;
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->RemoveDhcpResult(pResultNotify));
}

HWTEST_F(DhcpClientServiceTest, OnAddressChangedCallbackTest, TestSize.Level1)
{
    ASSERT_TRUE(pClientService != nullptr);
    std::string ifname;
    DhcpIpv6Info info;
    pClientService->OnAddressChangedCallback(ifname, info);

    ASSERT_TRUE(strncpy_s(info.globalIpv6Addr, DHCP_INET6_ADDRSTRLEN, " 192.168.1.10", ADDRESS_ARRAY_SIZE) == EOK);
    ASSERT_TRUE(strncpy_s(info.routeAddr, DHCP_INET6_ADDRSTRLEN, " 192.168.1.1", ADDRESS_ARRAY_SIZE) == EOK);
    pClientService->OnAddressChangedCallback(ifname, info);
}

HWTEST_F(DhcpClientServiceTest, GetDhcpEventIpv4ResultTest, TestSize.Level1)
{
    ASSERT_TRUE(pClientService != nullptr);
    std::vector<std::string> splits;
    splits.push_back("wlan0");
    splits.push_back("12");
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->GetDhcpEventIpv4Result(-1, splits));
    splits.push_back("*");
    splits.push_back("wlan4");
    splits.push_back("wlan5");
    splits.push_back("wlan6");
    splits.push_back("wlan7");
    splits.push_back("wlan8");
    splits.push_back("wlan9");
    splits.push_back("wlan10");
    splits.push_back("wlan11");
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->GetDhcpEventIpv4Result(-1, splits));
    splits[2] = "wlan3";
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->GetDhcpEventIpv4Result(0, splits));
    splits[0] = "";
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->GetDhcpEventIpv4Result(0, splits));
    splits[0] = "wlan0";
    splits[1] = "";
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->GetDhcpEventIpv4Result(0, splits));
}

HWTEST_F(DhcpClientServiceTest, CheckDhcpClientRunningTest, TestSize.Level1)
{
    ASSERT_TRUE(pClientService != nullptr);
    std::string ifname;
    EXPECT_EQ(DHCP_OPT_ERROR, pClientService->CheckDhcpClientRunning(ifname));
    ifname = "wlan0";
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->CheckDhcpClientRunning(ifname));
}

HWTEST_F(DhcpClientServiceTest, RenewDhcpTest, TestSize.Level1)
{
    ASSERT_TRUE(pClientService != nullptr);
    MockSystemFunc::SetMockFlag(true);

    EXPECT_CALL(MockSystemFunc::GetInstance(), vfork()).WillRepeatedly(Return(-1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), waitpid(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), kill(_, _))
        .WillOnce(Return(-1)).WillOnce(Return(0))
        .WillOnce(Return(-1)).WillOnce(Return(0))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), open(_, _)).WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(_, _, _)).Times(testing::AtLeast(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _)).Times(testing::AtLeast(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), select(_, _, _, _, _)).Times(testing::AtLeast(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), setsockopt(_, _, _, _, _)).Times(testing::AtLeast(0));

    std::string ifname = "wlan0";
    bool bIpv6 = true;
    DhcpServiceInfo dhcp;
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->StartDhcpClient(ifname, bIpv6));
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->GetDhcpInfo(ifname, dhcp));
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->StopDhcpClient(ifname, bIpv6));

    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->RenewDhcpClient(ifname));
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->GetDhcpInfo(ifname, dhcp));
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->ReleaseDhcpClient(ifname));
    MockSystemFunc::SetMockFlag(false);
}
}
}