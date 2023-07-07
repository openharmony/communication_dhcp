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
class DhcpClientServiceTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        printf("DhcpClientServiceTest SetUp()...\n");
        pClientService = std::make_unique<DhcpClientServiceImpl>();
    }
    virtual void TearDown()
    {
        printf("DhcpClientServiceTest TearDown()...\n");
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
        .WillOnce(Return(-1)).WillOnce(Return(1))
        .WillOnce(Return(-1)).WillOnce(Return(1))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), waitpid(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), open(_, _)).WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_)).WillRepeatedly(Return(0));

    std::string ifname = "wlan0";
    std::string strFile4 = DHCP_WORK_DIR + ifname + DHCP_RESULT_FILETYPE;
    std::string strData4 = "IP4 0 * * * * * * * * 0";
    ASSERT_TRUE(DhcpFunc::CreateFile(strFile4, strData4));
    bool bIpv6 = true;
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->StartDhcpClient(ifname, bIpv6));
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->StartDhcpClient(ifname, bIpv6));
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->StartDhcpClient(ifname, bIpv6));

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
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->StopDhcpClient(ifname, true));
    ASSERT_TRUE(DhcpFunc::RemoveFile(strFile4));

    MockSystemFunc::SetMockFlag(false);
}

HWTEST_F(DhcpClientServiceTest, DhcpClientService_Test3, TestSize.Level1)
{
    ASSERT_TRUE(pClientService != nullptr);

    MockSystemFunc::SetMockFlag(true);

    EXPECT_CALL(MockSystemFunc::GetInstance(), vfork()).WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), waitpid(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), kill(_, _))
        .WillOnce(Return(-1)).WillOnce(Return(0))
        .WillOnce(Return(-1)).WillOnce(Return(0))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), open(_, _)).WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_)).WillRepeatedly(Return(0));

    std::string ifname = "wlan0";
    EXPECT_EQ(0, pClientService->GetDhcpClientProPid(""));
    EXPECT_EQ(0, pClientService->GetDhcpClientProPid(ifname));

    std::string strFile4 = DHCP_WORK_DIR + ifname + DHCP_RESULT_FILETYPE;
    std::string strData4 = "IP4 0 * * * * * * * * 0";
    ASSERT_TRUE(DhcpFunc::CreateFile(strFile4, strData4));
    bool bIpv6 = true;
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->StopDhcpClient(ifname, bIpv6));
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->StartDhcpClient(ifname, bIpv6));

    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->RenewDhcpClient(ifname));
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->RenewDhcpClient(ifname));
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->ReleaseDhcpClient(ifname));
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->ReleaseDhcpClient(ifname));

    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->StopDhcpClient(ifname, bIpv6));
    ASSERT_TRUE(DhcpFunc::RemoveFile(strFile4));

    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->StartDhcpClient("wlan1", false));

    MockSystemFunc::SetMockFlag(false);
}

HWTEST_F(DhcpClientServiceTest, SubscribeDhcpEvent_Test, TestSize.Level1)
{
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->StartDhcpClient(nullptr, true));
}

HWTEST_F(DhcpClientServiceTest, GetDhcpStatus_Test, TestSize.Level1)
{
    EXPECT_EQ(-1, pClientService->GetDhcpStatus(nullptr));
}

HWTEST_F(DhcpClientServiceTest, RemoveDhcpResult_Test, TestSize.Level1)
{
    IDhcpResultNotify pResultNotify;
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->RemoveDhcpResult(nullptr));
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->RemoveDhcpResult(&pResultNotify));
}

HWTEST_F(DhcpClientServiceTest, GetDhcpInfo_Test, TestSize.Level1)
{
    DhcpServiceInfo dhcp;
    std::string ifname = "wlan0";
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->GetDhcpInfo(nullptr, dhcp));
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->GetDhcpInfo(ifname, dhcp));
}


HWTEST_F(DhcpClientServiceTest, GetDhcpEventIpv4Result_Test1, TestSize.Level1)
{
    std::vector<std::string> splits;
    splits.push_back("::Ipv4");
    int code = 0;
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->GetDhcpEventIpv4Result(code, splits));
}

HWTEST_F(DhcpClientServiceTest, GetDhcpEventIpv4Result_Test2, TestSize.Level1)
{
    std::vector<std::string> splits(11);
    int code = 0;
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->GetDhcpEventIpv4Result(code, splits));
    splits[0] = "ipv4";
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->GetDhcpEventIpv4Result(code, splits));
}

HWTEST_F(DhcpClientServiceTest, GetDhcpEventIpv4Result_Test3, TestSize.Level1)
{
    std::vector<std::string> splits(11);
    int code = PUBLISH_CODE_SUCCESS;
    splits[0] = "ipv4";
    splits[1] = ":";
    splits[2] = "*";
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->GetDhcpEventIpv4Result(code, splits));

    code = PUBLISH_CODE_FAILED;
    splits[2] = "::";
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->GetDhcpEventIpv4Result(code, splits));
}

HWTEST_F(DhcpClientServiceTest, GetDhcpEventIpv4Result_Test3, TestSize.Level1)
{
    std::vector<std::string> splits(11);
    int code = PUBLISH_CODE_FAILED;
    splits[0] = "ipv4";
    splits[1] = ":";
    splits[2] = "*";
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->GetDhcpEventIpv4Result(code, splits));
}

HWTEST_F(DhcpClientServiceTest, GetDhcpEventIpv4Result_Test4, TestSize.Level1)
{
    std::vector<std::string> splits(11);
    int code = 2;
    splits[0] = "ipv4";
    splits[1] = ":";
    splits[2] = "*";
    EXPECT_EQ(DHCP_OPT_FAILED, pClientService->GetDhcpEventIpv4Result(code, splits));
}

HWTEST_F(DhcpClientServiceTest, GetDhcpEventIpv4Result_Test5, TestSize.Level1)
{
    std::vector<std::string> splits(11);
    int code = PUBLISH_CODE_SUCCESS;
    splits[0] = "ipv4";
    splits[1] = ":";
    splits[2] = "::";
    EXPECT_EQ(DHCP_OPT_SUCCESS, pClientService->GetDhcpEventIpv4Result(code, splits));
}
}
}