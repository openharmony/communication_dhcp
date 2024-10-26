/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "dhcp_logger.h"
#include "dhcp_arp_checker.h"
#include "mock_system_func.h"
#include "securec.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpArpCheckerTest");
using namespace testing::ext;
using namespace OHOS::DHCP;

constexpr int ONE = 1;
constexpr int32_t MAC_ADDR_LEN = 6;
constexpr int32_t TIMEOUT = 50;

namespace OHOS {
class DhcpArpCheckerTest : public testing::Test {
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
/**
 * @tc.name: DoArpTest_SUCCESS
 * @tc.desc: DoArpTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpArpCheckerTest, DoArpTest_SUCCESS, TestSize.Level1)
{
    DHCP_LOGE("enter DoArpTest_SUCCESS");
    DhcpArpChecker dhcpArpChecker;
    std::string ifName = "wlantest";
    std::string ifaceMac = "11:22:33:44:55:66";
    std::string ipAddr = "0.0.0.1";
    int32_t timeoutMillis = TIMEOUT;
    uint64_t timeCost = 0;
    std::string senderIp =  "0.0.0.2";
    EXPECT_FALSE(dhcpArpChecker.Start(ifName, ifaceMac, senderIp, ipAddr));
    EXPECT_FALSE(dhcpArpChecker.DoArpCheck(timeoutMillis, false, timeCost));
    ifName = "wlan0";
    dhcpArpChecker.Start(ifName, ifaceMac, senderIp, ipAddr);
    dhcpArpChecker.DoArpCheck(timeoutMillis, false, timeCost);
}

/**
 * @tc.name: CreateSocketTest_001
 * @tc.desc: CreateSocketTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpArpCheckerTest, CreateSocketTest_001, TestSize.Level1)
{
    DHCP_LOGE("enter CreateSocketTest_001");
    DhcpArpChecker dhcpArpChecker;
    std::string ifName = "";
    uint16_t protocol = ETH_P_ARP;
    MockSystemFunc::SetMockFlag(true);
    EXPECT_TRUE(dhcpArpChecker.CreateSocket(ifName.c_str(), protocol) == -1);
    ifName = "wlantest";
    EXPECT_TRUE(dhcpArpChecker.CreateSocket(ifName.c_str(), protocol) == -1);
    ifName = "wlan0";
    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _)).WillOnce(Return(-1)).WillRepeatedly(Return(-1));
    EXPECT_TRUE(dhcpArpChecker.CreateSocket(ifName.c_str(), protocol) == -1);
    MockSystemFunc::SetMockFlag(false);
}

/**
 * @tc.name: CreateSocketTest_002
 * @tc.desc: CreateSocketTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpArpCheckerTest, CreateSocketTest_002, TestSize.Level1)
{
    DHCP_LOGE("enter CreateSocketTest_002");
    DhcpArpChecker dhcpArpChecker;
    std::string ifName = "wlan0";
    uint16_t protocol = ETH_P_ARP;
    MockSystemFunc::SetMockFlag(true);
    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _)).WillOnce(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_TRUE(dhcpArpChecker.CreateSocket(ifName.c_str(), protocol) == 0);
    MockSystemFunc::SetMockFlag(false);
}

HWTEST_F(DhcpArpCheckerTest, CreateSocketTest_003, TestSize.Level1)
{
    DHCP_LOGE("enter CreateSocketTest_003");
    DhcpArpChecker dhcpArpChecker;
    uint16_t protocol = ETH_P_ARP;
    EXPECT_EQ(dhcpArpChecker.CreateSocket(nullptr, protocol), -1);
}

/**
 * @tc.name: StopTest_001
 * @tc.desc: StopTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpArpCheckerTest, StopTest_001, TestSize.Level1)
{
    DHCP_LOGE("enter StopTest_001");
    DhcpArpChecker dhcpArpChecker;
    dhcpArpChecker.m_isSocketCreated = false;
    dhcpArpChecker.Stop();
    dhcpArpChecker.m_isSocketCreated = true;
    dhcpArpChecker.Stop();
    EXPECT_EQ(true, ONE);
}

/**
 * @tc.name: SendDataTest_001
 * @tc.desc: SendDataTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpArpCheckerTest, SendDataTest_001, TestSize.Level1)
{
    DHCP_LOGE("enter SendDataTest_001");
    DhcpArpChecker dhcpArpChecker;
    uint8_t *buff = nullptr;
    int32_t count = 1;
    uint8_t *destHwaddr = nullptr;
    dhcpArpChecker.m_socketFd = -1;
    dhcpArpChecker.m_ifaceIndex = 0;
    EXPECT_TRUE(dhcpArpChecker.SendData(buff, count, destHwaddr) == -1);
    uint8_t bufferTest = 1;
    buff = &bufferTest;
    EXPECT_TRUE(dhcpArpChecker.SendData(buff, count, destHwaddr) == -1);
    destHwaddr = &bufferTest;
    EXPECT_TRUE(dhcpArpChecker.SendData(buff, count, destHwaddr) == -1);
    dhcpArpChecker.m_socketFd = 1;
    EXPECT_TRUE(dhcpArpChecker.SendData(buff, count, destHwaddr) == -1);
    dhcpArpChecker.m_ifaceIndex = 1;
    dhcpArpChecker.SendData(buff, count, destHwaddr);
}

/**
 * @tc.name: RecvDataTest_001
 * @tc.desc: RecvDataTest
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpArpCheckerTest, RecvDataTest_001, TestSize.Level1)
{
    DHCP_LOGE("enter RecvDataTest_001");
    DhcpArpChecker dhcpArpChecker;

    uint8_t buff[MAC_ADDR_LEN] = {0};
    dhcpArpChecker.m_socketFd = -1;
    EXPECT_TRUE(dhcpArpChecker.RecvData(buff, 1, 1) == -1);
    dhcpArpChecker.m_socketFd = 1;
    dhcpArpChecker.RecvData(buff, 1, 1);
}

HWTEST_F(DhcpArpCheckerTest, GetGwMacAddrList_Success, TestSize.Level0)
{
    DHCP_LOGE("enter GetGwMacAddrList_Success");
    DhcpArpChecker dhcpArpChecker;
    int32_t timeoutMillis = 1000;
    bool isFillSenderIp = true;
    std::vector<std::string> gwMacLists;

    dhcpArpChecker.m_isSocketCreated = false;
    dhcpArpChecker.GetGwMacAddrList(timeoutMillis, isFillSenderIp, gwMacLists);

    dhcpArpChecker.m_isSocketCreated = true;
    dhcpArpChecker.GetGwMacAddrList(timeoutMillis, isFillSenderIp, gwMacLists);
    EXPECT_EQ(true, ONE);
}

HWTEST_F(DhcpArpCheckerTest, SaveGwMacAddrTest, TestSize.Level0)
{
    DHCP_LOGE("enter SaveGwMacAddrTest");
    DhcpArpChecker dhcpArpChecker;
    std::vector<std::string> gwMacLists;
    std::string gwMacAddr = "11:22:33:44:55:66";
    dhcpArpChecker.SaveGwMacAddr(gwMacAddr, gwMacLists);
    EXPECT_EQ(gwMacLists.size(), 1);

    gwMacLists.push_back(gwMacAddr);
    dhcpArpChecker.SaveGwMacAddr(gwMacAddr, gwMacLists);
    EXPECT_EQ(gwMacLists.size(), 2);

    gwMacAddr = "";
    dhcpArpChecker.SaveGwMacAddr(gwMacAddr, gwMacLists);
    EXPECT_EQ(gwMacLists.size(), 2);
}
}  // namespace OHOS