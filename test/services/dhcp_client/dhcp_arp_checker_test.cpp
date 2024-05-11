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
#include "securec.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpArpCheckerTest");
using namespace testing::ext;
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
    DHCP::DhcpArpChecker dhcpArpChecker;
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
}  // namespace OHOS