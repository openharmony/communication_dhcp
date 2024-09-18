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

#include "dhcp_result.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpResultTest");

using namespace testing::ext;
using namespace OHOS::DHCP;
namespace OHOS {
namespace DHCP {
constexpr int ARRAY_SIZE = 1030;
class DhcpResultTest : public testing::Test {
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

HWTEST_F(DhcpResultTest, PublishDhcpIpv4ResultTest, TestSize.Level1)
{
    DHCP_LOGI("PublishDhcpIpv4ResultTest enter!");
    struct DhcpIpResult ipResult;
    bool result = PublishDhcpIpv4Result(ipResult);
    DHCP_LOGE("PublishDhcpIpv4ResultTest result(%{public}d)", result);
    EXPECT_EQ(false, result);
}

HWTEST_F(DhcpResultTest, PublishDhcpIpv4ResultTest1, TestSize.Level1)
{
    DHCP_LOGI("PublishDhcpIpv4ResultTest1 enter!");
    struct DhcpIpResult ipResult;
    ipResult.code = PUBLISH_CODE_TIMEOUT;
    bool result = PublishDhcpIpv4Result(ipResult);
    EXPECT_EQ(false, result);

    ipResult.code = PUBLISH_CODE_EXPIRED;
    result = PublishDhcpIpv4Result(ipResult);
    EXPECT_EQ(false, result);

    ipResult.code = PUBLISH_DHCP_OFFER_REPORT;
    result = PublishDhcpIpv4Result(ipResult);
    EXPECT_EQ(false, result);
}

HWTEST_F(DhcpResultTest, DhcpIpv6TimerCallbackEventTest, TestSize.Level1)
{
    DHCP_LOGI("DhcpIpv6TimerCallbackEventTest enter!");
    std::string ifname = "wlan0";
    EXPECT_EQ(false, DhcpIpv6TimerCallbackEvent(nullptr));
    EXPECT_EQ(true, DhcpIpv6TimerCallbackEvent(ifname.c_str()));
}
}
}
