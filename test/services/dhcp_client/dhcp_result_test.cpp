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

HWTEST_F(DhcpResultTest, SplitStrTest, TestSize.Level1)
{
    DHCP_LOGE("enter SplitStrTest");
    std::string src;
    std::string delim;
    int count = 0;
    std::vector<std::string> splits {};
    EXPECT_EQ(false, SplitStr(src, delim, count, splits));
    src = "";
    delim = "test";
    EXPECT_EQ(false, SplitStr(src, delim, count, splits));
    src = "testcode";
    delim = "";
    EXPECT_EQ(false, SplitStr(src, delim, count, splits));
    src = "testcode";
    delim = "test";
    count = 1;
    EXPECT_EQ(true, SplitStr(src, delim, count, splits));
}

HWTEST_F(DhcpResultTest, GetDhcpEventIpv4ResultTest, TestSize.Level1)
{
    DHCP_LOGE("enter GetDhcpEventIpv4ResultTest");
    std::vector<std::string> splits;
    splits.push_back("wlan0");
    splits.push_back("12");
    splits.push_back("*");
    EXPECT_EQ(DHCP_OPT_FAILED, GetDhcpEventIpv4Result(-1, splits));
    splits.push_back("wlan4");
    splits.push_back("wlan5");
    splits.push_back("wlan6");
    splits.push_back("wlan7");
    splits.push_back("wlan8");
    splits.push_back("wlan9");
    splits.push_back("wlan10");
    splits.push_back("wlan11");
    EXPECT_EQ(DHCP_OPT_FAILED, GetDhcpEventIpv4Result(-1, splits));
    splits[2] = "wlan3";
    EXPECT_EQ(DHCP_OPT_SUCCESS, GetDhcpEventIpv4Result(0, splits));
    splits[0] = "";
    EXPECT_EQ(DHCP_OPT_FAILED, GetDhcpEventIpv4Result(0, splits));
    splits[0] = "wlan0";
    splits[1] = "";
    EXPECT_EQ(DHCP_OPT_FAILED, GetDhcpEventIpv4Result(0, splits));
}

HWTEST_F(DhcpResultTest, DhcpEventResultHandleTest, TestSize.Level1)
{
    DHCP_LOGE("enter DhcpEventResultHandleTest");
    std::string data;
    int code = 0;
    EXPECT_EQ(DHCP_OPT_FAILED, DhcpEventResultHandle(code, data));
    data = "ipv4:ipv4,1640995200,*,*,*,*,*,*,*,*,*";
    EXPECT_EQ(DHCP_OPT_FAILED, DhcpEventResultHandle(code, data));
    data = "ipv6:ipv6,1640995200,*,*,*,*,*,*,*,*,*";
    EXPECT_EQ(DHCP_OPT_SUCCESS, DhcpEventResultHandle(code, data));
    data = "wlan0:wlan0,1640995200,*,*,*,*,*,*,*,*,*";
    EXPECT_EQ(DHCP_OPT_FAILED, DhcpEventResultHandle(code, data));
}

HWTEST_F(DhcpResultTest, PublishDhcpIpv4ResultEventTest1, TestSize.Level1)
{
    DHCP_LOGI("PublishDhcpIpv4ResultEventTest1 enter!");
    char data[] = "ipv6:ipv6,1640995200,*,*,*,*,*,*,*,*,*";
    char ifname[] = "testcode";
    bool result = PublishDhcpIpv4ResultEvent(1, data, ifname);
    DHCP_LOGE("PublishDhcpIpv4ResultEventTest1 result(%{public}d)", result);
    EXPECT_EQ(true, result);
}

HWTEST_F(DhcpResultTest, PublishDhcpIpv4ResultEventTest2, TestSize.Level1)
{
    DHCP_LOGI("PublishDhcpIpv4ResultEventTest2 enter!");
    char data[] = "wlan0:wlan0,1640995200,*,*,*,*,*,*,*,*,*";
    char ifname[ARRAY_SIZE] = {1};
    bool result = PublishDhcpIpv4ResultEvent(1, data, ifname);
    DHCP_LOGE("PublishDhcpIpv4ResultEventTest2 result(%{public}d)", result);
    EXPECT_EQ(false, result);
}

HWTEST_F(DhcpResultTest, DhcpIpv6TimerCallbackEventTest, TestSize.Level1)
{
    DHCP_LOGI("DhcpIpv6TimerCallbackEventTest enter!");
    std::string ifname = "wlan0";
    EXPECT_EQ(false, DhcpIpv6TimerCallbackEvent(nullptr));
    EXPECT_EQ(false, DhcpIpv6TimerCallbackEvent(ifname.c_str()));
}
}
}
