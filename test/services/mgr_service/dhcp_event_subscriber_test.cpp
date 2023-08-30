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
#include <gmock/gmock.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstddef>
#include <cstdint>
#include "securec.h"
#include "wifi_log.h"
#include "dhcp_func.h"
#include "dhcp_event_subscriber.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Ref;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
constexpr int PUBLISH_UCCESS_CODE = 0;
constexpr int PUBLISH_FAILED_CODE = -1;
class DhcpEventSubscriberTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        EventFwk::MatchingSkills matchingSkills;
        matchingSkills.AddEvent("testcode");
        EventFwk::CommonEventSubscribeInfo subInfo(matchingSkills);
        dhcpSubscriber = std::make_unique<OHOS::Wifi::DhcpEventSubscriber>(subInfo);
    }
    virtual void TearDown()
    {
        if (dhcpSubscriber != nullptr) {
            dhcpSubscriber.reset(nullptr);
        }
    }
public:
    std::unique_ptr<DhcpEventSubscriber> dhcpSubscriber;
};

HWTEST_F(DhcpEventSubscriberTest, OnReceiveEventTest_DataIsNull, TestSize.Level1)
{
    ASSERT_TRUE(dhcpSubscriber != nullptr);
    LOGE("OnReceiveEventTest_DataIsNull enter!");
    OHOS::EventFwk::CommonEventData commonData;
    commonData.SetCode(PUBLISH_UCCESS_CODE);
    commonData.SetData("");
    dhcpSubscriber->OnReceiveEvent(commonData);
}

HWTEST_F(DhcpEventSubscriberTest, OnReceiveEventTest_DataIsIpv4, TestSize.Level1)
{
    ASSERT_TRUE(dhcpSubscriber != nullptr);
    LOGE("OnReceiveEventTest_DataIsIpv4 enter!");
    OHOS::EventFwk::CommonEventData commonData;
    commonData.SetCode(PUBLISH_UCCESS_CODE);
    commonData.SetData("ipv4:ifname,time,cliIp,lease,servIp,subnet,dns1,dns2,router1,router2,vendor");
    dhcpSubscriber->OnReceiveEvent(commonData);
}

HWTEST_F(DhcpEventSubscriberTest, OnReceiveEventTest_DataIsIpv4_1, TestSize.Level1)
{
    ASSERT_TRUE(dhcpSubscriber != nullptr);
    LOGE("OnReceiveEventTest_DataIsIpv4_1 enter!");
    OHOS::EventFwk::CommonEventData commonData;
    commonData.SetCode(PUBLISH_FAILED_CODE);
    commonData.SetData("ipv4:ifname,time,cliIp,lease,servIp,subnet,dns1,dns2,router1,router2,vendor");
    dhcpSubscriber->OnReceiveEvent(commonData);
}

HWTEST_F(DhcpEventSubscriberTest, OnReceiveEventTest_DataIsIpv4_2, TestSize.Level1)
{
    ASSERT_TRUE(dhcpSubscriber != nullptr);
    LOGE("OnReceiveEventTest_DataIsIpv4_2 enter!");
    OHOS::EventFwk::CommonEventData commonData;
    commonData.SetCode(PUBLISH_UCCESS_CODE);
    commonData.SetData("ipv4:");
    dhcpSubscriber->OnReceiveEvent(commonData);
}

HWTEST_F(DhcpEventSubscriberTest, OnReceiveEventTest_DataIsIpv4_3, TestSize.Level1)
{
    ASSERT_TRUE(dhcpSubscriber != nullptr);
    LOGE("OnReceiveEventTest_DataIsIpv4_3 enter!");
    OHOS::EventFwk::CommonEventData commonData;
    commonData.SetCode(PUBLISH_UCCESS_CODE);
    commonData.SetData("ipv4:ifname");
    dhcpSubscriber->OnReceiveEvent(commonData);
    commonData.SetData("ipv4:ifname,time,cliIp,lease,servIp,subnet,dns1,dns2,router1");
    dhcpSubscriber->OnReceiveEvent(commonData);
}

HWTEST_F(DhcpEventSubscriberTest, OnReceiveEventTest_DataIsIpv4_4, TestSize.Level1)
{
    ASSERT_TRUE(dhcpSubscriber != nullptr);
    LOGE("OnReceiveEventTest_DataIsIpv4_4 enter!");
    OHOS::EventFwk::CommonEventData commonData;
    commonData.SetCode(PUBLISH_UCCESS_CODE);
    commonData.SetData("ipv4:ifname,time,*,lease,servIp,subnet,dns1,dns2,router1,router2,vendor");
    dhcpSubscriber->OnReceiveEvent(commonData);
    commonData.SetCode(PUBLISH_FAILED_CODE);
    commonData.SetData("ipv4:ifname,time,cliIp,lease,servIp,subnet,dns1,dns2,router1,router2,vendor");
    dhcpSubscriber->OnReceiveEvent(commonData);
}

HWTEST_F(DhcpEventSubscriberTest, OnReceiveEventTest_DataIsIpv4_5, TestSize.Level1)
{
    ASSERT_TRUE(dhcpSubscriber != nullptr);
    LOGE("OnReceiveEventTest_DataIsIpv4_5 enter!");
    OHOS::EventFwk::CommonEventData commonData;
    commonData.SetCode(PUBLISH_UCCESS_CODE);
    commonData.SetData("ipv4:,time,cliIp,lease,servIp,subnet,dns1,dns2,router1,router2,vendor");
    dhcpSubscriber->OnReceiveEvent(commonData);
    commonData.SetData("ipv4:ifname,,cliIp,lease,servIp,subnet,dns1,dns2,router1,router2,vendor");
    dhcpSubscriber->OnReceiveEvent(commonData);
    commonData.SetData("ipv4:,,cliIp,lease,servIp,subnet,dns1,dns2,router1,router2,vendor");
    dhcpSubscriber->OnReceiveEvent(commonData);
}

HWTEST_F(DhcpEventSubscriberTest, OnReceiveEventTest_DataIsIpv6, TestSize.Level1)
{
    ASSERT_TRUE(dhcpSubscriber != nullptr);
    LOGE("OnReceiveEventTest_DataIsIpv6 enter!");
    OHOS::EventFwk::CommonEventData commonData;
    commonData.SetCode(PUBLISH_UCCESS_CODE);
    commonData.SetData("ipv6:ifname,time,cliIp,lease,servIp,subnet,dns1,dns2,router1,router2,vendor");
    dhcpSubscriber->OnReceiveEvent(commonData);
}

HWTEST_F(DhcpEventSubscriberTest, OnReceiveEventTest_DataIsOther, TestSize.Level1)
{
    ASSERT_TRUE(dhcpSubscriber != nullptr);
    LOGE("OnReceiveEventTest_DataIsOther enter!");
    OHOS::EventFwk::CommonEventData commonData;
    commonData.SetCode(PUBLISH_UCCESS_CODE);
    commonData.SetData("testcode");
    dhcpSubscriber->OnReceiveEvent(commonData);
}
}
}