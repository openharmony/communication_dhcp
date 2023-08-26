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
#include "dhcp_function.h"
#include "dhcp_api.h"

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
constexpr int ARRAY_SIZE = 1030;
class DhcpApiTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(DhcpApiTest, PublishDhcpIpv4ResultEventTest1, TestSize.Level1)
{
    LOGE("PublishDhcpIpv4ResultEventTest1 enter!");
    char data[] = "testcode";
    bool result = PublishDhcpIpv4ResultEvent(1, data, nullptr);
    LOGE("PublishDhcpIpv4ResultEventTest1 result(%{public}d)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(DhcpApiTest, PublishDhcpIpv4ResultEventTest2, TestSize.Level1)
{
    LOGE("PublishDhcpIpv4ResultEventTest2 enter!");
    char data[] = "testcode";
    char ifname[] = "testcode";
    bool result = PublishDhcpIpv4ResultEvent(1, data, ifname);
    LOGE("PublishDhcpIpv4ResultEventTest2 result(%{public}d)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(DhcpApiTest, PublishDhcpIpv4ResultEventTest3, TestSize.Level1)
{
    LOGE("PublishDhcpIpv4ResultEventTest3 enter!");
    char data[] = "testcode";
    char ifname[ARRAY_SIZE] = {1};
    bool result = PublishDhcpIpv4ResultEvent(1, data, ifname);
    LOGE("PublishDhcpIpv4ResultEventTest3 result(%{public}d)", result);
    EXPECT_TRUE(result);
}
}
}
