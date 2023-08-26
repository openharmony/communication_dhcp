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
#include "dhcp_ipv6_client.h"

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
class DhcpIpv6ClientTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
    }
    static void TearDownTestCase()
    {
    }
    virtual void SetUp()
    {
        ipv6Client = std::make_unique<DhcpIpv6Client>();
    }
    virtual void TearDown()
    {
        if (ipv6Client != nullptr) {
            ipv6Client.reset(nullptr);
        }
    }
public:
    std::unique_ptr<DhcpIpv6Client> ipv6Client;
};

HWTEST_F(DhcpIpv6ClientTest, DhcpIpv6StartTest_IsNull, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    LOGE("DhcpIpv6StartTest_IsNull enter!");
    EXPECT_EQ(nullptr, ipv6Client->DhcpIpv6Start(nullptr));
}
}
}