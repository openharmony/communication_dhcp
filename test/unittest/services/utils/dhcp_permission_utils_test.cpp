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
#include "dhcp_permission_utils.h"
#include "dhcp_logger.h"
 
DEFINE_DHCPLOG_DHCP_LABEL("DhcpPermissionUtilsTest");
using namespace testing::ext;
using namespace OHOS::DHCP;
 
namespace OHOS {
constexpr uint64_t SLEEP_TIME = 2;
constexpr int TIMER_TYPE = 1;
class DhcpPermissionUtilsTest : public testing::Test {
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
 
HWTEST_F(DhcpPermissionUtilsTest, VerifyIsNativeProcessTest, TestSize.Level1)
{
    DHCP_LOGI("VerifyIsNativeProcessTest enter!");
    EXPECT_FALSE(DhcpPermissionUtils::VerifyIsNativeProcess());
}
 
HWTEST_F(DhcpPermissionUtilsTest, VerifyDhcpNetworkPermissionTest, TestSize.Level1)
{
    DHCP_LOGI("VerifyDhcpNetworkPermissionTest enter!");
    EXPECT_FALSE(DhcpPermissionUtils::VerifyDhcpNetworkPermission("NETWORK_DHCP"));
    EXPECT_FALSE(DhcpPermissionUtils::VerifyDhcpNetworkPermission("ohos.permission.NETWORK_DHCP"));
}
}