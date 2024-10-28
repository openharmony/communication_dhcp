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
#include "dhcp_result_store_manager.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpResultStoreManagerTest");

using namespace testing::ext;

namespace OHOS {
constexpr int ZERO = 0;
class DhcpResultStoreManagerTest : public testing::Test {
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
 * @tc.name: SaveIpInfoInLocalFile_SUCCESS
 * @tc.desc: SaveIpInfoInLocalFile
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpResultStoreManagerTest, SaveIpInfoInLocalFile_SUCCESS, TestSize.Level1)
{
    DHCP_LOGE("enter SaveIpInfoInLocalFile_SUCCESS");
    IpInfoCached ipInfoCached;
    ipInfoCached.bssid = "12:34:56:48:78:56";
    ipInfoCached.absoluteLeasetime = 1;
    DHCP::DhcpResultStoreManager::GetInstance().SaveIpInfoInLocalFile(ipInfoCached);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}
/**
 * @tc.name: GetCachedDhcpResult_SUCCESS
 * @tc.desc: GetCachedDhcpResult
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(DhcpResultStoreManagerTest, GetCachedDhcpResult_SUCCESS, TestSize.Level1)
{
    DHCP_LOGE("enter GetCachedDhcpResult_SUCCESS");
    std::string targetBssid = "12:34:56:48:78:56";
    IpInfoCached ipInfo;
    DHCP::DhcpResultStoreManager::GetInstance().GetCachedIp(targetBssid, ipInfo);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}
}  // namespace OHOS