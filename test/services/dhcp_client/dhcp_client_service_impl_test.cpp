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

#include "dhcp_logger.h"
#include "dhcp_client_service_impl.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpClientServiceImplTest");

using namespace testing::ext;
using namespace ::testing;
namespace OHOS {
namespace Wifi {
class DhcpClientServiceImplTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        dhcpClientImpl = std::make_unique<OHOS::Wifi::DhcpClientServiceImpl>();
    }
    virtual void TearDown()
    {
        if (dhcpClientImpl != nullptr) {
            dhcpClientImpl.reset(nullptr);
        }
    }
public:
    std::unique_ptr<OHOS::Wifi::DhcpClientServiceImpl> dhcpClientImpl;
};

HWTEST_F(DhcpClientServiceImplTest, IsNativeProcessTest, TestSize.Level1)
{
    ASSERT_TRUE(dhcpClientImpl != nullptr);
    DHCP_LOGE("enter IsNativeProcess fail Test");

    const std::string& ifname = "wlan0";
    bool bIpv6 = true;
    EXPECT_EQ(DHCP_E_PERMISSION_DENIED, dhcpClientImpl->StartDhcpClient(ifname, bIpv6));
    bIpv6 = false;
    EXPECT_EQ(DHCP_E_PERMISSION_DENIED, dhcpClientImpl->StopDhcpClient(ifname, bIpv6));
    EXPECT_EQ(DHCP_E_PERMISSION_DENIED, dhcpClientImpl->RenewDhcpClient(ifname));
}

HWTEST_F(DhcpClientServiceImplTest, OnStartTest, TestSize.Level1)
{
    DHCP_LOGE("enter OnStartTest");
    dhcpClientImpl->OnStart();
}

HWTEST_F(DhcpClientServiceImplTest, OnStopTest, TestSize.Level1)
{
    DHCP_LOGE("enter OnStopTest");
    dhcpClientImpl->OnStop();
}

HWTEST_F(DhcpClientServiceImplTest, InitTest, TestSize.Level1)
{
    DHCP_LOGE("enter InitTest");
    dhcpClientImpl->Init();
}

HWTEST_F(DhcpClientServiceImplTest, StartOldClientTest, TestSize.Level1)
{
    DHCP_LOGE("enter StartOldClientTest");
    ASSERT_TRUE(dhcpClientImpl != nullptr);

    const std::string& ifname = "wlan0";
    bool bIpv6 = true;
    DhcpClient client;
    client.ifName = ifname;
    client.isIpv6 = bIpv6;
    EXPECT_EQ(DHCP_E_FAILED, dhcpClientImpl->StartOldClient(ifname, bIpv6, client));
}

HWTEST_F(DhcpClientServiceImplTest, IsRemoteDiedTest, TestSize.Level1)
{
    DHCP_LOGE("enter IsRemoteDiedTest");
    ASSERT_TRUE(dhcpClientImpl != nullptr);

    EXPECT_EQ(true, dhcpClientImpl->IsRemoteDied());
}

HWTEST_F(DhcpClientServiceImplTest, DhcpIpv4ResultTimeOutTest, TestSize.Level1)
{
    DHCP_LOGE("enter DhcpIpv4ResultTimeOut");
    ASSERT_TRUE(dhcpClientImpl != nullptr);
    std::string ifname;
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClientImpl->DhcpIpv4ResultTimeOut(ifname));
    ifname = "wlan0";
    EXPECT_EQ(DHCP_OPT_FAILED, dhcpClientImpl->DhcpIpv4ResultTimeOut(ifname));
}
1
}
}
