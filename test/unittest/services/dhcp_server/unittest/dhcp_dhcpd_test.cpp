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

#include "dhcp_dhcpd.h"
#include "dhcp_s_server.h"
#include "dhcp_config.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpDhcpdTest");

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::DHCP;
namespace OHOS {
namespace DHCP {
class DhcpDhcpdTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
    }
    virtual void TearDown()
    {
    }
private:
    DhcpServerContext *m_pServerCtx = nullptr;
    DhcpConfig m_serverConfg;
};

HWTEST_F(DhcpDhcpdTest, StartDhcpServerMainTest, TestSize.Level1)
{
    DHCP_LOGI("StartDhcpServerMainTest enter");
    std::string ifName = "wlan0";
    std::string netMask = "192.77.1.232";
    std::string ipRange;
    std::string localIp = "192.77.1.232";
    EXPECT_EQ(1, StartDhcpServerMain(ifName, netMask, ipRange, localIp));
}

HWTEST_F(DhcpDhcpdTest, RegisterDeviceConnectCallBackTest, TestSize.Level1) // duliqun
{
    DHCP_LOGI("RegisterDeviceConnectCallBackTest enter");
    DeviceConnectFun func = nullptr;
    EXPECT_EQ(0, RegisterDeviceConnectCallBack(func));
}
}
}
