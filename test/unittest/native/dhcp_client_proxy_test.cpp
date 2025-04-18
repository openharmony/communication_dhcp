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
#include <gmock/gmock.h>
#include "dhcp_client_proxy.h"
#include "dhcp_logger.h"

using namespace testing::ext;
namespace OHOS {
namespace DHCP {
static std::string g_errLog = "wifitest";
class DhcpClientProxyTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        dhcpClientProxy_ = std::make_unique<DhcpClientProxy>(impl);
    }
    virtual void TearDown()
    {
    }
    sptr<IRemoteObject> impl;
    std::unique_ptr<DhcpClientProxy> dhcpClientProxy_;
};

HWTEST_F(DhcpClientProxyTest, OnRemoteDiedTest01, TestSize.Level1)
{
    wptr<IRemoteObject> remoteObject;
    dhcpClientProxy_->OnRemoteDied(remoteObject);
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
}
}
}