/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include <string>

#include "dhcp_v6_callback_impl.h"
#include "dhcp_v6_result.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpV6CallbackImplTest");

using namespace testing::ext;
using namespace OHOS::DHCP;

namespace OHOS {
class MockDhcpClientServiceImpl {
public:
    int successCallbackCount = 0;
    int failureCallbackCount = 0;
    int expiredCallbackCount = 0;
    int stopCallbackCount = 0;
    DhcpV6Result lastResult;
    int lastErrorCode = 0;
    std::string lastIfname;
    bool lastStateless = false;

    void DhcpV6ResultCallback(const std::string &ifname, const DhcpV6Result &result, bool stateless)
    {
        successCallbackCount++;
        lastResult = result;
        lastIfname = ifname;
        lastStateless = stateless;
    }

    void DhcpV6FailCallback(const std::string &ifname, int errorCode, bool stateless)
    {
        failureCallbackCount++;
        lastErrorCode = errorCode;
        lastIfname = ifname;
        lastStateless = stateless;
    }

    void DhcpV6ExpiredCallback(const std::string &ifname, bool stateless)
    {
        expiredCallbackCount++;
        lastIfname = ifname;
        lastStateless = stateless;
    }

    void DhcpV6StopCallback(const std::string &ifname, bool stateless)
    {
        stopCallbackCount++;
        lastIfname = ifname;
        lastStateless = stateless;
    }
};

class DhcpV6CallbackImplTest : public testing::Test {
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

HWTEST_F(DhcpV6CallbackImplTest, Constructor_Success, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE({
        DhcpV6CallbackImpl callback(nullptr, "wlan0", false);
    });
}

HWTEST_F(DhcpV6CallbackImplTest, Constructor_WithService, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE({
        DhcpV6CallbackImpl callback(nullptr, "eth0", true);
    });
}

HWTEST_F(DhcpV6CallbackImplTest, SetStateless, TestSize.Level1)
{
    DhcpV6CallbackImpl callback(nullptr, "wlan0", false);
    EXPECT_NO_FATAL_FAILURE(callback.SetStateless(true));
    EXPECT_NO_FATAL_FAILURE(callback.SetStateless(false));
}

HWTEST_F(DhcpV6CallbackImplTest, OnDhcpV6Success_NullService, TestSize.Level1)
{
    DhcpV6CallbackImpl callback(nullptr, "wlan0", false);
    DhcpV6Result result;
    result.ipv6Addresses = {"2001:db8::1"};

    EXPECT_NO_FATAL_FAILURE(callback.OnDhcpV6Success(result));
}

HWTEST_F(DhcpV6CallbackImplTest, OnDhcpV6Failed_NullService, TestSize.Level1)
{
    DhcpV6CallbackImpl callback(nullptr, "wlan0", false);
    EXPECT_NO_FATAL_FAILURE(callback.OnDhcpV6Failed(-1));
}

HWTEST_F(DhcpV6CallbackImplTest, OnDhcpV6Expired_NullService, TestSize.Level1)
{
    DhcpV6CallbackImpl callback(nullptr, "wlan0", false);
    EXPECT_NO_FATAL_FAILURE(callback.OnDhcpV6Expired());
}

HWTEST_F(DhcpV6CallbackImplTest, OnDhcpV6Stop_NullService, TestSize.Level1)
{
    DhcpV6CallbackImpl callback(nullptr, "wlan0", false);
    EXPECT_NO_FATAL_FAILURE(callback.OnDhcpV6Stop());
}

HWTEST_F(DhcpV6CallbackImplTest, OnDhcpV6Success_StatelessMode, TestSize.Level1)
{
    DhcpV6CallbackImpl callback(nullptr, "wlan0", true);
    DhcpV6Result result;
    result.dnsServers = {"2001:db8::53"};

    EXPECT_NO_FATAL_FAILURE(callback.OnDhcpV6Success(result));
}

HWTEST_F(DhcpV6CallbackImplTest, OnDhcpV6Failed_ErrorCode, TestSize.Level1)
{
    DhcpV6CallbackImpl callback(nullptr, "wlan0", false);
    EXPECT_NO_FATAL_FAILURE(callback.OnDhcpV6Failed(-2));
    EXPECT_NO_FATAL_FAILURE(callback.OnDhcpV6Failed(0));
}

HWTEST_F(DhcpV6CallbackImplTest, OnDhcpV6Expired_StatelessMode, TestSize.Level1)
{
    DhcpV6CallbackImpl callback(nullptr, "wlan0", true);
    EXPECT_NO_FATAL_FAILURE(callback.OnDhcpV6Expired());
}

HWTEST_F(DhcpV6CallbackImplTest, OnDhcpV6Stop_StatelessMode, TestSize.Level1)
{
    DhcpV6CallbackImpl callback(nullptr, "wlan0", true);
    EXPECT_NO_FATAL_FAILURE(callback.OnDhcpV6Stop());
}

HWTEST_F(DhcpV6CallbackImplTest, OnDhcpV6Success_WithResult, TestSize.Level1)
{
    DhcpV6CallbackImpl callback(nullptr, "wlan0", false);
    DhcpV6Result result;
    result.ipv6Addresses = {"2001:db8::1", "2001:db8::2"};
    result.dnsServers = {"2001:db8::53"};
    result.preferredLifetime = 1800;
    result.validLifetime = 3600;

    EXPECT_NO_FATAL_FAILURE(callback.OnDhcpV6Success(result));
}

HWTEST_F(DhcpV6CallbackImplTest, OnDhcpV6Failed_LeaseExpired, TestSize.Level1)
{
    DhcpV6CallbackImpl callback(nullptr, "wlan0", false);
    EXPECT_NO_FATAL_FAILURE(callback.OnDhcpV6Failed(-3));
}

HWTEST_F(DhcpV6CallbackImplTest, OnDhcpV6Stop_StatefulMode, TestSize.Level1)
{
    DhcpV6CallbackImpl callback(nullptr, "wlan0", false);
    EXPECT_NO_FATAL_FAILURE(callback.OnDhcpV6Stop());
}
}  // namespace OHOS
