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
#include <vector>
#include <string>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "dhcp_v6_client.h"
#include "dhcp_v6_callback.h"
#include "dhcp_logger.h"
#include "mock_system_func.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpV6ClientTest");

using namespace testing::ext;
using namespace OHOS::DHCP;

namespace OHOS {

class TestDhcpV6Callback : public IDhcpV6Callback {
public:
    TestDhcpV6Callback() : successCount(0), failureCount(0), expiredCount(0) {}
    virtual ~TestDhcpV6Callback() = default;

    void OnDhcpV6Success(const DhcpV6Result& result) override
    {
        successCount++;
        lastResult = result;
    }

    void OnDhcpV6Failed(int errorCode) override
    {
        failureCount++;
        lastErrorCode = errorCode;
    }

    void OnDhcpV6Expired() override
    {
        expiredCount++;
    }

    void OnDhcpV6Stop() override {}

    int successCount;
    int failureCount;
    int expiredCount;
    DhcpV6Result lastResult;
    int lastErrorCode;
};

class DhcpV6ClientTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        MockSystemFunc::SetMockFlag(true);
    }
    virtual void TearDown()
    {
        MockSystemFunc::SetMockFlag(false);
    }
};

HWTEST_F(DhcpV6ClientTest, Constructor_SUCCESS, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE({
        DhcpV6Client client("wlan0");
    });
}

HWTEST_F(DhcpV6ClientTest, Destructor_SUCCESS, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE({
        DhcpV6Client* client = new DhcpV6Client("wlan0");
        delete client;
    });
}

HWTEST_F(DhcpV6ClientTest, DhcpV6ConfigureStateless_True, TestSize.Level1)
{
    DhcpV6Client client("wlan0");
    EXPECT_NO_FATAL_FAILURE(client.DhcpV6ConfigureStateless(true));
}

HWTEST_F(DhcpV6ClientTest, DhcpV6ConfigureStateless_False, TestSize.Level1)
{
    DhcpV6Client client("wlan0");
    EXPECT_NO_FATAL_FAILURE(client.DhcpV6ConfigureStateless(false));
}

HWTEST_F(DhcpV6ClientTest, DhcpV6Stop_Success, TestSize.Level1)
{
    DhcpV6Client client("wlan0");

    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), setsockopt(_, _, _, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_))
        .WillRepeatedly(Return(0));

    int result = client.DhcpV6Stop();
    EXPECT_GE(result, 0);
}

HWTEST_F(DhcpV6ClientTest, DhcpV6RegisterCallback_Success, TestSize.Level1)
{
    DhcpV6Client client("wlan0");
    TestDhcpV6Callback callback;

    int result = client.DhcpV6RegisterCallback(&callback);
    EXPECT_GE(result, 0);
}

HWTEST_F(DhcpV6ClientTest, DhcpV6RegisterCallback_Nullptr, TestSize.Level1)
{
    DhcpV6Client client("wlan0");

    int result = client.DhcpV6RegisterCallback(nullptr);
    EXPECT_GE(result, 0);
}

HWTEST_F(DhcpV6ClientTest, OnKernelDadConflict, TestSize.Level1)
{
    DhcpV6Client client("wlan0");

    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), setsockopt(_, _, _, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_))
        .WillRepeatedly(Return(0));

    EXPECT_NO_FATAL_FAILURE(client.OnKernelDadConflict("2001:db8::1"));
}

HWTEST_F(DhcpV6ClientTest, IsDhcpV6ConfiguredAddress, TestSize.Level1)
{
    DhcpV6Client client("wlan0");

    bool result = client.IsDhcpV6ConfiguredAddress("2001:db8::1");
    EXPECT_FALSE(result);
}

HWTEST_F(DhcpV6ClientTest, DhcpV6Stop_MultipleTimes, TestSize.Level1)
{
    DhcpV6Client client("wlan0");
    client.DhcpV6ConfigureStateless(true);

    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), setsockopt(_, _, _, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), sendto(_, _, _, _, _, _))
        .WillRepeatedly(Return(10));
    EXPECT_CALL(MockSystemFunc::GetInstance(), poll(_, _, _))
        .WillRepeatedly(Return(-1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), if_nametoindex(_))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_))
        .WillRepeatedly(Return(0));

    // Test calling Stop multiple times (should handle gracefully)
    (void)client.DhcpV6Stop();
    (void)client.DhcpV6Stop();  // Second call should return early
}

HWTEST_F(DhcpV6ClientTest, RegisterCallback_BeforeStop, TestSize.Level1)
{
    DhcpV6Client client("wlan0");
    client.DhcpV6ConfigureStateless(true);

    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), setsockopt(_, _, _, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), sendto(_, _, _, _, _, _))
        .WillRepeatedly(Return(10));
    EXPECT_CALL(MockSystemFunc::GetInstance(), poll(_, _, _))
        .WillRepeatedly(Return(-1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), if_nametoindex(_))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_))
        .WillRepeatedly(Return(0));

    TestDhcpV6Callback callback;
    (void)client.DhcpV6RegisterCallback(&callback);
    (void)client.DhcpV6Stop();
}

HWTEST_F(DhcpV6ClientTest, DhcpV6Stop_StatelessMode, TestSize.Level1)
{
    DhcpV6Client client("wlan0");
    client.DhcpV6ConfigureStateless(true);

    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), setsockopt(_, _, _, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), sendto(_, _, _, _, _, _))
        .WillRepeatedly(Return(10));
    EXPECT_CALL(MockSystemFunc::GetInstance(), poll(_, _, _))
        .WillRepeatedly(Return(-1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), if_nametoindex(_))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_))
        .WillRepeatedly(Return(0));

    int result = client.DhcpV6Stop();
    EXPECT_GE(result, 0);
}

HWTEST_F(DhcpV6ClientTest, DhcpV6Stop_StatefulMode, TestSize.Level1)
{
    DhcpV6Client client("wlan0");
    client.DhcpV6ConfigureStateless(false);

    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), setsockopt(_, _, _, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), sendto(_, _, _, _, _, _))
        .WillRepeatedly(Return(10));
    EXPECT_CALL(MockSystemFunc::GetInstance(), poll(_, _, _))
        .WillRepeatedly(Return(-1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), if_nametoindex(_))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_))
        .WillRepeatedly(Return(0));

    int result = client.DhcpV6Stop();
    EXPECT_GE(result, 0);
}
}  // namespace OHOS
