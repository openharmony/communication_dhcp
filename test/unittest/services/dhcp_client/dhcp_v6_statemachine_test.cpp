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
#include <vector>

#include "dhcp_v6_statemachine.h"
#include "dhcp_v6_message.h"
#include "dhcp_v6_constants.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpV6StateMachineTest");

using namespace testing::ext;
using namespace OHOS::DHCP;

namespace OHOS {

class DhcpV6StateMachineTest : public testing::Test {
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

//=============================================================================
// Constructor and Destructor Tests
//=============================================================================
HWTEST_F(DhcpV6StateMachineTest, Constructor_Success, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE({
        DhcpV6StateMachine sm;
    });
}

HWTEST_F(DhcpV6StateMachineTest, Destructor_Success, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE({
        DhcpV6StateMachine* sm = new DhcpV6StateMachine();
        delete sm;
    });
}

//=============================================================================
// Configuration Tests
//=============================================================================
HWTEST_F(DhcpV6StateMachineTest, SetConfig_Stateless, TestSize.Level1)
{
    DhcpV6StateMachine sm;
    DhcpV6Config config;
    config.stateless = true;
    config.clientId = "test-client-id";

    EXPECT_NO_FATAL_FAILURE(sm.SetConfig(config));
}

HWTEST_F(DhcpV6StateMachineTest, SetConfig_Stateful, TestSize.Level1)
{
    DhcpV6StateMachine sm;
    DhcpV6Config config;
    config.stateless = false;
    config.clientId = "test-client-id";

    EXPECT_NO_FATAL_FAILURE(sm.SetConfig(config));
}

HWTEST_F(DhcpV6StateMachineTest, SetIfaceName, TestSize.Level1)
{
    DhcpV6StateMachine sm;
    std::string ifname = "wlan0";

    EXPECT_NO_FATAL_FAILURE(sm.SetIfaceName(ifname));
    EXPECT_EQ(ifname, sm.GetIface());
}

HWTEST_F(DhcpV6StateMachineTest, SetSocket, TestSize.Level1)
{
    DhcpV6StateMachine sm;
    DhcpV6Socket* socket = nullptr;

    EXPECT_NO_FATAL_FAILURE(sm.SetSocket(socket));
    EXPECT_EQ(socket, sm.GetSocket());
}

HWTEST_F(DhcpV6StateMachineTest, SetStopping, TestSize.Level1)
{
    DhcpV6StateMachine sm;

    EXPECT_NO_FATAL_FAILURE(sm.SetStopping(true));
    EXPECT_TRUE(sm.IsStopping());

    EXPECT_NO_FATAL_FAILURE(sm.SetStopping(false));
    EXPECT_FALSE(sm.IsStopping());
}

//=============================================================================
// Callback Tests
//=============================================================================
HWTEST_F(DhcpV6StateMachineTest, SetResultCallback, TestSize.Level1)
{
    DhcpV6StateMachine sm;
    std::function<void(const DhcpV6Result&)> successCb = [](const DhcpV6Result&) {};
    std::function<void(int)> failureCb = [](int) {};

    EXPECT_NO_FATAL_FAILURE(sm.SetResultCallback(successCb, failureCb));
}

HWTEST_F(DhcpV6StateMachineTest, SetExpiredCallback, TestSize.Level1)
{
    DhcpV6StateMachine sm;
    std::function<void()> expiredCb = []() {};

    EXPECT_NO_FATAL_FAILURE(sm.SetExpiredCallback(expiredCb));
}

//=============================================================================
// Retry and Timeout Tests
//=============================================================================
HWTEST_F(DhcpV6StateMachineTest, RetryCountOperations, TestSize.Level1)
{
    DhcpV6StateMachine sm;

    EXPECT_EQ(0, sm.GetRetryCount());

    sm.IncrementRetryCount();
    EXPECT_EQ(1, sm.GetRetryCount());

    sm.IncrementRetryCount();
    EXPECT_EQ(2, sm.GetRetryCount());

    sm.ResetRetryCount();
    EXPECT_EQ(0, sm.GetRetryCount());
}

HWTEST_F(DhcpV6StateMachineTest, MaxRetries, TestSize.Level1)
{
    DhcpV6StateMachine sm;

    EXPECT_EQ(DEFAULT_MAX_RETRIES, sm.GetMaxRetries());
}

HWTEST_F(DhcpV6StateMachineTest, TimeoutOperations, TestSize.Level1)
{
    DhcpV6StateMachine sm;

    EXPECT_EQ(BASE_TIMEOUT_MS, sm.GetCurrentTimeout());

    sm.SetCurrentTimeout(2000);
    EXPECT_EQ(2000, sm.GetCurrentTimeout());
}

//=============================================================================
// Result Management Tests
//=============================================================================
HWTEST_F(DhcpV6StateMachineTest, SetAndGetResult, TestSize.Level1)
{
    DhcpV6StateMachine sm;
    DhcpV6Result result;
    result.ipv6Addresses = {"2001:db8::1"};
    result.dnsServers = {"2001:db8::53"};
    result.preferredLifetime = 1800;
    result.validLifetime = 3600;

    EXPECT_NO_FATAL_FAILURE(sm.SetResult(result));

    const auto& retrieved = sm.GetResult();
    EXPECT_EQ(result.ipv6Addresses, retrieved.ipv6Addresses);
    EXPECT_EQ(result.dnsServers, retrieved.dnsServers);
    EXPECT_EQ(result.preferredLifetime, retrieved.preferredLifetime);
    EXPECT_EQ(result.validLifetime, retrieved.validLifetime);
}

HWTEST_F(DhcpV6StateMachineTest, SetAndGetConfig, TestSize.Level1)
{
    DhcpV6StateMachine sm;
    DhcpV6Config config;
    config.stateless = true;
    config.clientId = "client-123";

    sm.SetConfig(config);

    const auto& retrieved = sm.GetConfig();
    EXPECT_EQ(config.stateless, retrieved.stateless);
    EXPECT_EQ(config.clientId, retrieved.clientId);
}

//=============================================================================
// Advertise Management Tests
//=============================================================================
HWTEST_F(DhcpV6StateMachineTest, SetAndGetCurrentAdvertise, TestSize.Level1)
{
    DhcpV6StateMachine sm;
    DhcpV6Advertise advertise;
    advertise.serverId = "server-456";
    advertise.preference = 255;

    EXPECT_NO_FATAL_FAILURE(sm.SetCurrentAdvertise(advertise));

    const auto& retrieved = sm.GetCurrentAdvertise();
    EXPECT_EQ(advertise.serverId, retrieved.serverId);
    EXPECT_EQ(advertise.preference, retrieved.preference);
}

//=============================================================================
// Transaction ID Tests
//=============================================================================
HWTEST_F(DhcpV6StateMachineTest, TransactionIdOperations, TestSize.Level1)
{
    DhcpV6StateMachine sm;

    sm.SetTransactionId(0xABCDEF);
    EXPECT_EQ(0xABCDEF, sm.GetTransactionId());

    sm.SetTransactionId(0);
    EXPECT_EQ(0, sm.GetTransactionId());
}

//=============================================================================
// DAD Conflict Tests
//=============================================================================
HWTEST_F(DhcpV6StateMachineTest, IsDhcpV6ConfiguredAddress_Empty, TestSize.Level1)
{
    DhcpV6StateMachine sm;

    EXPECT_FALSE(sm.IsDhcpV6ConfiguredAddress("2001:db8::1"));
}

HWTEST_F(DhcpV6StateMachineTest, IsDhcpV6ConfiguredAddress_WithResult, TestSize.Level1)
{
    DhcpV6StateMachine sm;
    DhcpV6Result result;
    result.ipv6Addresses = {"2001:db8::1", "2001:db8::2"};
    sm.SetResult(result);

    EXPECT_TRUE(sm.IsDhcpV6ConfiguredAddress("2001:db8::1"));
    EXPECT_TRUE(sm.IsDhcpV6ConfiguredAddress("2001:db8::2"));
    EXPECT_FALSE(sm.IsDhcpV6ConfiguredAddress("2001:db8::3"));
}

//=============================================================================
// Deadline Management Tests
//=============================================================================
HWTEST_F(DhcpV6StateMachineTest, T2DeadlineOperations, TestSize.Level1)
{
    DhcpV6StateMachine sm;

    sm.SetT2DeadlineMs(1234567890);
    EXPECT_EQ(1234567890, sm.GetT2DeadlineMs());

    sm.ClearT2Deadline();
    EXPECT_EQ(0, sm.GetT2DeadlineMs());
}

HWTEST_F(DhcpV6StateMachineTest, ExpireDeadlineOperations, TestSize.Level1)
{
    DhcpV6StateMachine sm;

    sm.SetExpireDeadlineMs(9876543210);
    EXPECT_EQ(9876543210, sm.GetExpireDeadlineMs());

    sm.ClearExpireDeadline();
    EXPECT_EQ(0, sm.GetExpireDeadlineMs());
}

//=============================================================================
// Callback Invocation Tests
//=============================================================================
HWTEST_F(DhcpV6StateMachineTest, OnSuccess_CallbackSet, TestSize.Level1)
{
    DhcpV6StateMachine sm;
    DhcpV6Result result;
    result.ipv6Addresses = {"2001:db8::1"};

    bool callbackInvoked = false;
    std::function<void(const DhcpV6Result&)> successCb = [&callbackInvoked](const DhcpV6Result&) {
        callbackInvoked = true;
    };
    std::function<void(int)> failureCb = [](int) {};

    sm.SetResultCallback(successCb, failureCb);
    sm.SetResult(result);
    sm.OnSuccess();

    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(DhcpV6StateMachineTest, OnFailure_CallbackSet, TestSize.Level1)
{
    DhcpV6StateMachine sm;

    bool callbackInvoked = false;
    int receivedErrorCode = 0;
    std::function<void(const DhcpV6Result&)> successCb = [](const DhcpV6Result&) {};
    std::function<void(int)> failureCb = [&callbackInvoked, &receivedErrorCode](int errorCode) {
        callbackInvoked = true;
        receivedErrorCode = errorCode;
    };

    sm.SetResultCallback(successCb, failureCb);
    sm.OnFailure(ERR_DAD_FAILED);

    EXPECT_TRUE(callbackInvoked);
    EXPECT_EQ(ERR_DAD_FAILED, receivedErrorCode);
}

HWTEST_F(DhcpV6StateMachineTest, OnLeaseExpired_CallbackSet, TestSize.Level1)
{
    DhcpV6StateMachine sm;

    bool callbackInvoked = false;
    std::function<void()> expiredCb = [&callbackInvoked]() {
        callbackInvoked = true;
    };

    sm.SetExpiredCallback(expiredCb);
    sm.OnLeaseExpired();

    EXPECT_TRUE(callbackInvoked);
}

//=============================================================================
// ProcessResultInfo Tests
//=============================================================================
HWTEST_F(DhcpV6StateMachineTest, ProcessResultInfo_Basic, TestSize.Level1)
{
    DhcpV6StateMachine sm;
    DhcpV6Advertise advertise;
    advertise.serverId = "server-123";
    advertise.ipv6Addresses = {"2001:db8::100"};
    advertise.dnsServers = {"2001:db8::53"};
    advertise.preferredLifetime = 1800;
    advertise.validLifetime = 3600;
    advertise.t1 = 0;  // Should be calculated
    advertise.t2 = 0;  // Should be calculated

    EXPECT_NO_FATAL_FAILURE(sm.ProcessResultInfo(advertise));

    const auto& result = sm.GetResult();
    EXPECT_EQ(advertise.ipv6Addresses, result.ipv6Addresses);
    EXPECT_EQ(advertise.dnsServers, result.dnsServers);
    EXPECT_EQ(1800, result.preferredLifetime);
    EXPECT_EQ(3600, result.validLifetime);
}

HWTEST_F(DhcpV6StateMachineTest, ProcessResultInfo_T1Calculation, TestSize.Level1)
{
    DhcpV6StateMachine sm;
    DhcpV6Advertise advertise;
    advertise.validLifetime = 3600;
    advertise.t1 = 0;  // Should be calculated: 3600 / 2 = 1800

    sm.ProcessResultInfo(advertise);

    const auto& result = sm.GetResult();
    EXPECT_EQ(1800, result.t1);  // validLifetime / T1_DIVISOR
}

HWTEST_F(DhcpV6StateMachineTest, ProcessResultInfo_T2Calculation, TestSize.Level1)
{
    DhcpV6StateMachine sm;
    DhcpV6Advertise advertise;
    advertise.validLifetime = 3600;
    advertise.t2 = 0;  // Should be calculated: 3600 * 80 / 100 = 2880

    sm.ProcessResultInfo(advertise);

    const auto& result = sm.GetResult();
    EXPECT_EQ(2880, result.t2);  // validLifetime * T2_LIFETIME_RATIO / LIFETIME_RATIO_BASE
}

HWTEST_F(DhcpV6StateMachineTest, ProcessResultInfo_T1NotZero, TestSize.Level1)
{
    DhcpV6StateMachine sm;
    DhcpV6Advertise advertise;
    advertise.validLifetime = 3600;
    advertise.t1 = 1000;  // Should NOT be recalculated

    sm.ProcessResultInfo(advertise);

    const auto& result = sm.GetResult();
    EXPECT_EQ(1000, result.t1);
}

HWTEST_F(DhcpV6StateMachineTest, ProcessResultInfo_T2NotZero, TestSize.Level1)
{
    DhcpV6StateMachine sm;
    DhcpV6Advertise advertise;
    advertise.validLifetime = 3600;
    advertise.t2 = 2000;  // Should NOT be recalculated

    sm.ProcessResultInfo(advertise);

    const auto& result = sm.GetResult();
    EXPECT_EQ(2000, result.t2);
}

HWTEST_F(DhcpV6StateMachineTest, ProcessResultInfo_InfiniteLifetime, TestSize.Level1)
{
    DhcpV6StateMachine sm;
    DhcpV6Advertise advertise;
    advertise.validLifetime = INFINITE_LIFETIME;
    advertise.t1 = 0;
    advertise.t2 = 0;

    sm.ProcessResultInfo(advertise);

    const auto& result = sm.GetResult();
    EXPECT_EQ(INFINITE_LIFETIME, result.validLifetime);
    EXPECT_EQ(0, result.t1);
    EXPECT_EQ(0, result.t2);
}

//=============================================================================
// GetCurrentTimeMs Test
//=============================================================================
HWTEST_F(DhcpV6StateMachineTest, GetCurrentTimeMs_PositiveValue, TestSize.Level1)
{
    DhcpV6StateMachine sm;

    uint64_t time1 = sm.GetCurrentTimeMs();
    uint64_t time2 = sm.GetCurrentTimeMs();

    EXPECT_GT(time1, 0);
    EXPECT_GE(time2, time1);
}

//=============================================================================
// Error Code Constants Test
//=============================================================================
HWTEST_F(DhcpV6StateMachineTest, ErrorCodeConstants, TestSize.Level1)
{
    EXPECT_EQ(-1, ERR_GENERIC);
    EXPECT_EQ(-3, ERR_DAD_FAILED);
    EXPECT_EQ(-4, ERR_LEASE_EXPIRED);
    EXPECT_EQ(-5, ERR_RETRY_EXCEEDED);
}

//=============================================================================
// Time Constants Test
//=============================================================================
HWTEST_F(DhcpV6StateMachineTest, TimeConstants, TestSize.Level1)
{
    EXPECT_EQ(1000, BASE_TIMEOUT_MS);
    EXPECT_EQ(1000, TIMEOUT_INCREMENT_MS);
    EXPECT_EQ(1000, RECV_TIMEOUT_MS);
}

//=============================================================================
// Lifetime Ratio Constants Test
//=============================================================================
HWTEST_F(DhcpV6StateMachineTest, LifetimeRatioConstants, TestSize.Level1)
{
    EXPECT_EQ(80, T2_LIFETIME_RATIO);
    EXPECT_EQ(100, LIFETIME_RATIO_BASE);
    EXPECT_EQ(2, T1_DIVISOR);
}

}  // namespace OHOS
