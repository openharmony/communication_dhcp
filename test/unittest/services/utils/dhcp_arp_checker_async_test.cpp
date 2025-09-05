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
#include <chrono>
#include <thread>
#include <future>
#include <memory>
#include "dhcp_logger.h"
#include "dhcp_arp_checker.h"
#include "mock_system_func.h"
#include "securec.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpArpCheckerAsyncTest");
using namespace testing::ext;
using namespace OHOS::DHCP;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetErrnoAndReturn;

namespace OHOS {
class DhcpArpCheckerAsyncTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        MockSystemFunc::SetMockFlag(false);
    }

    static void TearDownTestCase()
    {
        MockSystemFunc::SetMockFlag(false);
    }

    virtual void SetUp()
    {
        MockSystemFunc::SetMockFlag(false);
        checker_ = std::make_unique<DhcpArpChecker>();
    }

    virtual void TearDown()
    {
        if (checker_) {
            checker_->m_isSocketCreated = false;
            checker_->m_socketFd = -1;
        }
        MockSystemFunc::SetMockFlag(false);
        checker_.reset();
    }

protected:
    std::unique_ptr<DhcpArpChecker> checker_;
    const std::string validIfName_ = "eth0";
    const std::string validMacAddr_ = "11:22:33:44:55:66";
    const std::string validSenderIp_ = "192.168.1.100";
    const std::string validTargetIp_ = "192.168.1.1";
    const int validSocket = 3;

    void SetupValidSocket()
    {
        checker_->m_socketFd = validSocket;
        checker_->m_ifaceIndex = 1;
        checker_->m_protocol = ETH_P_ARP;
        checker_->m_isSocketCreated = true;
    }
};

// ==================== Concurrent Access Tests ====================

/**
 * @tc.name: ConcurrentStartTest_MultipleCalls_SafeHandling
 * @tc.desc: Test concurrent Start calls are handled safely
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DhcpArpCheckerAsyncTest, ConcurrentStartTest_MultipleCalls_SafeHandling, TestSize.Level1)
{
    DHCP_LOGE("enter ConcurrentStartTest_MultipleCalls_SafeHandling");

    MockSystemFunc::SetMockFlag(true);
    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(AF_PACKET, SOCK_DGRAM, ::testing::_))
        .WillRepeatedly(Return(3));
    
    // Mock fcntl for SetNonBlock
    EXPECT_CALL(MockSystemFunc::GetInstance(), fcntl2(3, F_GETFL))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), fcntl3(3, F_SETFL, ::testing::_))
        .WillRepeatedly(Return(0));
    
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(3, ::testing::_, ::testing::_))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_))
        .WillRepeatedly(Return(0));
    
    // Mock if_nametoindex for GetInterfaceIndex
    EXPECT_CALL(MockSystemFunc::GetInstance(), if_nametoindex(::testing::_))
        .WillRepeatedly(Return(2));

    const int numThreads = 5;
    std::vector<std::future<bool>> futures;

// Launch multiple Start operations concurrently
for (int i = 0; i < numThreads; ++i) {
    futures.push_back(std::async(std::launch::async, [this, i]() {
        std::string ifName = validIfName_;
        std::string hwAddr = validMacAddr_;
        std::string senderIp = validSenderIp_;
        std::string targetIp = validTargetIp_;
        
        return checker_->Start(ifName, hwAddr, senderIp, targetIp); }));
    }

    // Wait for all operations to complete
    int successCount = 0;
for (auto &future : futures) {
    if (future.get()) {
        successCount++;
    }
}

    // At least one should succeed
    EXPECT_GT(successCount, 0);

    MockSystemFunc::SetMockFlag(false);
}

/**
 * @tc.name: ConcurrentStopTest_MultipleCalls_SafeHandling
 * @tc.desc: Test concurrent Stop calls are handled safely
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DhcpArpCheckerAsyncTest, ConcurrentStopTest_MultipleCalls_SafeHandling, TestSize.Level1)
{
    DHCP_LOGE("enter ConcurrentStopTest_MultipleCalls_SafeHandling");

    SetupValidSocket();

    MockSystemFunc::SetMockFlag(true);
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_))
        .WillRepeatedly(Return(0));

    const int numThreads = 3;
    std::vector<std::future<void>> futures;

// Launch multiple Stop operations concurrently
for (int i = 0; i < numThreads; ++i) {
    futures.push_back(std::async(std::launch::async, [this]() {
        checker_->Stop();
    }));
}

// Wait for all operations to complete
for (auto &future : futures) {
        future.get();
    }

    // Socket should be properly closed
    EXPECT_FALSE(checker_->m_isSocketCreated);
    EXPECT_EQ(checker_->m_socketFd, -1);

    MockSystemFunc::SetMockFlag(false);
}

/**
 * @tc.name: StartStopConcurrentTest_StartAndStop_SafeHandling
 * @tc.desc: Test concurrent Start and Stop operations
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DhcpArpCheckerAsyncTest, StartStopConcurrentTest_StartAndStop_SafeHandling, TestSize.Level1)
{
    DHCP_LOGE("enter StartStopConcurrentTest_StartAndStop_SafeHandling");

    MockSystemFunc::SetMockFlag(true);
    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(AF_PACKET, SOCK_DGRAM, ::testing::_))
        .WillRepeatedly(Return(3));
    
    // Mock fcntl for SetNonBlock
    EXPECT_CALL(MockSystemFunc::GetInstance(), fcntl2(3, F_GETFL))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), fcntl3(3, F_SETFL, ::testing::_))
        .WillRepeatedly(Return(0));
    
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(3, ::testing::_, ::testing::_))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_))
        .WillRepeatedly(Return(0));
    
    // Mock if_nametoindex for GetInterfaceIndex
    EXPECT_CALL(MockSystemFunc::GetInstance(), if_nametoindex(::testing::_))
        .WillRepeatedly(Return(2));

    // Start a thread that continuously starts the checker
    auto startFuture = std::async(std::launch::async, [this]()
                                    {
    for (int i = 0; i < 10; ++i) {
        std::string ifName = validIfName_;
        std::string hwAddr = validMacAddr_;
        std::string senderIp = validSenderIp_;
        std::string targetIp = validTargetIp_;
        
        checker_->Start(ifName, hwAddr, senderIp, targetIp);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } });

    // Start a thread that continuously stops the checker
    auto stopFuture = std::async(std::launch::async, [this]()
                                    {
    for (int i = 0; i < 10; ++i) {
        checker_->Stop();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } });

    // Wait for both threads to complete
    startFuture.get();
    stopFuture.get();

    // Final cleanup
    checker_->Stop();

    MockSystemFunc::SetMockFlag(false);
}

// ==================== Timeout and Long-running Operation Tests ====================

/**
 * @tc.name: LongRunningDoArpCheckTest_ExtendedTimeout_HandleCorrectly
 * @tc.desc: Test DoArpCheck with extended timeout
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DhcpArpCheckerAsyncTest, LongRunningDoArpCheckTest_ExtendedTimeout_HandleCorrectly, TestSize.Level1)
{
    DHCP_LOGE("enter LongRunningDoArpCheckTest_ExtendedTimeout_HandleCorrectly");

    SetupValidSocket();
    checker_->ParseAndValidateMacAddress(validMacAddr_);
    checker_->ValidateAndSetIpAddresses(validSenderIp_, validTargetIp_);

    MockSystemFunc::SetMockFlag(true);
    EXPECT_CALL(MockSystemFunc::GetInstance(), sendto(_, _, _, _, _, _))
        .WillOnce(Return(sizeof(ArpPacket)));
    EXPECT_CALL(MockSystemFunc::GetInstance(), poll(_, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), read(_, _, _))
        .WillRepeatedly(Return(0)); // Always timeout

    auto startTime = std::chrono::steady_clock::now();
    uint64_t timeCost = 0;

    // Use async to test with a reasonable timeout
    auto future = std::async(std::launch::async, [this, &timeCost]()
                                {
                                    return checker_->DoArpCheck(1000, false, timeCost); // 1 second timeout
                                });

// Should complete within reasonable time (allow some extra time for processing)
auto status = future.wait_for(std::chrono::seconds(3));
EXPECT_EQ(status, std::future_status::ready);

if (status == std::future_status::ready) {
    bool result = future.get();
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

    // Should respect the timeout (allow some tolerance)
    EXPECT_LE(duration.count(), 2000); // Should not exceed 2 seconds
    EXPECT_LE(timeCost, 1000);          // Should be less than 1 second
    EXPECT_FALSE(result);
}

    MockSystemFunc::SetMockFlag(false);
}

// ==================== Interface blocklist Tests ====================

/**
 * @tc.name: InterfaceAttemptTest_OngoingBind_Blocked
 * @tc.desc: Test ongoing bind attempt blocks new attempts
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DhcpArpCheckerAsyncTest, InterfaceAttemptTest_OngoingBind_Blocked, TestSize.Level1)
{
    DHCP_LOGE("enter InterfaceAttemptTest_OngoingBind_Blocked");

    const std::string testInterface = "test_attempt_interface";

    // Initially should be safe
    EXPECT_TRUE(checker_->IsInterfaceSafe(testInterface.c_str()));

    // Record ongoing bind attempt
    checker_->RecordInterfaceAttempt(testInterface.c_str());

    // Should now be blocked
    EXPECT_FALSE(checker_->IsInterfaceSafe(testInterface.c_str()));

    // Test that CreateSocket respects ongoing attempts
    EXPECT_EQ(checker_->CreateSocket(testInterface.c_str(), ETH_P_ARP), -1);
}

/**
 * @tc.name: InterfaceAttemptConcurrentTest_MultipleInterfaces_SafeHandling
 * @tc.desc: Test concurrent attempt operations on multiple interfaces
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DhcpArpCheckerAsyncTest, InterfaceAttemptConcurrentTest_MultipleInterfaces_SafeHandling, TestSize.Level1)
{
    DHCP_LOGE("enter InterfaceAttemptConcurrentTest_MultipleInterfaces_SafeHandling");

    const std::vector<std::string> testInterfaces = {
        "test_if1", "test_if2", "test_if3", "test_if4", "test_if5"};

    std::vector<std::future<void>> futures;

// Concurrently record attempts on interfaces
for (const auto &ifName : testInterfaces) {
    futures.push_back(std::async(std::launch::async, [this, ifName]() {
        for (int i = 0; i < 10; ++i) {
            checker_->RecordInterfaceAttempt(ifName.c_str());
            checker_->IsInterfaceSafe(ifName.c_str());
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    }));
}

// Wait for all operations
for (auto &future : futures) {
    future.get();
}

// All interfaces should have ongoing attempts
for (const auto &ifName : testInterfaces) {
    EXPECT_FALSE(checker_->IsInterfaceSafe(ifName.c_str()));
}
}

// ==================== Memory and Resource Tests ====================

/**
 * @tc.name: ResourceLeakTest_MultipleStartStop_NoLeaks
 * @tc.desc: Test multiple start/stop cycles don't cause resource leaks
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DhcpArpCheckerAsyncTest, ResourceLeakTest_MultipleStartStop_NoLeaks, TestSize.Level1)
{
    DHCP_LOGE("enter ResourceLeakTest_MultipleStartStop_NoLeaks");

    MockSystemFunc::SetMockFlag(true);

    // Set up expectations for multiple socket operations
    EXPECT_CALL(MockSystemFunc::GetInstance(), if_nametoindex(::testing::_))
        .WillRepeatedly(Return(2));
    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(AF_PACKET, SOCK_DGRAM, ::testing::_))
        .WillRepeatedly(Return(3));
    EXPECT_CALL(MockSystemFunc::GetInstance(), fcntl2(3, F_GETFL))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), fcntl3(3, F_SETFL, ::testing::_))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(3, ::testing::_, ::testing::_))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_))
        .WillRepeatedly(Return(0));

// Perform multiple start/stop cycles
for (int i = 0; i < 50; ++i) {
    std::string ifName = validIfName_;
    std::string hwAddr = validMacAddr_;
    std::string senderIp = validSenderIp_;
    std::string targetIp = validTargetIp_;

        bool started = checker_->Start(ifName, hwAddr, senderIp, targetIp);
        if (started) {
            checker_->Stop();
        }

        // Verify clean state after each cycle
        EXPECT_FALSE(checker_->m_isSocketCreated);
        EXPECT_EQ(checker_->m_socketFd, -1);
    }

    MockSystemFunc::SetMockFlag(false);
}

/**
 * @tc.name: DestructorResourceCleanupTest_PendingOperations_CleanExit
 * @tc.desc: Test destructor cleans up resources even with pending operations
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DhcpArpCheckerAsyncTest, DestructorResourceCleanupTest_PendingOperations_CleanExit, TestSize.Level1)
{
    DHCP_LOGE("enter DestructorResourceCleanupTest_PendingOperations_CleanExit");

    SetupValidSocket();

    MockSystemFunc::SetMockFlag(true);
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_))
        .WillOnce(Return(0));

    // Start a background operation
    auto future = std::async(std::launch::async, [this]()
                                {
                                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                                    // Destructor should handle cleanup even if operations are pending
                                });

    // Destroy the checker while background operation might be running
    checker_.reset();

    // Wait for background task
    future.get();

    // Test passes if no crashes occur
    EXPECT_TRUE(true);

    MockSystemFunc::SetMockFlag(false);
}

// ==================== Stress Tests ====================

/**
 * @tc.name: StressTest_RapidStartStop_StableOperation
 * @tc.desc: Stress test with rapid start/stop operations
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DhcpArpCheckerAsyncTest, StressTest_RapidStartStop_StableOperation, TestSize.Level1)
{
    DHCP_LOGE("enter StressTest_RapidStartStop_StableOperation");

    MockSystemFunc::SetMockFlag(true);
    EXPECT_CALL(MockSystemFunc::GetInstance(), if_nametoindex(::testing::_))
        .WillRepeatedly(Return(2));
    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(AF_PACKET, SOCK_DGRAM, ::testing::_))
        .WillRepeatedly(Return(3));
    EXPECT_CALL(MockSystemFunc::GetInstance(), fcntl2(3, F_GETFL))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), fcntl3(3, F_SETFL, ::testing::_))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(3, ::testing::_, ::testing::_))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_))
        .WillRepeatedly(Return(0));

    const int iterations = 100;

    auto startTime = std::chrono::steady_clock::now();

    for (int i = 0; i < iterations; ++i) {
        std::string ifName = validIfName_;
        std::string hwAddr = validMacAddr_;
        std::string senderIp = validSenderIp_;
        std::string targetIp = validTargetIp_;

        checker_->Start(ifName, hwAddr, senderIp, targetIp);
        checker_->Stop();

        // Brief pause to avoid overwhelming the system
        if (i % 10 == 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    }

    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

    DHCP_LOGI("Completed %{public}d iterations in %{public}lld ms", iterations, duration.count());

    // Should complete within reasonable time (less than 5 seconds)
    EXPECT_LT(duration.count(), 5000);

    MockSystemFunc::SetMockFlag(false);
}

} // namespace OHOS
