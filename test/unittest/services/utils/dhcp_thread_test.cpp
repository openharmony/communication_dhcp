/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include <chrono>
#include <thread>
#include "dhcp_logger.h"
#include "dhcp_socket.h"
#include "dhcp_function.h"
#include "dhcp_thread.h"
#include "securec.h"
#include "mock_system_func.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpThreadTest");

using namespace testing::ext;
using namespace OHOS::DHCP;
namespace OHOS {
class DhcpThreadTest : public testing::Test {
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

HWTEST_F(DhcpThreadTest, PostSyncTask_SUCCESS, TestSize.Level1)
{
    DHCP_LOGE("enter PostSyncTask_SUCCESS");
    DhcpThread dhcpThread("TestThread");
    bool result = dhcpThread.PostSyncTask([]() {
        // Task implementation
    });

    EXPECT_TRUE(result);
}

HWTEST_F(DhcpThreadTest, PostAsyncTask_SUCCESS, TestSize.Level1)
{
    DHCP_LOGE("enter PostAsyncTask_SUCCESS");
    DhcpThread dhcpThread("TestThread");
    bool result = dhcpThread.PostAsyncTask([]() {
        // Task implementation
    });

    EXPECT_TRUE(result);
}

HWTEST_F(DhcpThreadTest, PostAsyncTaskWithName_SUCCESS, TestSize.Level1)
{
    DHCP_LOGE("enter PostAsyncTaskWithName_SUCCESS");
    DhcpThread dhcpThread("TestThread");
    bool result = dhcpThread.PostAsyncTask([]() {
        // Task implementation
    }, "TaskName");

    EXPECT_TRUE(result);
}

HWTEST_F(DhcpThreadTest, PostSyncTimeOutTask_001, TestSize.Level1)
{
    DHCP_LOGE("enter PostSyncTimeOutTask_001");
    DhcpThread dhcpThread("TestThread");
    int timeOut = 500;
    bool result = dhcpThread.PostSyncTimeOutTask([]() -> int32_t {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        return 0;
    }, timeOut);
 
    EXPECT_TRUE(result);
}
 
HWTEST_F(DhcpThreadTest, PostSyncTimeOutTask_002, TestSize.Level1)
{
    DHCP_LOGE("enter PostSyncTimeOutTask_002");
    DhcpThread dhcpThread("TestThread");
    int timeOut = 500;
    bool result = dhcpThread.PostSyncTimeOutTask([]() -> int32_t {
        std::this_thread::sleep_for(std::chrono::milliseconds(600));
        return 0;
    }, timeOut);
 
    EXPECT_FALSE(result);
}

HWTEST_F(DhcpThreadTest, RemoveAsyncTask_SUCCESS, TestSize.Level1)
{
    DHCP_LOGE("enter RemoveAsyncTask_SUCCESS");
    DhcpThread dhcpThread("TestThread");
    bool result = dhcpThread.PostAsyncTask([]() {
        // Task implementation
    }, "TaskName");
    EXPECT_TRUE(result);
    dhcpThread.RemoveAsyncTask("TaskName");
}

HWTEST_F(DhcpThreadTest, Register_SUCCESS, TestSize.Level1)
{
    DHCP_LOGE("enter Register_SUCCESS");
    DhcpTimer *dhcpTimer = DhcpTimer::GetInstance();
    uint32_t timerId;
    EnumErrCode result = dhcpTimer->Register([]() {
        // Timer callback implementation
    }, timerId);

    EXPECT_EQ(result, EnumErrCode::DHCP_OPT_FAILED);
}

HWTEST_F(DhcpThreadTest, UnRegister_SUCCESS, TestSize.Level1)
{
    DHCP_LOGE("enter UnRegister_SUCCESS");
    DhcpTimer *dhcpTimer = DhcpTimer::GetInstance();
    uint32_t timerId;
    EnumErrCode result = dhcpTimer->Register([]() {
        // Timer callback implementation
    }, timerId);
    EXPECT_EQ(result, EnumErrCode::DHCP_OPT_FAILED);
    dhcpTimer->UnRegister(timerId);
}

HWTEST_F(DhcpThreadTest, GetInstance_SUCCESS, TestSize.Level1)
{
    DhcpTimer *dhcpTimer = DhcpTimer::GetInstance();
    EXPECT_NE(dhcpTimer, nullptr);
}

HWTEST_F(DhcpThreadTest, RegisterWithInterval_SUCCESS, TestSize.Level1)
{
    DhcpTimer *dhcpTimer = DhcpTimer::GetInstance();
    uint32_t timerId;
    EnumErrCode result = dhcpTimer->Register([]() {
    }, timerId, 5000);

    EXPECT_EQ(result, EnumErrCode::DHCP_OPT_FAILED);
}
}