/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "dhcp_client_def.h"
#include "dhcp_function.h"
#include "securec.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpClientTest");

using namespace testing::ext;

namespace OHOS {
class DhcpClientTest : public testing::Test {
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

HWTEST_F(DhcpClientTest, GetProStatus_SUCCESS, TestSize.Level1)
{
    DHCP_LOGE("enter GetProStatus_SUCCESS");
    char workDir[DIR_MAX_LEN] = "./";
    char pidFile[DIR_MAX_LEN] = "./wlan0.pid";
    ASSERT_EQ(DHCP_OPT_SUCCESS, InitPidfile(workDir, pidFile, getpid()));

    unlink(pidFile);
}

HWTEST_F(DhcpClientTest, StopProcess_SUCCESS, TestSize.Level1)
{
    char pidFile[DIR_MAX_LEN] = "./wlan0.pid";

    char workDir[DIR_MAX_LEN] = "./";
    pid_t testPid = 12345;
    ASSERT_EQ(DHCP_OPT_SUCCESS, InitPidfile(workDir, pidFile, testPid));

    unlink(pidFile);
}
}  // namespace OHOS