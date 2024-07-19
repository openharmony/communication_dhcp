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
#include "dhcp_system_timer.h"
#include "dhcp_logger.h"
#include "common_timer_errors.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpSystemTimerTest");
using namespace testing::ext;
using namespace OHOS::DHCP;

namespace OHOS {
constexpr uint64_t SLEEP_TIME = 2;
constexpr int TIMER_TYPE = 1;
class DhcpSystemTimerTest : public testing::Test {
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

void SystemTimerTimeOut() 
{
    DHCP_LOGI("SystemTimerTimeOut enter!");
}

HWTEST_F(DhcpSystemTimerTest, SystemTimer1Test, TestSize.Level1)
{
    DHCP_LOGI("SystemTimer1Test enter!");
    DhcpSysTimer dhcpSysTimer;
    dhcpSysTimer.OnTrigger();
    dhcpSysTimer.SetRepeat(false);
    dhcpSysTimer.SetInterval(SLEEP_TIME);
}

HWTEST_F(DhcpSystemTimerTest, SystemTimer2Test, TestSize.Level1)
{
    DHCP_LOGI("SystemTimer2Test enter!");
    DhcpSysTimer dhcpSysTimer(false, 0, false, false);
    dhcpSysTimer.SetCallbackInfo(SystemTimerTimeOut);
    dhcpSysTimer.OnTrigger();
    dhcpSysTimer.SetType(TIMER_TYPE);
    dhcpSysTimer.SetRepeat(false);
    dhcpSysTimer.SetInterval(SLEEP_TIME);
}
}