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
using namespace OHOS::Wifi;

namespace OHOS {
constexpr uint64_t SLEEP_TIME = 2;
class SystemTimerTest : public testing::Test {
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
    DHCP_LOGI("SystemTimerStart SystemTimerTimeOut enter!");
}

HWTEST_F(DhcpCommonUtilsTest, SystemTimerTest, TestSize.Level1)
{
    uint32_t timerId = 0;
    DhcpSysTimer dhcpSysTimer;
    dhcpSysTimer.OnTrigger();
    
    DhcpSysTimer dhcpSysTimer2(false, 0, false, false);
    dhcpSysTimer2->SetCallbackInfo(SystemTimerTimeOut);
    dhcpSysTimer2.OnTrigger();
    dhcpSysTimer2.SetType(TIMER_TYPE_REALTIME);
    dhcpSysTimer2.SetRepeat(false);
    dhcpSysTimer2.SetInterval(SLEEP_TIME);
    std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent =
        std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgen>();
    dhcpSysTimer2.SetWantAgent(wantAgent);
}
}