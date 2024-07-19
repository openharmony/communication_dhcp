/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
#ifndef OHOS_ARCH_LITE
#include "dhcp_system_timer.h"
#include "dhcp_logger.h"
#include "common_timer_errors.h"

namespace OHOS {
namespace DHCP {
DEFINE_DHCPLOG_DHCP_LABEL("DhcpSystemTimer");
DhcpSysTimer::DhcpSysTimer()
{
    DHCP_LOGI("DhcpSysTimer");
}

DhcpSysTimer::~DhcpSysTimer()
{
    DHCP_LOGI("~DhcpSysTime");
}

DhcpSysTimer::DhcpSysTimer(bool repeat, uint64_t interval, bool isNoWakeUp, bool isIdle)
{
    this->repeat = repeat;
    this->interval = interval;
    this->type = TIMER_TYPE_REALTIME;
    if (!isNoWakeUp) {
        this->type = TIMER_TYPE_WAKEUP + TIMER_TYPE_REALTIME;
    }
    if (isIdle) {
        this->type = TIMER_TYPE_IDLE;
    }
}

void DhcpSysTimer::OnTrigger()
{
    if (callBack_ != nullptr) {
        callBack_();
    }
}

void DhcpSysTimer::SetCallbackInfo(const std::function<void()> &callBack)
{
    this->callBack_ = callBack;
}

void DhcpSysTimer::SetType(const int &type)
{
    this->type = type;
}

void DhcpSysTimer::SetRepeat(bool repeat)
{
    this->repeat = repeat;
}

void DhcpSysTimer::SetInterval(const uint64_t &interval)
{
    this->interval = interval;
}

void DhcpSysTimer::SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent)
{
    this->wantAgent = wantAgent;
}
} // namespace Wifi
} // namespace DHCP
#endif