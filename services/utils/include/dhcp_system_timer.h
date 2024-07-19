#ifndef OHOS_ARCH_LITE
#include "dhcp_system_timer.h"
#endif

m_leaseTime = ipCached.ipResult.uOptLeasetime;
    m_renewalSec = ipCached.ipResult.uOptLeasetime * RENEWAL_SEC_MULTIPLE;
    m_rebindSec = ipCached.ipResult.uOptLeasetime * REBIND_SEC_MULTIPLE;
    m_renewalTimestamp = ipCached.ipResult.uAddTime;
    DHCP_LOGI("TryCachedIp m_renewalTimestamp:%{public}u m_leaseTime:%{public}u %{public}u %{public}u",
        m_renewalTimestamp, m_leaseTime, m_renewalSec, m_rebindSec);
    ScheduleLeaseTimers();


void DhcpClientStateMachine::StartTimer(TimerType type, uint32_t &timerId, uint32_t interval, bool once)
{
    DHCP_LOGI("StartTimer timerId:%{public}u type:%{public}u interval:%{public}u once:%{public}d", timerId, type,
        interval, once);
    std::unique_lock<std::mutex> lock(getIpTimerMutex);
    std::function<void()> timeCallback = nullptr;
    if (timerId != 0) {
        DHCP_LOGE("StartTimer timerId !=0 id:%{public}u", timerId);
        return;
    }
    switch (type) {
        case TIMER_GET_IP:
            timeCallback = std::bind(&DhcpClientStateMachine::GetIpTimerCallback, this);
            break;
        case TIMER_RENEW_DELAY:
            timeCallback = std::bind(&DhcpClientStateMachine::RenewDelayCallback, this);
            break;
        case TIMER_REBIND_DELAY:
            timeCallback = std::bind(&DhcpClientStateMachine::RebindDelayCallback, this);
            break;
        case TIMER_REMAINING_DELAY:
            timeCallback = std::bind(&DhcpClientStateMachine::RemainingDelayCallback, this);
            break;
        default:
            DHCP_LOGE("StartTimer default timerId:%{public}u", timerId);
            break;
    }
    if (timeCallback != nullptr && (timerId == 0)) {
        std::shared_ptr<OHOS::Wifi::DhcpSysTimer> dhcpSysTimer =
            std::make_shared<OHOS::Wifi::DhcpSysTimer>(false, 0, false, false);
        dhcpSysTimer->SetCallbackInfo(timeCallback);
        timerId = MiscServices::TimeServiceClient::GetInstance()->CreateTimer(dhcpSysTimer);
        int64_t currentTime = MiscServices::TimeServiceClient::GetInstance()->GetBootTimeMs();
        MiscServices::TimeServiceClient::GetInstance()->StartTimer(timerId, currentTime + interval);
        DHCP_LOGI("duliqun 0718 StartTimer timerId:%{public}u [%{public}u %{public}u %{public}u %{public}u]", timerId, getIpTimerId,
            renewDelayTimerId, rebindDelayTimerId, remainingDelayTimerId);
    }
}

void DhcpClientStateMachine::StopTimer(uint32_t &timerId)
{
    uint32_t stopTimerId = timerId;
    if (timerId == 0) {
        DHCP_LOGE("StopTimer timerId is 0, no unregister timer");
        return;
    }
    std::unique_lock<std::mutex> lock(getIpTimerMutex);
    MiscServices::TimeServiceClient::GetInstance()->StopTimer(timerId);
    MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    timerId = 0;
    DHCP_LOGI("duliqun 0718 StopTimer stopTimerId:%{public}u [%{public}u %{public}u %{public}u %{public}u]", stopTimerId,
        getIpTimerId, renewDelayTimerId, rebindDelayTimerId, remainingDelayTimerId);
}


/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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
#ifndef DHCP_SYSTEM_TIMER_H
#define DHCP_SYSTEM_TIMER_H

#ifndef OHOS_ARCH_LITE
#include <cstdint>
#include <functional>
#include <string>
#include <sys/time.h>
#include <vector>
#include "time_service_client.h"
#include "itimer_info.h"
#include "timer.h"

namespace OHOS {
namespace Wifi {
class DhcpSysTimer : public MiscServices::ITimerInfo {
public:
    DhcpSysTimer();
    DhcpSysTimer(bool repeat, uint64_t interval, bool isNoWakeUp, bool isIdle = false);
    virtual ~DhcpSysTimer();
    void OnTrigger() override;
    void SetType(const int &type) override;
    void SetRepeat(bool repeat) override;
    void SetInterval(const uint64_t &interval) override;
    void SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> _wantAgent) override;
    void SetCallbackInfo(const std::function<void()> &callBack);
private:
    std::function<void()> callBack_ = nullptr;
};
} // namespace Wifi
} // namespace OHOS
#endif
#endif