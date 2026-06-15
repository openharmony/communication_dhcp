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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DHCP_V6_STATEMACHINE_H
#define DHCP_V6_STATEMACHINE_H

#include "state_machine.h"
#include "state.h"
#include "internal_message.h"
#include "dhcp_v6_message.h"
#include "dhcp_v6_result.h"
#include "dhcp_v6_constants.h"
#include <cstdint>
#include <vector>
#include <string>
#include <functional>

namespace OHOS {
namespace DHCP {

using OHOS::Wifi::InternalMessagePtr;
using OHOS::Wifi::State;
using OHOS::Wifi::StateMachine;
using OHOS::Wifi::EXECUTED;
using OHOS::Wifi::NOT_EXECUTED;

class DhcpV6Socket;

// Message IDs for state machine
constexpr int CMD_START = 0x01;           // Start DHCPv6 client
constexpr int CMD_STOP = 0x02;             // Stop DHCPv6 client
constexpr int CMD_MESSAGE_RECEIVED = 0x03; // DHCPv6 message received from server
constexpr int CMD_TIMEOUT = 0x04;          // Retry timeout
constexpr int CMD_ERROR = 0x05;            // Socket or protocol error
constexpr int CMD_DAD_CONFLICT = 0x06;     // Duplicate Address Detection conflict
constexpr int CMD_T2_TIMEOUT = 0x07;       // T2 deadline reached in RENEW state
constexpr int CMD_EXPIRE_TIMEOUT = 0x08;   // Lease expired in REBIND state


class DhcpV6StateMachine : public OHOS::Wifi::StateMachine {
public:
    DhcpV6StateMachine();
    ~DhcpV6StateMachine() override;

    bool InitDhcpV6StateMachine();
    void SetSocket(DhcpV6Socket* socket);
    void SetConfig(const DhcpV6Config& config);
    void SetResultCallback(std::function<void(const DhcpV6Result&)> successCallback,
                           std::function<void(int)> failureCallback);
    void SetExpiredCallback(std::function<void()> expiredCallback);
    void SetIfaceName(const std::string& iface);

    void OnKernelDadConflict(const std::string& addr);
    bool IsDhcpV6ConfiguredAddress(const std::string& addr) const;
    void SetStopping(bool stopping);
    bool IsStopping() const;

    DhcpV6Socket* GetSocket() const
    {
        return socket_;
    }

    const std::string& GetIface() const
    {
        return iface_;
    }

    const DhcpV6Config& GetConfig() const
    {
        return config_;
    }

    DhcpV6Config& GetConfig()
    {
        return config_;
    }

    DhcpV6Result& GetResult()
    {
        return result_;
    }

    const DhcpV6Result& GetResult() const
    {
        return result_;
    }

    void SetResult(const DhcpV6Result& res)
    {
        result_ = res;
    }

    DhcpV6Advertise& GetCurrentAdvertise()
    {
        return currentAdvertise_;
    }

    void SetCurrentAdvertise(const DhcpV6Advertise& adv)
    {
        currentAdvertise_ = adv;
    }

    uint32_t GetTransactionId() const
    {
        return transactionId_;
    }

    void SetTransactionId(uint32_t id)
    {
        transactionId_ = id;
    }

    void IncrementRetryCount()
    {
        retryCount_++;
    }

    int GetRetryCount() const
    {
        return retryCount_;
    }

    void ResetRetryCount()
    {
        retryCount_ = 0;
    }

    int GetMaxRetries() const
    {
        return maxRetries_;
    }

    uint32_t GetCurrentTimeout() const
    {
        return currentTimeout_;
    }

    void SetCurrentTimeout(uint32_t timeout)
    {
        currentTimeout_ = timeout;
    }

    const std::function<void(const DhcpV6Result&)>& GetSuccessCallback() const
    {
        return successCallback_;
    }

    const std::function<void(int)>& GetFailureCallback() const
    {
        return failureCallback_;
    }

    const std::function<void()>& GetExpiredCallback() const
    {
        return expiredCallback_;
    }

    void OnSuccess();
    void OnFailure(int errorCode);
    void OnLeaseExpired();

    void ProcessResultInfo(const DhcpV6Advertise& advertise);

    // Deadline management
    uint64_t GetT2DeadlineMs() const
    {
        return t2DeadlineMs_;
    }

    void SetT2DeadlineMs(uint64_t deadline)
    {
        t2DeadlineMs_ = deadline;
    }

    void ClearT2Deadline()
    {
        t2DeadlineMs_ = 0;
    }

    uint64_t GetExpireDeadlineMs() const
    {
        return expireDeadlineMs_;
    }

    void SetExpireDeadlineMs(uint64_t deadline)
    {
        expireDeadlineMs_ = deadline;
    }

    void ClearExpireDeadline()
    {
        expireDeadlineMs_ = 0;
    }

    uint64_t GetCurrentTimeMs() const;

    // Process timeout with retry for InfoRequest/Advertise/Request states
    // Returns true if message was sent and timer set, false if max retries exceeded
    bool ProcessTimeoutWithRetry(const char* stateName, const std::vector<uint8_t>& message);
    // renew: true = RENEW, false = REBIND
    void ProcessRenewOrRebind(bool renew);

private:
    // 构建并发送 RENEW/REBIND 消息
    void SendRenewOrRebindMsg(bool renew);

private:
    friend class DhcpV6InitState;
    friend class DhcpV6InfoRequestState;
    friend class DhcpV6SolicitState;
    friend class DhcpV6AdvertiseState;
    friend class DhcpV6RequestState;
    friend class DhcpV6BoundState;
    friend class DhcpV6RenewState;
    friend class DhcpV6RebindState;
    friend class DhcpV6ReleaseState;
    friend class DhcpV6FailState;

    // State instances
    State* pInitState_ = nullptr;
    State* pInfoRequestState_ = nullptr;
    State* pSolicitState_ = nullptr;
    State* pAdvertiseState_ = nullptr;
    State* pRequestState_ = nullptr;
    State* pBoundState_ = nullptr;
    State* pRenewState_ = nullptr;
    State* pRebindState_ = nullptr;
    State* pReleaseState_ = nullptr;
    State* pFailState_ = nullptr;

    DhcpV6Socket* socket_ = nullptr;
    std::string iface_;
    DhcpV6Config config_;
    DhcpV6Result result_;
    DhcpV6Advertise currentAdvertise_;
    uint32_t transactionId_ = 0;
    int retryCount_ = 0;
    int maxRetries_ = DEFAULT_MAX_RETRIES;
    uint32_t currentTimeout_ = BASE_TIMEOUT_MS;
    bool isStopping_ = false;

    // Deadline tracking (absolute timestamps in milliseconds since epoch)
    uint64_t t2DeadlineMs_ = 0;       // T2 deadline for RENEW state
    uint64_t expireDeadlineMs_ = 0;    // Lease expire deadline for REBIND state

    std::function<void(const DhcpV6Result&)> successCallback_;
    std::function<void(int)> failureCallback_;
    std::function<void()> expiredCallback_;

    void InitDhcpV6States();
    void BuildStateTree();
};

// Base state class
class DhcpV6State : public OHOS::Wifi::State {
public:
    explicit DhcpV6State(const std::string& name, DhcpV6StateMachine& stateMachine)
        : OHOS::Wifi::State(name), stateMachine_(stateMachine) {}
    virtual ~DhcpV6State() = default;

protected:
    DhcpV6StateMachine& stateMachine_;
};

// DhcpV6InitState - Initial/Idle state
class DhcpV6InitState : public DhcpV6State {
public:
    explicit DhcpV6InitState(DhcpV6StateMachine& stateMachine)
        : DhcpV6State("DhcpV6InitState", stateMachine) {}
    virtual ~DhcpV6InitState() = default;

    void GoInState() override;
    void GoOutState() override;
    bool ExecuteStateMsg(InternalMessagePtr msg) override;

private:
    bool ProcessStart(InternalMessagePtr msg);
};

// DhcpV6InfoRequestState - Stateless information request
class DhcpV6InfoRequestState : public DhcpV6State {
public:
    explicit DhcpV6InfoRequestState(DhcpV6StateMachine& stateMachine)
        : DhcpV6State("DhcpV6InfoRequestState", stateMachine) {}
    virtual ~DhcpV6InfoRequestState() = default;

    void GoInState() override;
    void GoOutState() override;
    bool ExecuteStateMsg(InternalMessagePtr msg) override;

private:
    bool ProcessMessageReceived(InternalMessagePtr msg);
    bool ProcessTimeout(InternalMessagePtr msg);
    bool ProcessStop(InternalMessagePtr msg);
};

// DhcpV6SolicitState - Request advertisements (stateful mode)
class DhcpV6SolicitState : public DhcpV6State {
public:
    explicit DhcpV6SolicitState(DhcpV6StateMachine& stateMachine)
        : DhcpV6State("DhcpV6SolicitState", stateMachine) {}
    virtual ~DhcpV6SolicitState() = default;

    void GoInState() override;
    void GoOutState() override;
    bool ExecuteStateMsg(InternalMessagePtr msg) override;

private:
    bool ProcessStop(InternalMessagePtr msg);
};

// DhcpV6AdvertiseState - Wait for advertise messages
class DhcpV6AdvertiseState : public DhcpV6State {
public:
    explicit DhcpV6AdvertiseState(DhcpV6StateMachine& stateMachine)
        : DhcpV6State("DhcpV6AdvertiseState", stateMachine) {}
    virtual ~DhcpV6AdvertiseState() = default;

    void GoInState() override;
    void GoOutState() override;
    bool ExecuteStateMsg(InternalMessagePtr msg) override;

private:
    bool ProcessMessageReceived(InternalMessagePtr msg);
    bool ProcessTimeout(InternalMessagePtr msg);
    bool ProcessStop(InternalMessagePtr msg);
};

// DhcpV6RequestState - Request address from server
class DhcpV6RequestState : public DhcpV6State {
public:
    explicit DhcpV6RequestState(DhcpV6StateMachine& stateMachine)
        : DhcpV6State("DhcpV6RequestState", stateMachine) {}
    virtual ~DhcpV6RequestState() = default;

    void GoInState() override;
    void GoOutState() override;
    bool ExecuteStateMsg(InternalMessagePtr msg) override;

private:
    bool ProcessMessageReceived(InternalMessagePtr msg);
    bool ProcessTimeout(InternalMessagePtr msg);
    bool ProcessStop(InternalMessagePtr msg);
};

// DhcpV6BoundState - Has obtained address, kernel performs DAD automatically
class DhcpV6BoundState : public DhcpV6State {
public:
    explicit DhcpV6BoundState(DhcpV6StateMachine& stateMachine)
        : DhcpV6State("DhcpV6BoundState", stateMachine) {}
    virtual ~DhcpV6BoundState() = default;

    void GoInState() override;
    void GoOutState() override;
    bool ExecuteStateMsg(InternalMessagePtr msg) override;

private:
    bool ProcessTimeout(InternalMessagePtr msg);
    bool ProcessStop(InternalMessagePtr msg);
    bool ProcessDadConflict(InternalMessagePtr msg);
};

// DhcpV6RenewState - Renewal state
class DhcpV6RenewState : public DhcpV6State {
public:
    explicit DhcpV6RenewState(DhcpV6StateMachine& stateMachine)
        : DhcpV6State("DhcpV6RenewState", stateMachine) {}
    virtual ~DhcpV6RenewState() = default;

    void GoInState() override;
    void GoOutState() override;
    bool ExecuteStateMsg(InternalMessagePtr msg) override;

private:
    bool ProcessMessageReceived(InternalMessagePtr msg);
    bool ProcessTimeout(InternalMessagePtr msg);
    bool ProcessStop(InternalMessagePtr msg);
};

// DhcpV6RebindState - Rebind state
class DhcpV6RebindState : public DhcpV6State {
public:
    explicit DhcpV6RebindState(DhcpV6StateMachine& stateMachine)
        : DhcpV6State("DhcpV6RebindState", stateMachine) {}
    virtual ~DhcpV6RebindState() = default;

    void GoInState() override;
    void GoOutState() override;
    bool ExecuteStateMsg(InternalMessagePtr msg) override;

private:
    bool ProcessMessageReceived(InternalMessagePtr msg);
    bool ProcessTimeout(InternalMessagePtr msg);
    bool ProcessStop(InternalMessagePtr msg);
};

// DhcpV6ReleaseState - Release addresses
class DhcpV6ReleaseState : public DhcpV6State {
public:
    explicit DhcpV6ReleaseState(DhcpV6StateMachine& stateMachine)
        : DhcpV6State("DhcpV6ReleaseState", stateMachine) {}
    virtual ~DhcpV6ReleaseState() = default;

    void GoInState() override;
    void GoOutState() override;
    bool ExecuteStateMsg(InternalMessagePtr msg) override;
};

// DhcpV6FailState - Failure state
class DhcpV6FailState : public DhcpV6State {
public:
    explicit DhcpV6FailState(DhcpV6StateMachine& stateMachine)
        : DhcpV6State("DhcpV6FailState", stateMachine) {}
    virtual ~DhcpV6FailState() = default;

    void GoInState() override;
    void GoOutState() override;
    bool ExecuteStateMsg(InternalMessagePtr msg) override;
};

} // namespace DHCP
} // namespace OHOS

#endif // DHCP_V6_STATEMACHINE_H
