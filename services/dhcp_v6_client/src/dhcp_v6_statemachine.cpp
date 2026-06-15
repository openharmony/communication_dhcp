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

#include "dhcp_v6_statemachine.h"
#include "dhcp_v6_socket.h"
#include "dhcp_v6_message.h"
#include "dhcp_v6_constants.h"
#include "dhcp_logger.h"
#include "dhcp_common_utils.h"
#include <chrono>
#include <cinttypes>

DEFINE_DHCPLOG_DHCP_LABEL("DhcpV6StateMachine");

namespace OHOS {
namespace DHCP {

using OHOS::Wifi::State;
using OHOS::Wifi::StateMachine;
using OHOS::Wifi::InternalMessagePtr;

DhcpV6StateMachine::DhcpV6StateMachine()
    : StateMachine("DhcpV6StateMachine"), socket_(nullptr), transactionId_(0),
      retryCount_(0), maxRetries_(DEFAULT_MAX_RETRIES), currentTimeout_(BASE_TIMEOUT_MS), isStopping_(false)
{
}

DhcpV6StateMachine::~DhcpV6StateMachine()
{
    StopHandlerThread();
}

bool DhcpV6StateMachine::InitDhcpV6StateMachine()
{
    if (!InitialStateMachine("DhcpV6StateMachine")) {
        DHCP_LOGE("[DHCPv6] DhcpV6StateMachine::InitDhcpV6StateMachine failed");
        return false;
    }

    InitDhcpV6States();
    BuildStateTree();
    SetFirstState(pInitState_);
    StartStateMachine();

    DHCP_LOGI("[DHCPv6] DhcpV6StateMachine initialized successfully");
    return true;
}

void DhcpV6StateMachine::InitDhcpV6States()
{
    pInitState_ = new DhcpV6InitState(*this);
    pInfoRequestState_ = new DhcpV6InfoRequestState(*this);
    pSolicitState_ = new DhcpV6SolicitState(*this);
    pAdvertiseState_ = new DhcpV6AdvertiseState(*this);
    pRequestState_ = new DhcpV6RequestState(*this);
    pBoundState_ = new DhcpV6BoundState(*this);
    pRenewState_ = new DhcpV6RenewState(*this);
    pRebindState_ = new DhcpV6RebindState(*this);
    pReleaseState_ = new DhcpV6ReleaseState(*this);
    pFailState_ = new DhcpV6FailState(*this);
}

void DhcpV6StateMachine::BuildStateTree()
{
    // Build hierarchical state tree
    StatePlus(pInitState_, nullptr);
    StatePlus(pInfoRequestState_, pInitState_);
    StatePlus(pSolicitState_, pInitState_);
    StatePlus(pAdvertiseState_, pSolicitState_);
    StatePlus(pRequestState_, pInitState_);
    StatePlus(pBoundState_, pInitState_);
    StatePlus(pRenewState_, pBoundState_);
    StatePlus(pRebindState_, pBoundState_);
    StatePlus(pReleaseState_, pInitState_);
    StatePlus(pFailState_, pInitState_);
}

void DhcpV6StateMachine::SetSocket(DhcpV6Socket* socket)
{
    socket_ = socket;
}

void DhcpV6StateMachine::SetConfig(const DhcpV6Config& config)
{
    config_ = config;
    transactionId_ = DhcpV6Message::GenerateTransactionId();
}

void DhcpV6StateMachine::SetResultCallback(
    std::function<void(const DhcpV6Result&)> successCallback,
    std::function<void(int)> failureCallback)
{
    successCallback_ = successCallback;
    failureCallback_ = failureCallback;
}

void DhcpV6StateMachine::SetExpiredCallback(std::function<void()> expiredCallback)
{
    expiredCallback_ = expiredCallback;
}

void DhcpV6StateMachine::SetIfaceName(const std::string& iface)
{
    iface_ = iface;
}

void DhcpV6StateMachine::SetStopping(bool stopping)
{
    isStopping_ = stopping;
}

bool DhcpV6StateMachine::IsStopping() const
{
    return isStopping_;
}

void DhcpV6StateMachine::OnKernelDadConflict(const std::string& addr)
{
    DHCP_LOGW("[DHCPv6] OnKernelDadConflict: %{public}s DAD FAILED", Ipv6Anonymize(addr).c_str());

    if (!IsDhcpV6ConfiguredAddress(addr)) {
        DHCP_LOGI("[DHCPv6] OnKernelDadConflict: %{public}s not configured by DHCPv6, ignoring",
            Ipv6Anonymize(addr).c_str());
        return;
    }

    auto msg = CreateMessage(CMD_DAD_CONFLICT);
    if (msg) {
        msg->SetMessageObj(addr);
        SendMessage(msg);
    }
}

bool DhcpV6StateMachine::IsDhcpV6ConfiguredAddress(const std::string& addr) const
{
    for (const auto& configuredAddr : result_.ipv6Addresses) {
        if (configuredAddr == addr) {
            return true;
        }
    }
    return false;
}

void DhcpV6StateMachine::OnSuccess()
{
    DHCP_LOGI("[DHCPv6] DhcpV6StateMachine::OnSuccess");
    if (successCallback_) {
        successCallback_(result_);
    }
}

void DhcpV6StateMachine::OnFailure(int errorCode)
{
    DHCP_LOGI("[DHCPv6] DhcpV6StateMachine::OnFailure error:%{public}d", errorCode);
    if (failureCallback_) {
        failureCallback_(errorCode);
    }
}

void DhcpV6StateMachine::OnLeaseExpired()
{
    DHCP_LOGI("[DHCPv6] DhcpV6StateMachine::OnLeaseExpired");
    if (expiredCallback_) {
        expiredCallback_();
    }
}

void DhcpV6StateMachine::ProcessResultInfo(const DhcpV6Advertise& advertise)
{
    result_.ipv6Addresses = advertise.ipv6Addresses;
    result_.dnsServers = advertise.dnsServers;
    result_.preferredLifetime = advertise.preferredLifetime;
    result_.validLifetime = advertise.validLifetime;
    result_.t1 = advertise.t1;
    result_.t2 = advertise.t2;

    bool isInfinite = (result_.validLifetime == INFINITE_LIFETIME);
    if (result_.validLifetime != 0 && !isInfinite) {
        if (result_.t1 == 0) {
            result_.t1 = result_.validLifetime / T1_DIVISOR;
        }
        if (result_.t2 == 0) {
            result_.t2 = static_cast<uint32_t>((result_.validLifetime * T2_LIFETIME_RATIO) / LIFETIME_RATIO_BASE);
        }
    }

    config_.serverId = advertise.serverId;
}

uint64_t DhcpV6StateMachine::GetCurrentTimeMs() const
{
    auto now = std::chrono::system_clock::now();
    auto epoch = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
}

bool DhcpV6StateMachine::ProcessTimeoutWithRetry(const char* stateName, const std::vector<uint8_t>& message)
{
    DHCP_LOGI("[DHCPv6] %{public}s::ProcessTimeout retry=%{public}d/%{public}d",
        stateName, retryCount_, maxRetries_);
    if (retryCount_ > maxRetries_) {
        DHCP_LOGI("[DHCPv6] %{public}s: max retries exceeded", stateName);
        OnFailure(ERR_RETRY_EXCEEDED);
        SwitchState(pFailState_);
        return false;
    }

    auto socket = GetSocket();
    if (socket) {
        socket->DhcpV6Send(message);
    }

    int64_t timeout = BASE_TIMEOUT_MS + (retryCount_ * TIMEOUT_INCREMENT_MS);
    SetCurrentTimeout(static_cast<uint32_t>(timeout));
    IncrementRetryCount();
    MessageExecutedLater(CMD_TIMEOUT, timeout);
    return true;
}

void DhcpV6StateMachine::ProcessRenewOrRebind(bool renew)
{
    auto socket = GetSocket();
    if (!socket) {
        return;
    }

    uint64_t nowMs = GetCurrentTimeMs();
    uint64_t deadline = renew ? GetT2DeadlineMs() : GetExpireDeadlineMs();
    int deadlineCmd = renew ? CMD_T2_TIMEOUT : CMD_EXPIRE_TIMEOUT;

    // 检查 deadline
    if (deadline > 0 && nowMs >= deadline) {
        if (renew) {
            DHCP_LOGI("[DHCPv6] RENEW: T2 deadline passed, transition to REBIND");
            ClearT2Deadline();
            SwitchState(pRebindState_);
        } else {
            DHCP_LOGI("[DHCPv6] REBIND: EXPIRE deadline reached");
            OnFailure(ERR_LEASE_EXPIRED);
            OnLeaseExpired();
            ClearExpireDeadline();
            SwitchState(pInitState_);
        }
        return;
    }

    SendRenewOrRebindMsg(renew);

    // 设置定时器
    ResetRetryCount();
    int64_t timeout = BASE_TIMEOUT_MS + (GetRetryCount() * TIMEOUT_INCREMENT_MS);
    if (deadline > 0) {
        uint64_t remainingMs = (deadline > nowMs) ? (deadline - nowMs) : 0;
        if (remainingMs > 0 && remainingMs < static_cast<uint64_t>(timeout)) {
            SetCurrentTimeout(static_cast<uint32_t>(remainingMs));
            MessageExecutedLater(deadlineCmd, remainingMs);
            return;
        }
    }
    SetCurrentTimeout(static_cast<uint32_t>(timeout));
    IncrementRetryCount();
    MessageExecutedLater(CMD_TIMEOUT, timeout);
}

void DhcpV6StateMachine::SendRenewOrRebindMsg(bool renew)
{
    auto socket = GetSocket();
    if (!socket) {
        return;
    }

    DhcpV6Config config = GetConfig();
    config.transactionId = DhcpV6Message::GenerateTransactionId();
    SetTransactionId(config.transactionId);
    config.serverId = renew ? GetConfig().serverId : std::string();
    config.ipv6Addresses = GetResult().ipv6Addresses;
    config.preferredLifetime = GetResult().preferredLifetime;
    config.validLifetime = GetResult().validLifetime;

    auto message = renew ? DhcpV6Message::BuildRenewMessage(config)
                        : DhcpV6Message::BuildRebindMessage(config);
    socket->DhcpV6Send(message);
    DHCP_LOGI("[DHCPv6] Sent %{public}s message", renew ? "RENEW" : "REBIND");
}

//=============================================================================
// DhcpV6InitState Implementation
//=============================================================================
void DhcpV6InitState::GoInState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6InitState::GoInState");
    stateMachine_.ResetRetryCount();
    stateMachine_.SetCurrentAdvertise({});
    stateMachine_.SetResult({});
    stateMachine_.SetStopping(false);
}

void DhcpV6InitState::GoOutState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6InitState::GoOutState");
}

bool DhcpV6InitState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return NOT_EXECUTED;
    }

    int msgName = msg->GetMessageName();
    if (msgName == CMD_START) {
        return ProcessStart(msg);
    }
    return NOT_EXECUTED;
}

bool DhcpV6InitState::ProcessStart(InternalMessagePtr msg)
{
    DHCP_LOGI("[DHCPv6] DhcpV6InitState::ProcessStart");

    const auto& config = stateMachine_.GetConfig();
    if (config.stateless) {
        stateMachine_.SwitchState(stateMachine_.pInfoRequestState_);
    } else {
        stateMachine_.SwitchState(stateMachine_.pSolicitState_);
    }
    return EXECUTED;
}

//=============================================================================
// DhcpV6InfoRequestState Implementation
//=============================================================================
void DhcpV6InfoRequestState::GoInState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6InfoRequestState::GoInState");
    auto socket = stateMachine_.GetSocket();
    if (!socket) {
        return;
    }

    DhcpV6Config config = stateMachine_.GetConfig();
    config.transactionId = stateMachine_.GetTransactionId();
    auto message = DhcpV6Message::BuildInformationRequestMessage(config);
    socket->DhcpV6Send(message);
    DHCP_LOGI("[DHCPv6] Sent INFORMATION-REQUEST message");

    // Start reply timer
    int64_t timeout = BASE_TIMEOUT_MS + (stateMachine_.GetRetryCount() * TIMEOUT_INCREMENT_MS);
    stateMachine_.SetCurrentTimeout(static_cast<uint32_t>(timeout));
    stateMachine_.IncrementRetryCount();
    stateMachine_.MessageExecutedLater(CMD_TIMEOUT, timeout);
}

void DhcpV6InfoRequestState::GoOutState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6InfoRequestState::GoOutState");
    stateMachine_.StopTimer(static_cast<int>(CMD_TIMEOUT));
}

bool DhcpV6InfoRequestState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return NOT_EXECUTED;
    }

    int msgName = msg->GetMessageName();
    switch (msgName) {
        case CMD_MESSAGE_RECEIVED:
            return ProcessMessageReceived(msg);
        case CMD_TIMEOUT:
            return ProcessTimeout(msg);
        case CMD_STOP:
            return ProcessStop(msg);
        default:
            return NOT_EXECUTED;
    }
}

bool DhcpV6InfoRequestState::ProcessMessageReceived(InternalMessagePtr msg)
{
    std::vector<uint8_t> data;
    msg->GetMessageObj(data);

    DhcpV6MessageInfo msgInfo;
    if (!DhcpV6Message::ParseV6Message(data, msgInfo)) {
        DHCP_LOGE("[DHCPv6] DhcpV6InfoRequestState: failed to parse message");
        return NOT_EXECUTED;
    }

    if (msgInfo.transactionId != stateMachine_.GetTransactionId()) {
        DHCP_LOGI("[DHCPv6] DhcpV6InfoRequestState: transaction ID mismatch, ignoring");
        return NOT_EXECUTED;
    }

    DhcpV6Advertise reply;
    if (!DhcpV6Message::ParseV6Reply(data, reply)) {
        DHCP_LOGE("[DHCPv6] DhcpV6InfoRequestState: REPLY parse failed");
        return NOT_EXECUTED;
    }

    DHCP_LOGI("[DHCPv6] DhcpV6InfoRequestState: received REPLY, DNS=%{public}zu",
        reply.dnsServers.size());

    stateMachine_.ProcessResultInfo(reply);
    stateMachine_.OnSuccess();
    stateMachine_.SwitchState(stateMachine_.pInitState_);
    return EXECUTED;
}

bool DhcpV6InfoRequestState::ProcessTimeout(InternalMessagePtr msg)
{
    DhcpV6Config config = stateMachine_.GetConfig();
    config.transactionId = stateMachine_.GetTransactionId();
    auto message = DhcpV6Message::BuildInformationRequestMessage(config);
    bool ret = stateMachine_.ProcessTimeoutWithRetry("InfoRequestState", message);
    if (ret) {
        DHCP_LOGI("[DHCPv6] Resent INFORMATION-REQUEST");
    }
    return EXECUTED;
}

bool DhcpV6InfoRequestState::ProcessStop(InternalMessagePtr msg)
{
    DHCP_LOGI("[DHCPv6] DhcpV6InfoRequestState::ProcessStop");
    stateMachine_.SwitchState(stateMachine_.pInitState_);
    return EXECUTED;
}

//=============================================================================
// DhcpV6SolicitState Implementation
//=============================================================================
void DhcpV6SolicitState::GoInState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6SolicitState::GoInState");
    auto socket = stateMachine_.GetSocket();
    if (!socket) {
        return;
    }

    DhcpV6Config config = stateMachine_.GetConfig();
    config.transactionId = stateMachine_.GetTransactionId();
    auto message = DhcpV6Message::BuildSolicitMessage(config);
    socket->DhcpV6Send(message);
    DHCP_LOGI("[DHCPv6] Sent SOLICIT message");

    // Transition to Advertise state
    stateMachine_.SwitchState(stateMachine_.pAdvertiseState_);
}

void DhcpV6SolicitState::GoOutState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6SolicitState::GoOutState");
}

bool DhcpV6SolicitState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return NOT_EXECUTED;
    }

    int msgName = msg->GetMessageName();
    switch (msgName) {
        case CMD_STOP:
            return ProcessStop(msg);
        default:
            return NOT_EXECUTED;
    }
}

bool DhcpV6SolicitState::ProcessStop(InternalMessagePtr msg)
{
    DHCP_LOGI("[DHCPv6] DhcpV6SolicitState::ProcessStop");
    stateMachine_.SwitchState(stateMachine_.pInitState_);
    return EXECUTED;
}

//=============================================================================
// DhcpV6AdvertiseState Implementation
//=============================================================================
void DhcpV6AdvertiseState::GoInState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6AdvertiseState::GoInState");
    stateMachine_.ResetRetryCount();

    // Start advertise timer
    int64_t timeout = BASE_TIMEOUT_MS + (stateMachine_.GetRetryCount() * TIMEOUT_INCREMENT_MS);
    stateMachine_.SetCurrentTimeout(static_cast<uint32_t>(timeout));
    stateMachine_.IncrementRetryCount();
    stateMachine_.MessageExecutedLater(CMD_TIMEOUT, timeout);
}

void DhcpV6AdvertiseState::GoOutState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6AdvertiseState::GoOutState");
    stateMachine_.StopTimer(static_cast<int>(CMD_TIMEOUT));
}

bool DhcpV6AdvertiseState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return NOT_EXECUTED;
    }

    int msgName = msg->GetMessageName();
    switch (msgName) {
        case CMD_MESSAGE_RECEIVED:
            return ProcessMessageReceived(msg);
        case CMD_TIMEOUT:
            return ProcessTimeout(msg);
        case CMD_STOP:
            return ProcessStop(msg);
        default:
            return NOT_EXECUTED;
    }
}

bool DhcpV6AdvertiseState::ProcessMessageReceived(InternalMessagePtr msg)
{
    std::vector<uint8_t> data;
    msg->GetMessageObj(data);

    // Verify transaction ID
    DhcpV6MessageInfo msgInfo;
    if (!DhcpV6Message::ParseV6Message(data, msgInfo)) {
        DHCP_LOGE("[DHCPv6] DhcpV6AdvertiseState: failed to parse message");
        return NOT_EXECUTED;
    }

    if (msgInfo.transactionId != stateMachine_.GetTransactionId()) {
        DHCP_LOGI("[DHCPv6] DhcpV6AdvertiseState: transaction ID mismatch, ignoring");
        return NOT_EXECUTED;
    }

    DhcpV6Advertise advertise;
    if (!DhcpV6Message::ParseV6Advertise(data, advertise)) {
        DHCP_LOGE("[DHCPv6] DhcpV6AdvertiseState: ADVERTISE parse failed");
        return NOT_EXECUTED;
    }

    DHCP_LOGI("[DHCPv6] DhcpV6AdvertiseState: received ADVERTISE, addresses=%{public}zu, preference=%{public}d",
        advertise.ipv6Addresses.size(), advertise.preference);

    // Only accept ADVERTISE with addresses
    if (advertise.ipv6Addresses.empty()) {
        DHCP_LOGI("[DHCPv6] DhcpV6AdvertiseState: ADVERTISE has no addresses, waiting");
        return EXECUTED;
    }

    // RFC 8415: preference=0 means "continue to wait for better ADVERTISE"
    // Save this ADVERTISE as fallback, but wait for better one
    if (advertise.preference == 0) {
        // Save as fallback if no better one exists
        if (stateMachine_.GetCurrentAdvertise().ipv6Addresses.empty()) {
            DHCP_LOGI("[DHCPv6] DhcpV6AdvertiseState: preference=0, saving as fallback");
            stateMachine_.SetCurrentAdvertise(advertise);
        } else {
            DHCP_LOGI("[DHCPv6] DhcpV6AdvertiseState: preference=0, waiting for better ADVERTISE");
        }
        return EXECUTED;
    }

    // Use this ADVERTISE if no better one exists
    bool shouldUse = stateMachine_.GetCurrentAdvertise().ipv6Addresses.empty();
    if (!shouldUse && advertise.preference > stateMachine_.GetCurrentAdvertise().preference) {
        shouldUse = true;
        DHCP_LOGI("[DHCPv6] DhcpV6AdvertiseState: new ADVERTISE has higher preference");
    }

    // Check configured serverId if specified
    const auto& config = stateMachine_.GetConfig();
    if (!config.serverId.empty() && advertise.serverId != config.serverId) {
        DHCP_LOGI("[DHCPv6] DhcpV6AdvertiseState: server ID mismatch, ignoring");
        return EXECUTED;
    }

    if (shouldUse) {
        stateMachine_.SetCurrentAdvertise(advertise);
        stateMachine_.SwitchState(stateMachine_.pRequestState_);
    }
    return EXECUTED;
}

bool DhcpV6AdvertiseState::ProcessTimeout(InternalMessagePtr msg)
{
    // Check if we have a saved ADVERTISE (preference=0 fallback) to use
    const auto& savedAdvertise = stateMachine_.GetCurrentAdvertise();
    if (!savedAdvertise.ipv6Addresses.empty()) {
        DHCP_LOGI("[DHCPv6] DhcpV6AdvertiseState: max retries exceeded, using saved ADVERTISE");
        stateMachine_.SwitchState(stateMachine_.pRequestState_);
        return EXECUTED;
    }

    DhcpV6Config config = stateMachine_.GetConfig();
    config.transactionId = stateMachine_.GetTransactionId();
    auto message = DhcpV6Message::BuildSolicitMessage(config);
    bool ret = stateMachine_.ProcessTimeoutWithRetry("AdvertiseState", message);
    if (ret) {
        DHCP_LOGI("[DHCPv6] Resent SOLICIT");
    }
    return EXECUTED;
}

bool DhcpV6AdvertiseState::ProcessStop(InternalMessagePtr msg)
{
    DHCP_LOGI("[DHCPv6] DhcpV6AdvertiseState::ProcessStop");
    stateMachine_.SwitchState(stateMachine_.pInitState_);
    return EXECUTED;
}

//=============================================================================
// DhcpV6RequestState Implementation
//=============================================================================
void DhcpV6RequestState::GoInState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6RequestState::GoInState");
    auto socket = stateMachine_.GetSocket();
    if (!socket) {
        return;
    }

    DhcpV6Config config = stateMachine_.GetConfig();
    config.transactionId = stateMachine_.GetTransactionId();
    config.serverId = stateMachine_.GetCurrentAdvertise().serverId;
    auto message = DhcpV6Message::BuildRequestMessage(config, stateMachine_.GetCurrentAdvertise());
    socket->DhcpV6Send(message);
    DHCP_LOGI("[DHCPv6] Sent REQUEST message");

    stateMachine_.ResetRetryCount();

    // Start reply timer
    int64_t timeout = BASE_TIMEOUT_MS + (stateMachine_.GetRetryCount() * TIMEOUT_INCREMENT_MS);
    stateMachine_.SetCurrentTimeout(static_cast<uint32_t>(timeout));
    stateMachine_.IncrementRetryCount();
    stateMachine_.MessageExecutedLater(CMD_TIMEOUT, timeout);
}

void DhcpV6RequestState::GoOutState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6RequestState::GoOutState");
    stateMachine_.StopTimer(static_cast<int>(CMD_TIMEOUT));
}

bool DhcpV6RequestState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return NOT_EXECUTED;
    }

    int msgName = msg->GetMessageName();
    switch (msgName) {
        case CMD_MESSAGE_RECEIVED:
            return ProcessMessageReceived(msg);
        case CMD_TIMEOUT:
            return ProcessTimeout(msg);
        case CMD_STOP:
            return ProcessStop(msg);
        default:
            return NOT_EXECUTED;
    }
}

bool DhcpV6RequestState::ProcessMessageReceived(InternalMessagePtr msg)
{
    std::vector<uint8_t> data;
    msg->GetMessageObj(data);

    DhcpV6MessageInfo msgInfo;
    if (!DhcpV6Message::ParseV6Message(data, msgInfo)) {
        DHCP_LOGE("[DHCPv6] DhcpV6RequestState: failed to parse message");
        return NOT_EXECUTED;
    }

    if (msgInfo.transactionId != stateMachine_.GetTransactionId()) {
        DHCP_LOGI("[DHCPv6] DhcpV6RequestState: transaction ID mismatch, ignoring");
        return NOT_EXECUTED;
    }

    if (msgInfo.msgType != REPLY) {
        DHCP_LOGI("[DHCPv6] DhcpV6RequestState: received %{public}s (type=%{public}d), waiting for REPLY",
            DhcpV6Message::GetMsgTypeName(msgInfo.msgType), msgInfo.msgType);
        return NOT_EXECUTED;
    }

    DhcpV6Advertise reply;
    if (!DhcpV6Message::ParseV6Reply(data, reply)) {
        DHCP_LOGE("[DHCPv6] DhcpV6RequestState: REPLY parse failed, statusCode=%{public}d, addresses=%{public}zu",
            reply.statusCode, reply.ipv6Addresses.size());
        stateMachine_.OnFailure(ERR_GENERIC);
        stateMachine_.SwitchState(stateMachine_.pFailState_);
        return EXECUTED;
    }

    DHCP_LOGI("[DHCPv6] DhcpV6RequestState: received REPLY");

    // Check for addresses in stateful mode
    if (reply.ipv6Addresses.empty()) {
        DHCP_LOGE("[DHCPv6] DhcpV6RequestState: no IPv6 addresses in REPLY, statusCode=%{public}d",
            reply.statusCode);
        stateMachine_.OnFailure(ERR_GENERIC);
        stateMachine_.SwitchState(stateMachine_.pFailState_);
        return EXECUTED;
    }

    stateMachine_.ProcessResultInfo(reply);
    stateMachine_.SwitchState(stateMachine_.pBoundState_);
    return EXECUTED;
}

bool DhcpV6RequestState::ProcessTimeout(InternalMessagePtr msg)
{
    DhcpV6Config config = stateMachine_.GetConfig();
    config.transactionId = stateMachine_.GetTransactionId();
    config.serverId = stateMachine_.GetCurrentAdvertise().serverId;
    auto message = DhcpV6Message::BuildRequestMessage(config, stateMachine_.GetCurrentAdvertise());
    bool ret = stateMachine_.ProcessTimeoutWithRetry("RequestState", message);
    if (ret) {
        DHCP_LOGI("[DHCPv6] Resent REQUEST");
    }
    return EXECUTED;
}

bool DhcpV6RequestState::ProcessStop(InternalMessagePtr msg)
{
    DHCP_LOGI("[DHCPv6] DhcpV6RequestState::ProcessStop");
    stateMachine_.SwitchState(stateMachine_.pInitState_);
    return EXECUTED;
}

//=============================================================================
// DhcpV6BoundState Implementation
//=============================================================================
void DhcpV6BoundState::GoInState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6BoundState::GoInState");

    // Report success result (kernel handles address configuration via Netlink)
    stateMachine_.OnSuccess();

    const auto& config = stateMachine_.GetConfig();
    if (!config.stateless) {
        const auto& result = stateMachine_.GetResult();
        uint32_t t1 = result.t1;
        uint32_t t2 = result.t2;
        uint32_t validLifetime = result.validLifetime;

        // RFC 8415: validLifetime=0 means address is invalid
        if (validLifetime == 0) {
            DHCP_LOGE("[DHCPv6] DhcpV6BoundState: validLifetime=0, lease expired");
            stateMachine_.ClearT2Deadline();
            stateMachine_.ClearExpireDeadline();
            stateMachine_.MessageExecutedLater(CMD_TIMEOUT, 0);
            return;
        }

        bool isInfinite = (validLifetime == INFINITE_LIFETIME);
        if (isInfinite) {
            DHCP_LOGI("[DHCPv6] DhcpV6BoundState: infinite lease, no renew timer");
            return;
        }

        // Calculate absolute deadlines
        uint64_t nowMs = stateMachine_.GetCurrentTimeMs();
        stateMachine_.SetT2DeadlineMs(nowMs + (static_cast<uint64_t>(t2) * MS_PER_SECOND));
        stateMachine_.SetExpireDeadlineMs(nowMs + (static_cast<uint64_t>(validLifetime) * MS_PER_SECOND));

        int64_t t1Ms = static_cast<int64_t>(t1) * MS_PER_SECOND;
        DHCP_LOGI("[DHCPv6] DhcpV6BoundState: starting T1 timer %{public}" PRId64 " ms, "
            "T2 deadline in %{public}" PRIu64 " ms, expire in %{public}" PRIu64 " ms",
            t1Ms, stateMachine_.GetT2DeadlineMs(), stateMachine_.GetExpireDeadlineMs());
        stateMachine_.MessageExecutedLater(CMD_TIMEOUT, t1Ms);
    } else {
        DHCP_LOGI("[DHCPv6] DhcpV6BoundState: stateless mode, no renew timer");
    }
}

void DhcpV6BoundState::GoOutState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6BoundState::GoOutState");
    stateMachine_.StopTimer(static_cast<int>(CMD_TIMEOUT));
    stateMachine_.ClearT2Deadline();
    stateMachine_.ClearExpireDeadline();
}

bool DhcpV6BoundState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return NOT_EXECUTED;
    }

    int msgName = msg->GetMessageName();
    switch (msgName) {
        case CMD_TIMEOUT:
            return ProcessTimeout(msg);
        case CMD_STOP:
            return ProcessStop(msg);
        case CMD_DAD_CONFLICT:
            return ProcessDadConflict(msg);
        default:
            return NOT_EXECUTED;
    }
}

bool DhcpV6BoundState::ProcessTimeout(InternalMessagePtr msg)
{
    DHCP_LOGI("[DHCPv6] DhcpV6BoundState::ProcessTimeout - T1 deadline reached, transitioning to RENEW");
    stateMachine_.SwitchState(stateMachine_.pRenewState_);
    return EXECUTED;
}

bool DhcpV6BoundState::ProcessStop(InternalMessagePtr msg)
{
    DHCP_LOGI("[DHCPv6] DhcpV6BoundState::ProcessStop");
    stateMachine_.SwitchState(stateMachine_.pReleaseState_);
    return EXECUTED;
}

bool DhcpV6BoundState::ProcessDadConflict(InternalMessagePtr msg)
{
    std::string addr;
    msg->GetMessageObj(addr);
    DHCP_LOGW("[DHCPv6] DhcpV6BoundState: DAD conflict for %{public}s", Ipv6Anonymize(addr).c_str());

    // Send DECLINE to server (network manager handles kernel address removal)
    auto socket = stateMachine_.GetSocket();
    if (socket) {
        DhcpV6Config config = stateMachine_.GetConfig();
        config.transactionId = DhcpV6Message::GenerateTransactionId();
        auto message = DhcpV6Message::BuildDeclineMessage(config, {addr});
        socket->DhcpV6Send(message);
        DHCP_LOGI("[DHCPv6] Sent DECLINE for %{public}s", Ipv6Anonymize(addr).c_str());
    }

    // Clear local result and restart (network manager will remove kernel address)
    stateMachine_.GetResult().ipv6Addresses.clear();
    stateMachine_.GetResult().dnsServers.clear();
    stateMachine_.ResetRetryCount();
    stateMachine_.SetTransactionId(DhcpV6Message::GenerateTransactionId());
    stateMachine_.GetConfig().serverId.clear();

    // Report DAD conflict to upper layer (network manager will handle address removal)
    stateMachine_.OnFailure(ERR_DAD_FAILED);

    stateMachine_.SwitchState(stateMachine_.pSolicitState_);
    return EXECUTED;
}

//=============================================================================
// DhcpV6RenewState Implementation
//=============================================================================
void DhcpV6RenewState::GoInState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6RenewState::GoInState");
    stateMachine_.ProcessRenewOrRebind(true);
}

void DhcpV6RenewState::GoOutState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6RenewState::GoOutState");
    stateMachine_.StopTimer(static_cast<int>(CMD_TIMEOUT));
    stateMachine_.StopTimer(static_cast<int>(CMD_T2_TIMEOUT));
}

bool DhcpV6RenewState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return NOT_EXECUTED;
    }

    int msgName = msg->GetMessageName();
    switch (msgName) {
        case CMD_MESSAGE_RECEIVED:
            return ProcessMessageReceived(msg);
        case CMD_TIMEOUT:
            return ProcessTimeout(msg);
        case CMD_T2_TIMEOUT:
            // T2 deadline reached, transition to REBIND
            DHCP_LOGI("[DHCPv6] DhcpV6RenewState: T2 deadline reached, transitioning to REBIND");
            stateMachine_.ClearT2Deadline();
            stateMachine_.SwitchState(stateMachine_.pRebindState_);
            return EXECUTED;
        case CMD_STOP:
            return ProcessStop(msg);
        default:
            return NOT_EXECUTED;
    }
}

bool DhcpV6RenewState::ProcessMessageReceived(InternalMessagePtr msg)
{
    std::vector<uint8_t> data;
    msg->GetMessageObj(data);

    DhcpV6MessageInfo msgInfo;
    if (!DhcpV6Message::ParseV6Message(data, msgInfo)) {
        DHCP_LOGE("[DHCPv6] DhcpV6RenewState: failed to parse message");
        return NOT_EXECUTED;
    }

    if (msgInfo.transactionId != stateMachine_.GetTransactionId()) {
        DHCP_LOGI("[DHCPv6] DhcpV6RenewState: transaction ID mismatch, ignoring");
        return NOT_EXECUTED;
    }

    if (msgInfo.msgType != REPLY) {
        DHCP_LOGI("[DHCPv6] DhcpV6RenewState: received %{public}s (type=%{public}d), waiting for REPLY",
            DhcpV6Message::GetMsgTypeName(msgInfo.msgType), msgInfo.msgType);
        return NOT_EXECUTED;
    }

    DhcpV6Advertise reply;
    if (!DhcpV6Message::ParseV6Reply(data, reply)) {
        DHCP_LOGE("[DHCPv6] DhcpV6RenewState: REPLY parse failed");
        return NOT_EXECUTED;
    }

    DHCP_LOGI("[DHCPv6] DhcpV6RenewState: received REPLY");

    // Empty address list means lease expired, continue to Rebind
    if (reply.ipv6Addresses.empty()) {
        DHCP_LOGI("[DHCPv6] DhcpV6RenewState: RENEW got empty address list, transitioning to REBIND");
        stateMachine_.SwitchState(stateMachine_.pRebindState_);
        return EXECUTED;
    }

    stateMachine_.ProcessResultInfo(reply);
    stateMachine_.SwitchState(stateMachine_.pBoundState_);
    return EXECUTED;
}

bool DhcpV6RenewState::ProcessTimeout(InternalMessagePtr msg)
{
    DHCP_LOGI("[DHCPv6] DhcpV6RenewState::ProcessTimeout");
    stateMachine_.ProcessRenewOrRebind(true);
    return EXECUTED;
}

bool DhcpV6RenewState::ProcessStop(InternalMessagePtr msg)
{
    DHCP_LOGI("[DHCPv6] DhcpV6RenewState::ProcessStop");
    stateMachine_.SwitchState(stateMachine_.pReleaseState_);
    return EXECUTED;
}

//=============================================================================
// DhcpV6RebindState Implementation
//=============================================================================
void DhcpV6RebindState::GoInState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6RebindState::GoInState");
    stateMachine_.ProcessRenewOrRebind(false);
}

void DhcpV6RebindState::GoOutState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6RebindState::GoOutState");
    stateMachine_.StopTimer(static_cast<int>(CMD_TIMEOUT));
    stateMachine_.StopTimer(static_cast<int>(CMD_EXPIRE_TIMEOUT));
}

bool DhcpV6RebindState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return NOT_EXECUTED;
    }

    int msgName = msg->GetMessageName();
    switch (msgName) {
        case CMD_MESSAGE_RECEIVED:
            return ProcessMessageReceived(msg);
        case CMD_TIMEOUT:
            return ProcessTimeout(msg);
        case CMD_EXPIRE_TIMEOUT:
            // Lease expired
            DHCP_LOGI("[DHCPv6] DhcpV6RebindState: EXPIRE deadline reached, lease expired");
            stateMachine_.OnFailure(ERR_LEASE_EXPIRED);
            stateMachine_.OnLeaseExpired();
            stateMachine_.ClearExpireDeadline();
            stateMachine_.SwitchState(stateMachine_.pInitState_);
            return EXECUTED;
        case CMD_STOP:
            return ProcessStop(msg);
        default:
            return NOT_EXECUTED;
    }
}

bool DhcpV6RebindState::ProcessMessageReceived(InternalMessagePtr msg)
{
    std::vector<uint8_t> data;
    msg->GetMessageObj(data);

    DhcpV6MessageInfo msgInfo;
    if (!DhcpV6Message::ParseV6Message(data, msgInfo)) {
        DHCP_LOGE("[DHCPv6] DhcpV6RebindState: failed to parse message");
        return NOT_EXECUTED;
    }

    if (msgInfo.transactionId != stateMachine_.GetTransactionId()) {
        DHCP_LOGI("[DHCPv6] DhcpV6RebindState: transaction ID mismatch, ignoring");
        return NOT_EXECUTED;
    }

    if (msgInfo.msgType != REPLY) {
        DHCP_LOGI("[DHCPv6] DhcpV6RebindState: received %{public}s (type=%{public}d), waiting for REPLY",
            DhcpV6Message::GetMsgTypeName(msgInfo.msgType), msgInfo.msgType);
        return NOT_EXECUTED;
    }

    DhcpV6Advertise reply;
    if (!DhcpV6Message::ParseV6Reply(data, reply)) {
        DHCP_LOGE("[DHCPv6] DhcpV6RebindState: REPLY parse failed");
        return NOT_EXECUTED;
    }

    DHCP_LOGI("[DHCPv6] DhcpV6RebindState: received REPLY");

    // Empty address list means lease expired
    if (reply.ipv6Addresses.empty()) {
        DHCP_LOGE("[DHCPv6] DhcpV6RebindState: REBIND got empty address list, lease expired");
        stateMachine_.OnFailure(ERR_LEASE_EXPIRED);
        stateMachine_.OnLeaseExpired();
        stateMachine_.SwitchState(stateMachine_.pInitState_);
        return EXECUTED;
    }

    stateMachine_.ProcessResultInfo(reply);

    // Update expire deadline with new validLifetime
    uint64_t nowMs = stateMachine_.GetCurrentTimeMs();
    if (reply.validLifetime != INFINITE_LIFETIME) {
        stateMachine_.SetExpireDeadlineMs(nowMs + (static_cast<uint64_t>(reply.validLifetime) * MS_PER_SECOND));
    } else {
        stateMachine_.ClearExpireDeadline();
    }

    stateMachine_.SwitchState(stateMachine_.pBoundState_);
    return EXECUTED;
}

bool DhcpV6RebindState::ProcessTimeout(InternalMessagePtr msg)
{
    DHCP_LOGI("[DHCPv6] DhcpV6RebindState::ProcessTimeout");
    stateMachine_.ProcessRenewOrRebind(false);
    return EXECUTED;
}

bool DhcpV6RebindState::ProcessStop(InternalMessagePtr msg)
{
    DHCP_LOGI("[DHCPv6] DhcpV6RebindState::ProcessStop");
    stateMachine_.SwitchState(stateMachine_.pReleaseState_);
    return EXECUTED;
}

//=============================================================================
// DhcpV6ReleaseState Implementation
//=============================================================================
void DhcpV6ReleaseState::GoInState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6ReleaseState::GoInState");
    auto socket = stateMachine_.GetSocket();
    if (!socket) {
        stateMachine_.SwitchState(stateMachine_.pInitState_);
        return;
    }

    DhcpV6Config releaseConfig = stateMachine_.GetConfig();
    releaseConfig.transactionId = DhcpV6Message::GenerateTransactionId();
    auto message = DhcpV6Message::BuildReleaseMessage(releaseConfig);
    socket->DhcpV6Send(message);
    DHCP_LOGI("[DHCPv6] Sent RELEASE message");

    // Immediately transition to init
    stateMachine_.SwitchState(stateMachine_.pInitState_);
}

void DhcpV6ReleaseState::GoOutState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6ReleaseState::GoOutState");
}

bool DhcpV6ReleaseState::ExecuteStateMsg(InternalMessagePtr msg)
{
    // This state is transient, no message processing
    return NOT_EXECUTED;
}

//=============================================================================
// DhcpV6FailState Implementation
//=============================================================================
void DhcpV6FailState::GoInState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6FailState::GoInState");
}

void DhcpV6FailState::GoOutState()
{
    DHCP_LOGI("[DHCPv6] DhcpV6FailState::GoOutState");
}

bool DhcpV6FailState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return NOT_EXECUTED;
    }

    int msgName = msg->GetMessageName();
    if (msgName == CMD_START) {
        // Allow restart from fail state
        stateMachine_.SwitchState(stateMachine_.pInitState_);
        return EXECUTED;
    }
    return NOT_EXECUTED;
}

} // namespace DHCP
} // namespace OHOS
