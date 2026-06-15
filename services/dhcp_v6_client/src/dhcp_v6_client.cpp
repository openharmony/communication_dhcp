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

#include "dhcp_v6_client.h"
#include "dhcp_v6_constants.h"
#include "dhcp_logger.h"
#include "dhcp_common_utils.h"
#include <thread>

DEFINE_DHCPLOG_DHCP_LABEL("DhcpV6Client");

namespace OHOS {
namespace DHCP {

DhcpV6Client::DhcpV6Client(const std::string& iface)
    : iface_(iface),
      socket_(std::make_unique<DhcpV6Socket>(iface)),
      callback_(nullptr),
      isClientRunning_(false),
      isStopRequested_(false)
{
    stateMachine_ = std::make_unique<DhcpV6StateMachine>();
    stateMachine_->SetSocket(socket_.get());
    stateMachine_->SetIfaceName(iface_);

    stateMachine_->SetResultCallback(
        [this](const DhcpV6Result& result) {
            IDhcpV6Callback* cb = nullptr;
            {
                std::lock_guard<std::mutex> lock(callbackMutex_);
                cb = callback_;
                result_ = result;
            }
            if (cb) {
                cb->OnDhcpV6Success(result);
            }
        },
        [this](int errorCode) {
            IDhcpV6Callback* cb = nullptr;
            {
                std::lock_guard<std::mutex> lock(callbackMutex_);
                cb = callback_;
            }
            if (cb) {
                cb->OnDhcpV6Failed(errorCode);
            }
        });

    stateMachine_->SetExpiredCallback([this]() {
        IDhcpV6Callback* cb = nullptr;
        {
            std::lock_guard<std::mutex> lock(callbackMutex_);
            cb = callback_;
        }
        if (cb) {
            cb->OnDhcpV6Expired();
        }
    });

    config_.clientId = DhcpV6Message::GenerateDuid(iface_);
    stateMachine_->SetConfig(config_);
}

void DhcpV6Client::DhcpV6ConfigureStateless(bool stateless)
{
    config_.stateless = stateless;
    config_.transactionId = 0;
    stateMachine_->SetConfig(config_);
}

DhcpV6Client::~DhcpV6Client()
{
    DhcpV6Stop();
}

int DhcpV6Client::DhcpV6Start()
{
    if (isClientRunning_) {
        return 0;
    }

    DHCP_LOGI("[DHCPv6] Start() interface:%{public}s stateless:%{public}d",
        iface_.c_str(), config_.stateless);

    if (socket_->DhcpV6Init() != 0) {
        DHCP_LOGE("[DHCPv6] Start() socket init failed");
        return ERR_GENERIC;
    }

    // Initialize state machine
    if (!stateMachine_->InitDhcpV6StateMachine()) {
        DHCP_LOGE("[DHCPv6] Start() state machine init failed");
        return ERR_GENERIC;
    }

    // Clear serverId so client re-discovers server from ADVERTISE
    config_.serverId.clear();
    stateMachine_->SetConfig(config_);

    isClientRunning_ = true;

    messageThread_ = std::thread([this]() {
        DhcpV6ReceiveLoop();
    });

    // Send CMD_START to state machine
    stateMachine_->SendMessage(CMD_START);
    return 0;
}

int DhcpV6Client::DhcpV6Stop()
{
    if (!isClientRunning_) {
        DHCP_LOGI("[DHCPv6] DhcpV6Stop: already stopped, returning");
        return 0;
    }

    DHCP_LOGI("[DHCPv6] DhcpV6Stop() interface:%{public}s", iface_.c_str());

    // Step 1: Set stop flags to prevent new operations
    isClientRunning_ = false;
    isStopRequested_ = true;
    stateMachine_->SetStopping(true);

    // Step 2: Send CMD_STOP to state machine
    DHCP_LOGI("[DHCPv6] DhcpV6Stop: sending CMD_STOP to clear state machine state");
    stateMachine_->SendMessage(CMD_STOP);
    DHCP_LOGI("[DHCPv6] DhcpV6Stop: CMD_STOP sent");

    // Step 3: Close socket FIRST to interrupt blocking recv() before join()
    socket_->Close();
    DHCP_LOGI("[DHCPv6] DhcpV6Stop: socket closed to interrupt recv");

    // Step 4: Wait for receive thread to exit
    if (messageThread_.joinable()) {
        DHCP_LOGI("[DHCPv6] DhcpV6Stop: joining message thread...");
        messageThread_.join();
        DHCP_LOGI("[DHCPv6] DhcpV6Stop: message thread exited");
    }

    // Step 5: Stop state machine
    stateMachine_->StopHandlerThread();
    DHCP_LOGI("[DHCPv6] DhcpV6Stop: state machine stopped");

    // Step 6: Notify upper layer that DHCPv6 client stopped
    // Network manager will handle kernel address removal
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        if (callback_) {
            DHCP_LOGI("[DHCPv6] DhcpV6Stop: calling OnDhcpV6Stop callback");
            callback_->OnDhcpV6Stop();
        }
    }

    // Step 7: Clear local result (network manager handles kernel address removal)
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        result_.ipv6Addresses.clear();
        result_.dnsServers.clear();
    }

    DHCP_LOGI("[DHCPv6] DhcpV6Stop: DONE");
    return 0;
}

bool DhcpV6Client::IsRunning() const
{
    return isClientRunning_.load();
}

int DhcpV6Client::DhcpV6RegisterCallback(IDhcpV6Callback* callback)
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    callback_ = callback;
    return 0;
}

void DhcpV6Client::OnKernelDadConflict(const std::string& addr)
{
    if (!isClientRunning_) {
        return;
    }
    stateMachine_->OnKernelDadConflict(addr);
}

bool DhcpV6Client::IsDhcpV6ConfiguredAddress(const std::string& addr) const
{
    if (!isClientRunning_) {
        return false;
    }
    return stateMachine_->IsDhcpV6ConfiguredAddress(addr);
}

void DhcpV6Client::DhcpV6ReceiveLoop()
{
    DHCP_LOGI("[DHCPv6] ReceiveLoop: START, isClientRunning_=%{public}d", isClientRunning_.load());
    std::vector<uint8_t> buffer;

    while (isClientRunning_ && !isStopRequested_) {
        int ret = socket_->DhcpV6Receive(buffer, RECV_TIMEOUT_MS);
        if (ret == 0) {
            // Create message with received data
            auto msg = stateMachine_->CreateMessage(CMD_MESSAGE_RECEIVED, buffer);
            if (msg) {
                stateMachine_->SendMessage(msg);
            }
        } else if (ret == SOCK_RECV_TIMEOUT) {
            continue;
        } else if (ret == ERR_GENERIC) {
            if (isClientRunning_ && !isStopRequested_) {
                DHCP_LOGE("[DHCPv6] ReceiveLoop: socket receive error, stopping client");
                stateMachine_->SendMessage(CMD_ERROR);
                break;
            }
        }
    }
    DHCP_LOGI("[DHCPv6] ReceiveLoop: EXIT, isClientRunning_=%{public}d, isStopRequested_=%{public}d",
        isClientRunning_.load(), isStopRequested_.load());
}

} // namespace DHCP
} // namespace OHOS
