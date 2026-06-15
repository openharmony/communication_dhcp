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

#ifndef DHCP_V6_CLIENT_H
#define DHCP_V6_CLIENT_H

#include <memory>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include "dhcp_v6_result.h"
#include "dhcp_v6_callback.h"
#include "dhcp_v6_statemachine.h"
#include "dhcp_v6_socket.h"
#include "dhcp_v6_message.h"

namespace OHOS {
namespace DHCP {

class DhcpV6Client {
public:
    explicit DhcpV6Client(const std::string& iface);
    ~DhcpV6Client();

    void DhcpV6ConfigureStateless(bool stateless);
    int DhcpV6Start();
    int DhcpV6Stop();
    int DhcpV6RegisterCallback(IDhcpV6Callback* callback);
    bool IsRunning() const;

    // Kernel DAD conflict notification (called from Netlink event handler)
    void OnKernelDadConflict(const std::string& addr);
    bool IsDhcpV6ConfiguredAddress(const std::string& addr) const;

private:
    std::string iface_;
    std::unique_ptr<DhcpV6StateMachine> stateMachine_;
    std::unique_ptr<DhcpV6Socket> socket_;
    DhcpV6Config config_;
    DhcpV6Result result_;
    IDhcpV6Callback* callback_;
    std::mutex callbackMutex_;  // Protect callback_ and result_ access

    // Threading
    std::atomic<bool> isClientRunning_;
    std::atomic<bool> isStopRequested_;  // Flag to stop the receive loop
    std::thread messageThread_;

    void DhcpV6ReceiveLoop();
};

} // namespace DHCP
} // namespace OHOS

#endif // DHCP_V6_CLIENT_H
