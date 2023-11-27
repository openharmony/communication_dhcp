/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "dhcp_server_callback_proxy.h"
#include "dhcp_manager_service_ipc_interface_code.h"
#include "dhcp_sdk_define.h"
#include "ipc_skeleton.h"
#include "rpc_errno.h"
#include "dhcp_logger.h"
DEFINE_DHCPLOG_DHCP_LABEL("DhcpServerCallbackProxyLite");

namespace OHOS {
namespace Wifi {
DhcpServerCallbackProxy::DhcpServerCallbackProxy(SvcIdentity *sid) : sid_(*sid)
{}

DhcpServerCallbackProxy::~DhcpServerCallbackProxy()
{
    ReleaseSvc(sid_);
}

void DhcpServerCallbackProxy::OnServerStatusChanged(int status)
{
    DHCP_LOGI("DhcpServerCallbackProxy::OnServerStatusChanged");
    IpcIo data;
    uint8_t buff[DEFAULT_IPC_SIZE];
    IpcIoInit(&data, buff, DEFAULT_IPC_SIZE, 0);
    if (!WriteInterfaceToken(&data, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    (void)WriteInt32(&data, 0);
    (void)WriteInt32(&data, status);
    IpcIo reply;
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int ret = SendRequest(sid_, static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_CBK_SERVER_STATUS_CHANGE),
        &data, &reply, option, nullptr);
    switch (ret) {
        case ERR_NONE:
            DHCP_LOGD("OnServerStatusChanged callback succeeded!");
            break;
        default: {
            DHCP_LOGE("OnServerStatusChanged,connect done failed, error: %{public}d!", ret);
            break;
        }
    }
}

void DhcpServerCallbackProxy::OnServerLeasesChanged(const std::string& ifname, std::vector<std::string>& leases)
{
    DHCP_LOGI("DhcpServerCallbackProxy::OnServerLeasesChanged");
    return;
}
void DhcpServerCallbackProxy::OnServerSerExitChanged(const std::string& ifname)
{
    DHCP_LOGI("DhcpServerCallbackProxy::OnServerSerExitChanged");
    return;
}
}  // namespace Wifi
}  // namespace OHOS
