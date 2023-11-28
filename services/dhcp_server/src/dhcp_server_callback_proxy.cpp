/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include "dhcp_logger.h"
#include "dhcp_manager_service_ipc_interface_code.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpServerCallbackProxy");

namespace OHOS {
namespace Wifi {
DhcpServerCallbackProxy::DhcpServerCallbackProxy(const sptr<IRemoteObject> &impl) :
    IRemoteProxy<IDhcpServerCallBack>(impl)
{}

DhcpServerCallbackProxy::~DhcpServerCallbackProxy()
{}

void DhcpServerCallbackProxy::OnServerStatusChanged(int status)
{
    DHCP_LOGI("DhcpServerCallbackProxy::OnServerStatusChanged");
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(status);
    DHCP_LOGI("start server requeset");
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_CBK_SERVER_STATUS_CHANGE), data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_CBK_SERVER_STATUS_CHANGE), error);
        return;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGE("notify wifi state change failed!");
    }
    DHCP_LOGI("send server request success");

    return;
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
