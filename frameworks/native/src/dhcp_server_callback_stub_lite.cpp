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
#include "dhcp_server_callback_stub.h"
#include "dhcp_manager_service_ipc_interface_code.h"
#include "dhcp_logger.h"
#include "dhcp_sdk_define.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpServreCallBackStubLite");

namespace OHOS {
namespace DHCP {

DhcpServreCallBackStub::DhcpServreCallBackStub() : userCallback_(nullptr), mRemoteDied(false)
{
    DHCP_LOGI("DhcpServreCallBackStub Enter DhcpServreCallBackStub");
}

DhcpServreCallBackStub::~DhcpServreCallBackStub()
{
    DHCP_LOGI("DhcpServreCallBackStub Enter ~DhcpServreCallBackStub");
}

int DhcpServreCallBackStub::OnRemoteRequest(uint32_t code, IpcIo *data)
{
    int ret = -1;
    DHCP_LOGD("OnRemoteRequest code:%{public}u!", code);
    if (mRemoteDied || data == nullptr) {
        DHCP_LOGD("Failed to %{public}s,mRemoteDied:%{public}d data:%{public}d!",
            __func__, mRemoteDied, data == nullptr);
        return ret;
    }

    size_t length;
    uint16_t* interfaceRead = nullptr;
    interfaceRead = ReadInterfaceToken(data, &length);
    for (size_t i = 0; i < length; i++) {
        if (i >= DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH || interfaceRead[i] != DECLARE_INTERFACE_DESCRIPTOR_L1[i]) {
            DHCP_LOGE("Scan stub token verification error: %{public}d", code);
            return -1;
        }
    }

    int exception = -1;
    (void)ReadInt32(data, &exception);
    if (exception) {
        DHCP_LOGD("OnRemoteRequest exception! %{public}d!", exception);
        return ret;
    }
    switch (code) {
        case static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_CBK_SERVER_STATUS_CHANGE): {
            ret = RemoteOnServerStatusChanged(code, data);
            break;
        }
        case static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_CBK_SERVER_LEASES_CHANGE): {
            ret = RemoteOnServerLeasesChanged(code, data);
            break;
        }
        case static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_CBK_SER_EXIT_CHANGE): {
            ret = RemoteOnServerSerExitChanged(code, data);
            break;
        }
        default: {
            ret = -1;
            break;
        }
    }
    return ret;
}

void DhcpServreCallBackStub::RegisterCallBack(const std::shared_ptr<IDhcpServerCallBack> &userCallback)
{
    if (userCallback_ != nullptr) {
        DHCP_LOGD("Callback has registered!");
        return;
    }
    userCallback_ = userCallback;
}

bool DhcpServreCallBackStub::IsRemoteDied() const
{
    return mRemoteDied;
}

void DhcpServreCallBackStub::SetRemoteDied(bool val)
{
    mRemoteDied = val;
}

void DhcpServreCallBackStub::OnServerStatusChanged(int status)
{
    DHCP_LOGI("DhcpServreCallBackStub::OnServerStatusChanged, status:%{public}d", status);
    if (userCallback_) {
        userCallback_->OnServerStatusChanged(status);
    }
}

void DhcpServreCallBackStub::OnServerLeasesChanged(const std::string& ifname, std::vector<std::string>& leases)
{
    DHCP_LOGI("DhcpServreCallBackStub::OnServerLeasesChanged, ifname:%{public}s", ifname.c_str());
    if (userCallback_) {
        userCallback_->OnServerLeasesChanged(ifname, leases);
    }
}

void DhcpServreCallBackStub::OnServerSerExitChanged(const std::string& ifname)
{
    DHCP_LOGI("DhcpServreCallBackStub::OnWifiWpsStateChanged, ifname:%{public}s", ifname.c_str());
    if (userCallback_) {
        userCallback_->OnServerSerExitChanged(ifname);
    }
}

int DhcpServreCallBackStub::RemoteOnServerStatusChanged(uint32_t code, IpcIo *data)
{
    DHCP_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int stateCode = 0;
    (void)ReadInt32(data, &stateCode);
    OnServerStatusChanged(state);
    return 0;
}

int DhcpServreCallBackStub::RemoteOnServerLeasesChanged(uint32_t code, IpcIo *data)
{
    DHCP_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    return 0;
}

int DhcpServreCallBackStub::RemoteOnServerSerExitChanged(uint32_t code, IpcIo *data)
{
    DHCP_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS