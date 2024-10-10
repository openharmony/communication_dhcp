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
#include "securec.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpServreCallBackStub");

namespace OHOS {
namespace DHCP {
DhcpServreCallBackStub::DhcpServreCallBackStub() : callback_(nullptr), mRemoteDied(false)
{
    DHCP_LOGI("DhcpServreCallBackStub Enter DhcpServreCallBackStub");
}

DhcpServreCallBackStub::~DhcpServreCallBackStub()
{
    DHCP_LOGI("DhcpServreCallBackStub Enter ~DhcpServreCallBackStub");
}

int DhcpServreCallBackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DHCP_LOGI("DhcpServreCallBackStub::OnRemoteRequest, code:%{public}u", code);
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        DHCP_LOGE("Sta callback stub token verification error: %{public}d", code);
        return DHCP_E_FAILED;
    }

    int exception = data.ReadInt32();
    if (exception) {
        DHCP_LOGE("DhcpServreCallBackStub::OnRemoteRequest, got exception: %{public}d!", exception);
        return DHCP_E_FAILED;
    }
    int ret = -1;
    switch (code) {
        case static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_CBK_SERVER_STATUS_CHANGE): {
            ret = RemoteOnServerStatusChanged(code, data, reply);
            break;
        }
        case static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_CBK_SERVER_LEASES_CHANGE): {
            ret = RemoteOnServerLeasesChanged(code, data, reply);
            break;
        }
        case static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_CBK_SER_EXIT_CHANGE): {
            ret = RemoteOnServerSerExitChanged(code, data, reply);
            break;
        }
        case static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_CBK_SERVER_SUCCESS): {
            ret = RemoteOnServerSuccess(code, data, reply);
            break;
        }
        default: {
            ret = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
        }
    }
    DHCP_LOGI("DhcpClientCallBackStub OnRemoteRequest, ret:%{public}d", ret);
    return ret;
}

void DhcpServreCallBackStub::RegisterCallBack(const sptr<IDhcpServerCallBack> &callBack)
{
    if (callBack == nullptr) {
        DHCP_LOGE("DhcpServreCallBackStub:callBack is nullptr!");
        return;
    }
    callback_ = callBack;
}

bool DhcpServreCallBackStub::IsRemoteDied() const
{
    return mRemoteDied;
}

void DhcpServreCallBackStub::SetRemoteDied(bool val)
{
    DHCP_LOGI("DhcpServreCallBackStub::SetRemoteDied, state:%{public}d!", val);
    mRemoteDied = val;
}

void DhcpServreCallBackStub::OnServerStatusChanged(int status)
{
    DHCP_LOGI("DhcpServreCallBackStub::OnServerStatusChanged, status:%{public}d", status);
    if (callback_) {
        callback_->OnServerStatusChanged(status);
    }
}

void DhcpServreCallBackStub::OnServerLeasesChanged(const std::string& ifname, std::vector<std::string>& leases)
{
    DHCP_LOGI("DhcpServreCallBackStub::OnServerLeasesChanged, ifname:%{public}s", ifname.c_str());
    if (callback_) {
        callback_->OnServerLeasesChanged(ifname, leases);
    }
}

void DhcpServreCallBackStub::OnServerSuccess(const std::string &ifname, std::vector<DhcpStationInfo> &stationInfos)
{
    DHCP_LOGI("DhcpServreCallBackStub::OnServerSuccess, ifname:%{public}s", ifname.c_str());
    if (callback_) {
        callback_->OnServerSuccess(ifname.c_str(), stationInfos);
    }
}

void DhcpServreCallBackStub::OnServerSerExitChanged(const std::string& ifname)
{
    DHCP_LOGI("DhcpServreCallBackStub::OnWifiWpsStateChanged, ifname:%{public}s", ifname.c_str());
    if (callback_) {
        callback_->OnServerSerExitChanged(ifname);
    }
}

int DhcpServreCallBackStub::RemoteOnServerStatusChanged(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    DHCP_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    // callback OnServerStatusChanged
    int state = data.ReadInt32();
    OnServerStatusChanged(state);
    reply.WriteInt32(0);
    return 0;
}

int DhcpServreCallBackStub::RemoteOnServerSuccess(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    DHCP_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::string ifName = data.ReadString();
    int size = data.ReadInt32();
    if (size < 0 || size > MAXIMUM_SIZE) {
        reply.WriteInt32(0);
        return 0;
    }
    std::vector<DhcpStationInfo> stationInfos;
    for (int i = 0; i < size; i++) {
        std::string deviceName = data.ReadString();
        std::string macAddress = data.ReadString();
        std::string ipAddress = data.ReadString();
        DhcpStationInfo stationInfo;
        memset_s(&stationInfo, sizeof(DhcpStationInfo), 0, sizeof(DhcpStationInfo));
        if (memcpy_s(stationInfo.ipAddr, sizeof(stationInfo.ipAddr), ipAddress.c_str(), sizeof(stationInfo.ipAddr)) != EOK) {
            DHCP_LOGE("ipAddr memcpy_s error!");
            return DHCP_E_FAILED;
        }
        if (memcpy_s(stationInfo.macAddr, sizeof(stationInfo.macAddr), macAddress.c_str(), sizeof(stationInfo.macAddr)) != EOK) {
            DHCP_LOGE("macAddr memcpy_s error!");
            return DHCP_E_FAILED;
        }
        if (memcpy_s(stationInfo.deviceName, sizeof(stationInfo.deviceName), deviceName.c_str(),sizeof(stationInfo.deviceName)) != EOK) {
            DHCP_LOGE("deviceName memcpy_s error!");
            return DHCP_E_FAILED;
        }
        stationInfos.emplace_back(stationInfo);
    }
    OnServerSuccess(ifName, stationInfos);
    reply.WriteInt32(0);
    return 0;
}

int DhcpServreCallBackStub::RemoteOnServerLeasesChanged(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    DHCP_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    reply.WriteInt32(0);
    return 0;
}

int DhcpServreCallBackStub::RemoteOnServerSerExitChanged(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    DHCP_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    reply.WriteInt32(0);
    return 0;
}

}  // namespace DHCP
}  // namespace OHOS
