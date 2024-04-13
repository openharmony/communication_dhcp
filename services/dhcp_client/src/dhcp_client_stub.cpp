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
#include "dhcp_client_callback_proxy.h"
#include "dhcp_client_stub.h"
#include "dhcp_logger.h"
#include "dhcp_manager_service_ipc_interface_code.h"
#include "dhcp_client_state_machine.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpClientStub");

namespace OHOS {
namespace DHCP {
DhcpClientStub::DhcpClientStub()
{
    InitHandleMap();
}

DhcpClientStub::~DhcpClientStub()
{
    DHCP_LOGI("enter ~DhcpClientStub!");
}

#ifndef OHOS_ARCH_LITE
void DhcpClientStub::RemoveDeviceCbDeathRecipient(void)
{
    DHCP_LOGI("enter RemoveDeathRecipient!");
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto iter = remoteDeathMap.begin(); iter != remoteDeathMap.end(); ++iter) {
        iter->first->RemoveDeathRecipient(iter->second);
        remoteDeathMap.erase(iter);
    }
}

void DhcpClientStub::RemoveDeviceCbDeathRecipient(const wptr<IRemoteObject> &remoteObject)
{
    DHCP_LOGI("RemoveDeathRecipient, remoteObject: %{private}p!", &remoteObject);
    std::lock_guard<std::mutex> lock(mutex_);
    RemoteDeathMap::iterator iter = remoteDeathMap.find(remoteObject.promote());
    if (iter == remoteDeathMap.end()) {
        DHCP_LOGI("not find remoteObject to deal!");
    } else {
        remoteObject->RemoveDeathRecipient(iter->second);
        remoteDeathMap.erase(iter);
        DHCP_LOGI("remove death recipient success!");
    }
}

void DhcpClientStub::OnRemoteDied(const wptr<IRemoteObject> &remoteObject)
{
    DHCP_LOGI("OnRemoteDied, Remote is died! remoteObject: %{private}p", &remoteObject);
    RemoveDeviceCbDeathRecipient(remoteObject);
}
#endif

void DhcpClientStub::InitHandleMap()
{
    handleFuncMap[static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_REG_CALL_BACK)] =
        &DhcpClientStub::OnRegisterCallBack;
    handleFuncMap[static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_START_DHCP_CLIENT)] =
        &DhcpClientStub::OnStartDhcpClient;
    handleFuncMap[static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_STOP_DHCP_CLIENT)] =
        &DhcpClientStub::OnStopDhcpClient;
    handleFuncMap[static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_RENEW_DHCP_CLIENT)] =
        &DhcpClientStub::OnRenewDhcpClient;
}

int DhcpClientStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        DHCP_LOGE("dhcp client stub token verification error: %{public}d", code);
        return DHCP_OPT_FAILED;
    }
    int exception = data.ReadInt32();
    if (exception) {
        DHCP_LOGI("exception is ture, return failed");
        reply.WriteInt32(0);
        return DHCP_OPT_FAILED;
    }
    HandleFuncMap::iterator iter = handleFuncMap.find(code);
    if (iter == handleFuncMap.end()) {
        DHCP_LOGI("not find function to deal, code %{public}u", code);
        reply.WriteInt32(0);
        reply.WriteInt32(2);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    } else {
        return (this->*(iter->second))(code, data, reply, option);
    }
}

int DhcpClientStub::OnRegisterCallBack(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DHCP_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    sptr<IRemoteObject> remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        DHCP_LOGE("Failed to ReadRemoteObject!");
        return DHCP_E_INVALID_PARAM; 
    }
    sptr<IDhcpClientCallBack> callback_ = iface_cast<IDhcpClientCallBack>(remote);
    if (callback_ == nullptr) {
        callback_ = new (std::nothrow) DhcpClientCallbackProxy(remote);
        DHCP_LOGI("create new DhcpClientCallbackProxy!");
    }
    std::string ifName = data.ReadString();
    if (deathRecipient_ == nullptr) {
#ifdef OHOS_ARCH_LITE
        deathRecipient_ = new (std::nothrow) DhcpClientDeathRecipient();
#else
        deathRecipient_ = new (std::nothrow) ClientDeathRecipient(*this);
        remoteDeathMap.insert(std::make_pair(remote, deathRecipient_));
#endif
    }
    ErrCode ret = RegisterDhcpClientCallBack(ifName, callback_);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return 0;
}

int DhcpClientStub::OnStartDhcpClient(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DHCP_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::string ifname = data.ReadString();
    bool bIpv6 = data.ReadBool();
    ErrCode ret = StartDhcpClient(ifname, bIpv6);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return 0;
}

int DhcpClientStub::OnStopDhcpClient(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DHCP_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::string ifname = data.ReadString();
    bool bIpv6 = data.ReadBool();
    ErrCode ret = StopDhcpClient(ifname, bIpv6);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return 0;
}

int DhcpClientStub::OnRenewDhcpClient(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DHCP_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::string ifName = data.ReadString();
    ErrCode ret = RenewDhcpClient(ifName);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return 0;
}

}
}
