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
#include "dhcp_server_stub.h"
#include "dhcp_logger.h"
#include "dhcp_manager_service_ipc_interface_code.h"
#include "dhcp_server_death_recipient.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpServerStub");

namespace OHOS {
namespace DHCP {
DhcpServerStub::DhcpServerStub() : mSingleCallback(false), callback_(nullptr)
{
    InitHandleMap();
}

DhcpServerStub::~DhcpServerStub()
{}

void DhcpServerStub::InitHandleMap()
{1
    handleFuncMap[static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REG_CALL_BACK)] =
        &DhcpServerStub::OnRegisterCallBack;
    handleFuncMap[static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_START_DHCP_SERVER)] =
        &DhcpServerStub::OnStartDhcpServer;
    handleFuncMap[static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_STOP_DHCP_SERVER)] =
        &DhcpServerStub::OnStopDhcpServer;
    handleFuncMap[static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_SET_DHCP_RANGE)] =
        &DhcpServerStub::OnSetDhcpRange;
    handleFuncMap[static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_SET_DHCP_NAME)] =
        &DhcpServerStub::OnSetDhcpName;
    handleFuncMap[static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_PUT_DHCP_RANGE)] =
        &DhcpServerStub::OnPutDhcpRange;
    handleFuncMap[static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REMOVE_ALL_DHCP_RANGE)] =
        &DhcpServerStub::OnRemoveAllDhcpRange;
    handleFuncMap[static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REMOVE_DHCP_RANGE)] =
        &DhcpServerStub::OnRemoveDhcpRange;
    handleFuncMap[static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_UPDATE_RENEW_TIME)] =
        &DhcpServerStub::OnUpdateLeasesTime;
    handleFuncMap[static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_GET_DHCP_CLIENT_INFO)] =
        &DhcpServerStub::OnGetDhcpClientInfos;
}

int DhcpServerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DHCP_LOGI("DhcpServerStub::OnRemoteRequest,code:%{public}u", code);
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        DHCP_LOGE("dhcp server stub token verification error: %{public}d", code);
        return DHCP_OPT_FAILED;
    }
    HandleFuncMap::iterator iter = handleFuncMap.find(code);
    if (iter == handleFuncMap.end()) {
        DHCP_LOGI("not find function to deal, code %{public}u", code);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    } else {
        int exception = data.ReadInt32();
        DHCP_LOGI("server rec, exception:%{public}d", exception);
        if (exception) {
            return DHCP_OPT_FAILED;
        }
        return (this->*(iter->second))(code, data, reply, option);
    }
}

bool DhcpServerStub::IsSingleCallback() const
{
    return mSingleCallback;
}

void DhcpServerStub::SetSingleCallback(const bool isSingleCallback)
{
    mSingleCallback = true;
}

int DhcpServerStub::OnRegisterCallBack(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DHCP_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    sptr<IRemoteObject> remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        DHCP_LOGE("Failed to ReadRemoteObject!");
        return DHCP_OPT_FAILED;
    }
    callback_ = iface_cast<IDhcpServerCallBack>(remote);
    if (callback_ == nullptr) {
        callback_ = new (std::nothrow) DhcpServerCallbackProxy(remote);
        DHCP_LOGI("create new DhcpServerCallbackProxy!");
    }
    DHCP_LOGI("send OnStartDhcpClient data start");
    int pid = data.ReadInt32();
    int tokenId = data.ReadInt32();
    std::string ifName = data.ReadString();
    DHCP_LOGD("%{public}s, get pid: %{public}d, tokenId: %{private}d", __func__, pid, tokenId);

    ErrCode ret = RegisterDhcpServerCallBack(ifName, callback_);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return 0;
}

int DhcpServerStub::OnStartDhcpServer(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DHCP_LOGI("OnStartDhcpServer\n");
    int pid = data.ReadInt32();
    int tokenId = data.ReadInt32();
    std::string ifName = data.ReadString();
    DHCP_LOGD("%{public}s, get pid: %{public}d, tokenId: %{private}d", __func__, pid, tokenId);
    
    ErrCode ret = StartDhcpServer(ifName);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return 0;
}

int DhcpServerStub::OnStopDhcpServer(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DHCP_LOGI("OnStopDhcpServer\n");
    std::string ifName = data.ReadString();
    ErrCode ret = StopDhcpServer(ifName);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return 0;
}

int DhcpServerStub::OnSetDhcpName(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::string tagName = data.ReadString();
    std::string ifname = data.ReadString();
    DHCP_LOGI("OnSetDhcpName ifname = %{public}s\n", ifname.c_str());
    ErrCode ret = SetDhcpName(ifname, tagName);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return 0;
}
int DhcpServerStub::OnSetDhcpRange(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DHCP_LOGI("OnSetDhcpRange\n");
    DhcpRange range;
    range.iptype = data.ReadInt32();
    range.leaseHours = data.ReadInt32();
    range.strTagName = data.ReadString();
    range.strStartip = data.ReadString();
    range.strEndip = data.ReadString();
    range.strSubnet = data.ReadString();
    std::string ifname = data.ReadString();
    ErrCode ret = SetDhcpRange(ifname, range);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return 0;
}
int DhcpServerStub::OnRemoveAllDhcpRange(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DHCP_LOGI("OnRemoveAllDhcpRange\n");
    std::string tagName = data.ReadString();
    ErrCode ret = RemoveAllDhcpRange(tagName);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return 0;
}
int DhcpServerStub::OnRemoveDhcpRange(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DHCP_LOGI("OnRemoveDhcpRange\n");
    DhcpRange range;
    range.iptype = data.ReadInt32();
    range.leaseHours = data.ReadInt32();
    range.strTagName = data.ReadString();
    range.strStartip = data.ReadString();
    range.strEndip = data.ReadString();
    range.strSubnet = data.ReadString();
    std::string tagName = data.ReadString();
    ErrCode ret = RemoveDhcpRange(tagName, range);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return 0;
}
int DhcpServerStub::OnGetDhcpClientInfos(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DHCP_LOGI("OnGetDhcpClientInfos\n");
    std::vector<std::string> leases;
    std::string ifname = data.ReadString();
    ErrCode ret = GetDhcpClientInfos(ifname, leases);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret != DHCP_E_SUCCESS) {
        return ret;
    }
    int size = leases.size();
    DHCP_LOGI("OnGetDhcpClientInfos, reply message size:%{public}d\n", size);
    reply.WriteInt32(size);
    for (auto str : leases) {
        reply.WriteString(str);
    }

    return 0;
}

int DhcpServerStub::OnUpdateLeasesTime(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DHCP_LOGI("OnUpdateLeasesTime\n");
    std::string leaseTime = data.ReadString();
    ErrCode ret = UpdateLeasesTime(leaseTime);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return 0;
}

int DhcpServerStub::OnPutDhcpRange(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    DHCP_LOGI("OnPutDhcpRange\n");
    DhcpRange range;
    range.iptype = data.ReadInt32();
    range.leaseHours = data.ReadInt32();
    range.strTagName = data.ReadString();
    range.strStartip = data.ReadString();
    range.strEndip = data.ReadString();
    range.strSubnet = data.ReadString();
    std::string tagName = data.ReadString();
    ErrCode ret = PutDhcpRange(tagName, range);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return 0;
}
}
}