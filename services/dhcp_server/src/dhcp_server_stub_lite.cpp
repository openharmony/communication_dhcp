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
#include "dhcp_server_stub_lite.h"
#include "dhcp_logger.h"
#include "dhcp_manager_service_ipc_interface_code.h"
#include "dhcp_sdk_define.h"
#include "ipc_skeleton.h"
#include "rpc_errno.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpServerStubLite");

namespace OHOS {
namespace DHCP {
DhcpServerStub::DhcpServerStub()
{
}

DhcpServerStub::~DhcpServerStub()
{}

int DhcpServerStub::CheckInterfaceToken(uint32_t code, IpcIo *req)
{
    size_t length;
    uint16_t* interfaceRead = nullptr;
    interfaceRead = ReadInterfaceToken(req, &length);
    if (length > DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH) {
        DHCP_LOGE("Scan stub token length too large");
        return DHCP_E_FAILED;
    }
    for (size_t i = 0; i < length; i++) {
        if (i >= DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH ||interfaceRead[i] != DECLARE_INTERFACE_DESCRIPTOR_L1[i]) {
            DHCP_LOGE("Scan stub token verification error: %{public}d", code);
            return DHCP_E_FAILED;
        }
    }
    return DHCP_E_SUCCESS;
}

int DhcpServerStub::OnRemoteRequest(uint32_t code, IpcIo *req, IpcIo *reply)
{
    DHCP_LOGD("DhcpServerStub::OnRemoteRequest,code:%{public}u", code);
    if (req == nullptr || reply == nullptr) {
        DHCP_LOGE("req:%{public}d, reply:%{public}d", req == nullptr, reply == nullptr);
        return DHCP_E_FAILED;
    }
    if (CheckInterfaceToken(code, req) == DHCP_E_FAILED) {
        return DHCP_E_FAILED;
    }
    int exception = DHCP_E_FAILED;
    (void)ReadInt32(req, &exception);
    if (exception) {
        return DHCP_E_FAILED;
    }

    int ret = -1;
    switch (code) {
        case static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REG_CALL_BACK): {
            ret = OnRegisterCallBack(code, req, reply);
            break;
        }
        case static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_START_DHCP_SERVER): {
            ret = OnStartDhcpServer(code, req, reply);
            break;
        }
        case static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_STOP_DHCP_SERVER): {
            ret = OnStopDhcpServer(code, req, reply);
            break;
        }
        default: {
            ret = -1;
        }
    }
    return ret;
}

int DhcpServerStub::OnRegisterCallBack(uint32_t code, IpcIo *req, IpcIo *reply)
{
    DHCP_LOGD("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = DHCP_E_FAILED;
    size_t readLen;
    SvcIdentity sid;
    bool readSid = ReadRemoteObject(req, &sid);
    if (!readSid) {
        DHCP_LOGE("read SvcIdentity failed");
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, ret);
        return ret;
    }

    std::shared_ptr<IDhcpServerCallBack> callback_ = std::make_shared<DhcpServerCallbackProxy>(&sid);
    DHCP_LOGD("create new DhcpServerCallbackProxy!");
    const char* rawStr = ReadString(req, &readLen);
    if (rawStr == nullptr) {
        DHCP_LOGE("OnRegisterCallBack ReadString failed");
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, ret);
        return ret;
    }
    std::string ifName = rawStr;

    ret = RegisterDhcpServerCallBack(ifName, callback_);

    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
    return 0;
}

int DhcpServerStub::OnStartDhcpServer(uint32_t code, IpcIo *req, IpcIo *reply)
{
    DHCP_LOGI("OnStartDhcpServer\n");
    size_t readLen;
    int pid;
    int tokenId;
    (void)ReadInt32(req, &pid);
    (void)ReadInt32(req, &tokenId);
    std::string ifName = (char *)ReadString(req, &readLen);
    DHCP_LOGD("%{public}s, get pid: %{public}d, tokenId: %{private}d", __func__, pid, tokenId);
    
    ErrCode ret = StartDhcpServer(ifName);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);

    return 0;
}

int DhcpServerStub::OnStopDhcpServer(uint32_t code, IpcIo *req, IpcIo *reply)
{
    DHCP_LOGI("OnStopDhcpServer\n");
    size_t readLen;
    const char* rawStr = ReadString(req, &readLen);
    if (rawStr == nullptr) {
        DHCP_LOGE("OnStopDhcpServer ReadString failed");
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, DHCP_E_FAILED);
        return DHCP_E_FAILED;
    }
    std::string ifName = rawStr;
    ErrCode ret = StopDhcpServer(ifName);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);

    return 0;
}

int DhcpServerStub::OnSetDhcpName(uint32_t code, IpcIo *req, IpcIo *reply)
{
    size_t readLen;
    const char* rawTagName = ReadString(req, &readLen);
    if (rawTagName == nullptr) {
        DHCP_LOGE("OnSetDhcpName ReadString tagName failed");
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, DHCP_E_FAILED);
        return DHCP_E_FAILED;
    }
    std::string tagName = rawTagName;
    const char* rawIfName = ReadString(req, &readLen);
    if (rawIfName == nullptr) {
        DHCP_LOGE("OnSetDhcpName ReadString ifName failed");
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, DHCP_E_FAILED);
        return DHCP_E_FAILED;
    }
    std::string ifName = rawIfName;
    ErrCode ret = SetDhcpName(ifName, tagName);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);

    return 0;
}
int DhcpServerStub::OnSetDhcpRange(uint32_t code, IpcIo *req, IpcIo *reply)
{
    DHCP_LOGI("OnSetDhcpRange\n");
    DhcpRange range;
    size_t readLen;
    (void)ReadInt32(req, &range.iptype);
    (void)ReadInt32(req, &range.leaseHours);
    const char* rawTagName = ReadString(req, &readLen);
    const char* rawStartip = ReadString(req, &readLen);
    const char* rawEndip = ReadString(req, &readLen);
    const char* rawSubnet = ReadString(req, &readLen);
    const char* rawIfname = ReadString(req, &readLen);
    if (rawTagName == nullptr || rawStartip == nullptr || rawEndip == nullptr || strSubnet == nullptr) {
        DHCP_LOGE("OnSetDhcpRange ReadString failed");
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, DHCP_E_FAILED);
        return DHCP_E_FAILED;
    }
    range.strTagName = rawTagName;
    range.strStartip = rawStartip;
    range.strEndip = rawEndip;
    range.strSubnet = rawSubnet;
    const char* rawIfname = ReadString(req, &readLen);
    if (rawIfname == nullptr) {
        DHCP_LOGE("OnSetDhcpRange ReadString ifname failed");
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, DHCP_E_FAILED);
        return DHCP_E_FAILED;
    }
    std::string ifname = rawIfname;
    ErrCode ret = SetDhcpRange(ifname, range);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
 
    return 0;
}
int DhcpServerStub::OnRemoveAllDhcpRange(uint32_t code, IpcIo *req, IpcIo *reply)
{
    DHCP_LOGI("OnRemoveAllDhcpRange\n");
    size_t readLen;
    const char* rawTagName = ReadString(req, &readLen);
    if (rawTagName == nullptr) {
        DHCP_LOGE("OnRemoveAllDhcpRange ReadString failed");
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, DHCP_E_FAILED);
        return DHCP_E_FAILED;
    }
    std::string tagName = rawTagName;
    ErrCode ret = RemoveAllDhcpRange(tagName);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
 
    return 0;
}
int DhcpServerStub::OnRemoveDhcpRange(uint32_t code, IpcIo *req, IpcIo *reply)
{
    DHCP_LOGI("OnRemoveDhcpRange\n");
    DhcpRange range;
    size_t readLen;
    (void)ReadInt32(req, &range.iptype);
    (void)ReadInt32(req, &range.leaseHours);
    const char* rawTagName = ReadString(req, &readLen);
    const char* rawStartip = ReadString(req, &readLen);
    const char* rawEndip = ReadString(req, &readLen);
    const char* rawSubnet = ReadString(req, &readLen);
    const char* rawIfname = ReadString(req, &readLen);
    if (rawTagName == nullptr || rawStartip == nullptr || rawEndip == nullptr || strSubnet == nullptr) {
        DHCP_LOGE("OnRemoveDhcpRange ReadString failed");
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, DHCP_E_FAILED);
        return DHCP_E_FAILED;
    }
    range.strTagName = rawTagName;
    range.strStartip = rawStartip;
    range.strEndip = rawEndip;
    range.strSubnet = rawSubnet;
    const char* rawTagName2 = ReadString(req, &readLen);
    if (rawTagName2 == nullptr) {
        DHCP_LOGE("OnRemoveDhcpRange ReadString tagName2 failed");
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, DHCP_E_FAILED);
        return DHCP_E_FAILED;
    }
    std::string tagName = rawTagName2;
 
    ErrCode ret = RemoveDhcpRange(tagName, range);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);

    return 0;
}
int DhcpServerStub::OnGetDhcpClientInfos(uint32_t code, IpcIo *req, IpcIo *reply)
{
    DHCP_LOGI("OnGetDhcpClientInfos\n");
    size_t readLen;
    std::vector<std::string> leases;
    const char* rawIfname = ReadString(req, &readLen);
    if (rawIfname == nullptr) {
        DHCP_LOGE("OnGetDhcpClientInfos ReadString failed");
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, DHCP_E_FAILED);
        return DHCP_E_FAILED;
    }
    std::string ifname = rawIfname;
    ErrCode ret = GetDhcpClientInfos(ifname, leases);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
    if (ret != DHCP_E_SUCCESS) {
        return ret;
    }
    int size = leases.size();
    DHCP_LOGI("OnGetDhcpClientInfos, reply message size:%{public}d\n", size);
    (void)WriteInt32(reply, size);
    for (auto str : leases) {
        (void)WriteString(reply, str.c_str());
    }
 
    return 0;
}

int DhcpServerStub::OnUpdateLeasesTime(uint32_t code, IpcIo *req, IpcIo *reply)
{
    DHCP_LOGI("OnUpdateLeasesTime\n");
    size_t readLen;
    const char* rawStr = ReadString(req, &readLen);
    const char* rawStr = ReadString(req, &readLen);
    if (rawStr == nullptr) {
        DHCP_LOGE("OnRegisterCallBack ReadString failed");
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, ret);
        return ret;
    }
    std::string ifName = rawStr;
    ErrCode ret = UpdateLeasesTime(leaseTime);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
 
    return 0;
}

int DhcpServerStub::OnPutDhcpRange(uint32_t code, IpcIo *req, IpcIo *reply)
{
    DHCP_LOGI("OnPutDhcpRange\n");
    DhcpRange range;
    size_t readLen;
    (void)ReadInt32(req, &range.iptype);
    (void)ReadInt32(req, &range.leaseHours);
    range.strTagName = (char *)ReadString(req, &readLen);
    range.strStartip = (char *)ReadString(req, &readLen);
    range.strEndip = (char *)ReadString(req, &readLen);
    range.strSubnet = (char *)ReadString(req, &readLen);
    std::string tagName = (char *)ReadString(req, &readLen);

    ErrCode ret = PutDhcpRange(tagName, range);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);

    return 0;
}

}
}