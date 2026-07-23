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
#include "dhcp_client_callback_stub_lite.h"
#include "dhcp_manager_service_ipc_interface_code.h"
#include "ipc_skeleton.h"
#include "rpc_errno.h"
#include "dhcp_sdk_define.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpClientCallBackStubLite");
namespace OHOS {
namespace DHCP {
DhcpClientCallBackStub::DhcpClientCallBackStub() : callback_(nullptr), mRemoteDied(false)
{
    DHCP_LOGI("Enter DhcpClientCallBackStub");
}

DhcpClientCallBackStub::~DhcpClientCallBackStub()
{
    DHCP_LOGI("Enter ~DhcpClientCallBackStub");
}

int DhcpClientCallBackStub::OnRemoteInterfaceToken(uint32_t code, IpcIo *data)
{
    size_t length;
    uint16_t* interfaceRead = nullptr;
    interfaceRead = ReadInterfaceToken(data, &length);
    if (interfaceRead == nullptr) {
        DHCP_LOGE("ReadInterfaceToken failed!");
        return DHCP_OPT_FAILED;
    }
    for (size_t i = 0; i < length; i++) {
        if (i >= DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH || interfaceRead[i] != DECLARE_INTERFACE_DESCRIPTOR_L1[i]) {
            DHCP_LOGE("Sta stub token verification error: %{public}d", code);
            return DHCP_OPT_FAILED;
        }
    }
    return DHCP_OPT_SUCCESS;
}

int DhcpClientCallBackStub::OnRemoteRequest(uint32_t code, IpcIo *data)
{
    int ret = DHCP_OPT_FAILED;
    DHCP_LOGI("OnRemoteRequest code:%{public}u!", code);
    if (mRemoteDied || data == nullptr) {
        DHCP_LOGE("Failed to %{public}s,mRemoteDied:%{public}d data:%{public}d!",
            __func__, mRemoteDied, data == nullptr);
        return ret;
    }

    if (OnRemoteInterfaceToken(code, data) == DHCP_OPT_FAILED) {
        return DHCP_OPT_FAILED;
    }
    int exception = DHCP_OPT_FAILED;
    (void)ReadInt32(data, &exception);
    if (exception) {
        DHCP_LOGE("DhcpClientCallBackStub::OnRemoteRequest, got exception: %{public}d!", exception);
        return ret;
    }
    switch (code) {
        case static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_CBK_CMD_IP_SUCCESS_CHANGE): {
            ret = RemoteOnIpSuccessChanged(code, data);
            break;
        }
        case static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_CBK_CMD_IP_FAIL_CHANGE): {
            ret = RemoteOnIpFailChanged(code, data);
            break;
        }
        default: {
            ret = DHCP_OPT_FAILED;
            break;
        }
    }
    DHCP_LOGI("DhcpClientCallBackStub OnRemoteRequest, ret:%{public}d", ret);
    return ret;
}

void DhcpClientCallBackStub::RegisterCallBack(const std::shared_ptr<IDhcpClientCallBack> &callBack)
{
    if (callBack == nullptr) {
        DHCP_LOGE("DhcpClientCallBackStub:callBack is nullptr!");
        return;
    }
    std::lock_guard<std::mutex> lock(callbackMutex_);
    callback_ = callBack;
}

bool DhcpClientCallBackStub::IsRemoteDied() const
{
    return mRemoteDied;
}

void DhcpClientCallBackStub::SetRemoteDied(bool val)
{
    DHCP_LOGI("DhcpClientCallBackStub::SetRemoteDied, state:%{public}d!", val);
    mRemoteDied = val;
}

void DhcpClientCallBackStub::OnIpSuccessChanged(int status, const std::string& ifname, DhcpResult& result)
{
    DHCP_LOGI("DhcpClientCallBackStub::OnIpSuccessChanged, status:%{public}d!", status);
    std::shared_ptr<IDhcpClientCallBack> tempCallback;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        tempCallback = callback_;
    }
    if (tempCallback) {
        tempCallback->OnIpSuccessChanged(status, ifname, result);
    }
}

void DhcpClientCallBackStub::OnIpFailChanged(int status, const std::string& ifname, const std::string& reason)
{
    DHCP_LOGI("DhcpClientCallBackStub::OnIpFailChanged, status:%{public}d!", status);
    std::shared_ptr<IDhcpClientCallBack> tempCallback;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        tempCallback = callback_;
    }
    if (tempCallback) {
        tempCallback->OnIpFailChanged(status, ifname, reason);
    }
}


int DhcpClientCallBackStub::RemoteOnIpSuccessChanged(uint32_t code, IpcIo *data)
{
    DHCP_LOGI("run %{public}s code %{public}u", __func__, code);
    size_t readLen;
    int state = 0;
    (void)ReadInt32(data, &state);
    char *ifnameStr = static_cast<char *>(ReadString(data, &readLen));
    if (ifnameStr == nullptr) {
        DHCP_LOGE("RemoteOnIpSuccessChanged ReadString failed!");
        return DHCP_OPT_FAILED;
    }
    std::string ifname = ifnameStr;

    DhcpResult result;
    (void)ReadInt32(data, &result.iptype);
    (void)ReadBool(data, &result.isOptSuc);
    (void)ReadUint32(data, &result.uLeaseTime);
    (void)ReadUint32(data, &result.uAddTime);
    (void)ReadUint32(data, &result.uGetTime);
    result.strYourCli = static_cast<char *>(ReadString(data, &readLen));
    result.strServer = static_cast<char *>(ReadString(data, &readLen));
    result.strSubnet = static_cast<char *>(ReadString(data, &readLen));
    result.strDns1 = static_cast<char *>(ReadString(data, &readLen));
    result.strDns2 = static_cast<char *>(ReadString(data, &readLen));
    result.strRouter1 = static_cast<char *>(ReadString(data, &readLen));
    result.strRouter2 = static_cast<char *>(ReadString(data, &readLen));
    result.strVendor = static_cast<char *>(ReadString(data, &readLen));
    result.strLinkIpv6Addr = static_cast<char *>(ReadString(data, &readLen));
    result.strRandIpv6Addr = static_cast<char *>(ReadString(data, &readLen));
    result.strLocalAddr1 = static_cast<char *>(ReadString(data, &readLen));
    result.strLocalAddr2 = static_cast<char *>(ReadString(data, &readLen));
    OnIpSuccessChanged(state, ifname, result);
    return 0;
}

int DhcpClientCallBackStub::RemoteOnIpFailChanged(uint32_t code, IpcIo *data)
{
    DHCP_LOGI("run %{public}s code %{public}u", __func__, code);
    size_t readLen;
    int state = 0;
    (void)ReadInt32(data, &state);
    char *ifnameStr = static_cast<char *>(ReadString(data, &readLen));
    if (ifnameStr == nullptr) {
        DHCP_LOGE("RemoteOnIpFailChanged ifnameStr is nullptr!");
        return DHCP_OPT_FAILED;
    }
    std::string ifname = ifnameStr;
    char *reasonStr = static_cast<char *>(ReadString(data, &readLen));
    if (reasonStr == nullptr) {
        DHCP_LOGE("RemoteOnIpFailChanged reasonStr is nullptr!");
        return DHCP_OPT_FAILED;
    }
    std::string reason = reasonStr;
    OnIpFailChanged(state, ifname, reason);
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS