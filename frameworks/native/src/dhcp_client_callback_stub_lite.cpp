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
namespace Wifi {
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
    if (callback_) {
        callback_->OnIpSuccessChanged(status, ifname, result);
    }
}

void DhcpClientCallBackStub::OnIpFailChanged(int status, const std::string& ifname, const std::string& reason)
{
    DHCP_LOGI("DhcpClientCallBackStub::OnIpFailChanged, status:%{public}d!", status);
    if (callback_) {
        callback_->OnIpFailChanged(status, ifname, reason);
    }
}


int DhcpClientCallBackStub::RemoteOnIpSuccessChanged(uint32_t code, IpcIo *data)
{
    DHCP_LOGI("run %{public}s code %{public}u", __func__, code);
    size_t readLen;
    int state = 0;
    (void)ReadInt32(data, &state);
    std::string ifname = (char *)ReadString(data, &readLen);

    DhcpResult result;
    (void)ReadInt32(data, &result.iptype);
    (void)ReadBool(data, &result.isOptSuc);
    (void)ReadUint32(data, &result.uLeaseTime);
    (void)ReadUint32(data, &result.uAddTime);
    (void)ReadUint32(data, &result.uGetTime);
    result.strYourCli = (char *)ReadString(data, &readLen);
    result.strServer = (char *)ReadString(data, &readLen);
    result.strSubnet = (char *)ReadString(data, &readLen);
    result.strDns1 = (char *)ReadString(data, &readLen);
    result.strDns2 = (char *)ReadString(data, &readLen);
    result.strRouter1 = (char *)ReadString(data, &readLen);
    result.strRouter2 = (char *)ReadString(data, &readLen);
    result.strVendor = (char *)ReadString(data, &readLen);
    result.strLinkIpv6Addr = (char *)ReadString(data, &readLen);
    result.strRandIpv6Addr = (char *)ReadString(data, &readLen);
    OnIpSuccessChanged(state, ifname, result);
    return 0;
}

int DhcpClientCallBackStub::RemoteOnIpFailChanged(uint32_t code, IpcIo *data)
{
    DHCP_LOGI("run %{public}s code %{public}u", __func__, code);
    size_t readLen;
    int state = 0;
    (void)ReadInt32(data, &state);
    std::string ifname = (char *)ReadString(data, &readLen);
    std::string reason = (char *)ReadString(data, &readLen);
    OnIpFailChanged(state, ifname, reason);
    return 0;
}
}  // namespace Wifi
}  // namespace OHOS