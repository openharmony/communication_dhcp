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
#include "dhcp_manager_service_ipc_interface_code.h"
#include "ipc_skeleton.h"
#include "rpc_errno.h"
#include "dhcp_logger.h"
#include "dhcp_sdk_define.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpClientCallbackProxyLite");
namespace OHOS {
namespace Wifi {
#ifndef OHOS_EUPDATER
DhcpClientCallbackProxy::DhcpClientCallbackProxy(SvcIdentity *sid) : sid_(*sid)
{}
#endif

DhcpClientCallbackProxy::~DhcpClientCallbackProxy()
{
#ifndef OHOS_EUPDATER
    ReleaseSvc(sid_);
#endif
}

void DhcpClientCallbackProxy::OnIpSuccessChanged(int status, const std::string& ifname, DhcpResult& result)
{
    DHCP_LOGI("DhcpClientCallbackProxy OnIpSuccessChanged status:%{public}d ifname:%{public}s", status, ifname.c_str());
    IpcIo data;
    uint8_t buff[DEFAULT_IPC_SIZE];
    IpcIoInit(&data, buff, DEFAULT_IPC_SIZE, 0);
    if (!WriteInterfaceToken(&data, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    (void)WriteInt32(&data, 0);
    (void)WriteInt32(&data, status);
    (void)WriteString(&data, ifname.c_str());
    (void)WriteInt32(&data,result.iptype);
    (void)WriteBool(&data,result.isOptSuc);
    (void)WriteInt32(&data,result.uLeaseTime);
    (void)WriteInt32(&data,result.uAddTime);
    (void)WriteInt32(&data,result.uGetTime);
    (void)WriteString(&data,result.strYourCli.c_str());
    (void)WriteString(&data,result.strServer.c_str());
    (void)WriteString(&data,result.strSubnet.c_str());
    (void)WriteString(&data,result.strDns1.c_str());
    (void)WriteString(&data,result.strDns2.c_str());
    (void)WriteString(&data,result.strRouter1.c_str());
    (void)WriteString(&data,result.strRouter2.c_str());
    (void)WriteString(&data,result.strVendor.c_str());
    (void)WriteString(&data,result.strLinkIpv6Addr.c_str());
    (void)WriteString(&data,result.strRandIpv6Addr.c_str());

    IpcIo reply;
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
#ifndef OHOS_EUPDATER
    int ret = SendRequest(sid_, static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_CBK_CMD_IP_SUCCESS_CHANGE), &data, &reply,
        option, nullptr);
    if (ret != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_CBK_CMD_IP_SUCCESS_CHANGE), ret);
    }
#endif
    DHCP_LOGI("OnIpSuccessChanged request success");
    return;
}

void DhcpClientCallbackProxy::OnIpFailChanged(int status, const std::string& ifname, const std::string& reason)
{
    DHCP_LOGI("DhcpClientCallbackProxy OnIpFailChanged status:%{public}d ifname:%{public}s", status, ifname.c_str());
    IpcIo data;
    uint8_t buff[DEFAULT_IPC_SIZE];
    IpcIoInit(&data, buff, DEFAULT_IPC_SIZE, 0);
    if (!WriteInterfaceToken(&data, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    (void)WriteInt32(&data, 0);
    (void)WriteInt32(&data, status);
    (void)WriteString(&data, ifname.c_str());
    (void)WriteString(&data, reason.c_str());
    
    IpcIo reply;
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
#ifndef OHOS_EUPDATER
    int ret = SendRequest(sid_, static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_CBK_CMD_IP_FAIL_CHANGE), &data, &reply,
        option, nullptr);
    if (ret != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_CBK_CMD_IP_FAIL_CHANGE), ret);
    }
#endif
    DHCP_LOGI("DhcpClientCallbackProxy OnIpFailChanged send client request success");
    return;
}
}  // namespace Wifi
}  // namespace OHOS
