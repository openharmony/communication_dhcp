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
#include "dhcp_logger.h"
#include "dhcp_manager_service_ipc_interface_code.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpClientCallbackProxy");

namespace OHOS {
namespace DHCP {
DhcpClientCallbackProxy::DhcpClientCallbackProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IDhcpClientCallBack>(impl)
{}

DhcpClientCallbackProxy::~DhcpClientCallbackProxy()
{}

void DhcpClientCallbackProxy::WriteDhcpResult(const DhcpResult& result, MessageParcel &data)
{
    data.WriteInt32(result.iptype);
    data.WriteBool(result.isOptSuc);
    data.WriteInt32(result.uLeaseTime);
    data.WriteInt32(result.uAddTime);
    data.WriteInt32(result.uGetTime);
    data.WriteString(result.strYourCli);
    data.WriteString(result.strServer);
    data.WriteString(result.strSubnet);
    data.WriteString(result.strDns1);
    data.WriteString(result.strDns2);
    data.WriteString(result.strRouter1);
    data.WriteString(result.strRouter2);
    data.WriteString(result.strVendor);
    data.WriteString(result.strLinkIpv6Addr);
    data.WriteString(result.strRandIpv6Addr);
    data.WriteString(result.strLocalAddr1);
    data.WriteString(result.strLocalAddr2);
    data.WriteInt32(static_cast<int32_t>(result.vectorDnsAddr.size()));
    for (auto &dns : result.vectorDnsAddr) {
        data.WriteString(dns);
    }
    // Serialize all IPv6 addresses and types
    data.WriteInt32(static_cast<int32_t>(result.IpAddrMap.size()));
    for (const auto &kv : result.IpAddrMap) {
        data.WriteString(kv.first);
        data.WriteInt32(kv.second);
    }
}

void DhcpClientCallbackProxy::OnIpSuccessChanged(int status, const std::string& ifname, DhcpResult& result)
{
    DHCP_LOGI("WifiDeviceCallBackProxy::OnIpSuccessChanged");
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DHCP_LOGE("Remote is null");
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(status);
    data.WriteString(ifname);
    WriteDhcpResult(result, data);
    int error = remote->SendRequest(
        static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_CBK_CMD_IP_SUCCESS_CHANGE), data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_CBK_CMD_IP_SUCCESS_CHANGE), error);
        return;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGE("notify wifi state change failed!");
    }
    DHCP_LOGI("send client request success");
    return;
}

void DhcpClientCallbackProxy::OnIpFailChanged(int status, const std::string& ifname, const std::string& reason)
{
    DHCP_LOGI("DhcpClientCallbackProxy OnIpFailChanged status:%{public}d ifname:%{public}s", status, ifname.c_str());
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DHCP_LOGE("Remote is null");
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(status);
    data.WriteString(ifname);
    data.WriteString(reason);
    int error = remote->SendRequest(
        static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_CBK_CMD_IP_FAIL_CHANGE), data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_CBK_CMD_IP_FAIL_CHANGE), error);
        return;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGE("notify wifi state change failed!");
        return;
    }
    DHCP_LOGI("DhcpClientCallbackProxy OnIpFailChanged send client request success");
    return;
}

void DhcpClientCallbackProxy::OnDhcpOfferReport(int status, const std::string& ifname, DhcpResult& result)
{
    DHCP_LOGI("WifiDeviceCallBackProxy::OnDhcpOfferReport");
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        DHCP_LOGE("Remote is null");
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(status);
    data.WriteString(ifname);
    WriteDhcpResult(result, data);
    int error = remote->SendRequest(static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_CBK_CMD_DHCP_OFFER),
        data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_CBK_CMD_DHCP_OFFER), error);
        return;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGE("notify wifi dhcp offer failed!");
    }
    return;
}
}  // namespace DHCP
}  // namespace OHOS
