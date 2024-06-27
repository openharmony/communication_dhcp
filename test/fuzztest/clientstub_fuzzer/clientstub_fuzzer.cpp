/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "clientstub_fuzzer.h"
#include "message_parcel.h"
#include "securec.h"
#include "dhcp_client_service_impl.h"
#include "dhcp_client_stub.h"
#include "dhcp_manager_service_ipc_interface_code.h"
#include "dhcp_fuzz_common_func.h"

namespace OHOS {
namespace DHCP {
constexpr size_t U32_AT_SIZE_ZERO = 4;
constexpr size_t DHCP_SLEEP_1 = 2;
constexpr size_t DHCP_SLEEP_2 = 4;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IDhcpClient";
sptr<DhcpClientStub> pDhcpClientStub = DhcpClientServiceImpl::GetInstance();
static sptr<DhcpClientCallBackStub> g_dhcpClientCallBackStub =
    sptr<DhcpClientCallBackStub>(new (std::nothrow)DhcpClientCallBackStub());

void OnRegisterCallBackTest(const std::string& ifname, size_t size)
{
    uint32_t code = static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_REG_CALL_BACK);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteRemoteObject(g_dhcpClientCallBackStub->AsObject());
    datas.WriteString(ifname);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pDhcpClientStub->OnRemoteRequest(code, datas, reply, option);
}

void OnStartDhcpClientTest(const std::string& ifname, size_t size, bool ipv6)
{
    uint32_t code = static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_START_DHCP_CLIENT);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteString(ifname);
    datas.WriteBool(ipv6);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pDhcpClientStub->OnRemoteRequest(code, datas, reply, option);
}

void OnStopDhcpClientTest(const std::string& ifname, size_t size, bool ipv6)
{
    uint32_t code = static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_STOP_DHCP_CLIENT);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteString(ifname);
    datas.WriteBool(ipv6);
    MessageParcel reply;
    MessageOption option;
    pDhcpClientStub->OnRemoteRequest(code, datas, reply, option);
}

void OnSetConfigurationTest(const std::string& ifname)
{
    uint32_t code = static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_SET_CONFIG);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteString(ifname);
    datas.WriteString("bssid");
    MessageParcel reply;
    MessageOption option;
    pDhcpClientStub->OnRemoteRequest(code, datas, reply, option);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::DHCP::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    std::string ifname = "wlan0";
    OnRegisterCallBackTest(ifname, size);
    sleep(DHCP_SLEEP_1);
    OnSetConfigurationTest(ifname);
    sleep(DHCP_SLEEP_1);
    OnStartDhcpClientTest(ifname, size, false); // max 18s timeout
    sleep(DHCP_SLEEP_2);
    OnStopDhcpClientTest(ifname, size, false);
    sleep(DHCP_SLEEP_1);
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS
