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
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <sys/time.h>
#include <cerrno>
#include <csignal>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <string>
#include "clientstub_fuzzer.h"
#include "message_parcel.h"
#include "securec.h"
#include "dhcp_client_service_impl.h"
#include "dhcp_client_stub.h"
#include "dhcp_manager_service_ipc_interface_code.h"
#include "dhcp_fuzz_common_func.h"
#include "dhcp_ipv6_client.h"
#include "dhcp_client_callback_stub.h"
#include "dhcp_logger.h"

namespace OHOS {
namespace DHCP {
constexpr size_t U32_AT_SIZE_ZERO = 4;
constexpr int THREE = 2;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IDhcpClient";
sptr<DhcpClientStub> pDhcpClientStub = DhcpClientServiceImpl::GetInstance();
static sptr<DhcpClientCallBackStub> g_dhcpClientCallBackStub =
    sptr<DhcpClientCallBackStub>(new (std::nothrow)DhcpClientCallBackStub());
std::shared_ptr<DhcpClientServiceImpl> pDhcpClientServiceImpl = std::make_shared<DhcpClientServiceImpl>();
static std::unique_ptr<DhcpIpv6Client> ipv6Client = std::make_unique<DhcpIpv6Client>("wlan0");

void OnRegisterCallBackTest(const std::string& ifname, size_t size)
{
    uint32_t code = static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_REG_CALL_BACK);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    if (!datas.WriteRemoteObject(g_dhcpClientCallBackStub->AsObject())) {
        return;
    }
    datas.WriteString(ifname);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pDhcpClientStub->OnRemoteRequest(code, datas, reply, option);
}

void OnStartDhcpClientTest(const std::string& ifname, size_t size, bool ipv6, const uint8_t* data)
{
    uint32_t code = static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_START_DHCP_CLIENT);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteString(ifname);
    datas.WriteString(std::string(reinterpret_cast<const char*>(data), size));
    datas.WriteBool(ipv6);
    datas.WriteBool(ipv6);
    datas.WriteBool(static_cast<int>(data[0]) % THREE);
    datas.RewindRead(0);
    ipv6Client->runFlag_ = true;
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

void OnStopClientSaTest(const uint8_t* data, size_t size)
{
    uint32_t code = static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_STOP_SA);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pDhcpClientStub->OnRemoteRequest(code, datas, reply, option);
}

void OnDealWifiDhcpCacheTest(const uint8_t* data, size_t size)
{
    uint32_t code = static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_DEAL_DHCP_CACHE);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pDhcpClientStub->OnRemoteRequest(code, datas, reply, option);
}

void IsGlobalIPv6AddressTest(const uint8_t* data, size_t size)
{
    std::string ipAddress = std::string(reinterpret_cast<const char*>(data), size);
    pDhcpClientServiceImpl->IsGlobalIPv6Address(ipAddress);
}

void DhcpOfferResultSuccessTest(const uint8_t* data, size_t size)
{
    std::string ipAddress = std::string(reinterpret_cast<const char*>(data), size);
    struct DhcpIpResult ipResult;
    struct DhcpIpv6Info info;
    ipResult.ifname = ipAddress;
    ipResult.uAddTime = static_cast<uint32_t>(data[0]);
    pDhcpClientServiceImpl->DhcpOfferResultSuccess(ipResult);
    pDhcpClientServiceImpl->DhcpIpv4ResultSuccess(ipResult);
    pDhcpClientServiceImpl->DhcpIpv4ResultFail(ipResult);
    pDhcpClientServiceImpl->DhcpIpv4ResultExpired(ipAddress);
    pDhcpClientServiceImpl->DhcpIpv6ResulCallback(ipAddress, info);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::DHCP::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    std::string ifname = "wlan0";
    OnRegisterCallBackTest(ifname, size);
    OnStartDhcpClientTest(ifname, size, false, data);
    OnStopDhcpClientTest(ifname, size, false);
    OnDealWifiDhcpCacheTest(data, size);
    DhcpOfferResultSuccessTest(data, size);
    OnStopClientSaTest(data, size);
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS