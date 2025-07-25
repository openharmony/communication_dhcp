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
#include "serverstub_fuzzer.h"
#include "message_parcel.h"
#include "securec.h"
#include "dhcp_server_service_impl.h"
#include "dhcp_server_stub.h"
#include "dhcp_manager_service_ipc_interface_code.h"
#include "dhcp_fuzz_common_func.h"

namespace OHOS {
namespace DHCP {
constexpr size_t U32_AT_SIZE_ZERO = 4;
constexpr size_t MAP_SCAN_NUMS = 12;
constexpr size_t DHCP_SLEEP_1 = 2;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IDhcpServer";
sptr<DhcpServerStub> pDhcpServerStub = DhcpServerServiceImpl::GetInstance();

void OnGetSupportedFeaturesTest(const uint8_t* data, size_t size)
{
    uint32_t code = U32_AT(data) % MAP_SCAN_NUMS + static_cast<uint32_t>
    (DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REG_CALL_BACK);
    if (code == static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_GET_SERVER_STATUS) ||
        code ==  static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_GET_IP_LIST)) {
        return;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pDhcpServerStub->OnRemoteRequest(code, datas, reply, option);
}

void OnRegisterCallBackTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pDhcpServerStub->OnRemoteRequest(static_cast<uint32_t>
        (DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REG_CALL_BACK), datas, reply, option);
}

void OnStopDhcpServerTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pDhcpServerStub->OnRemoteRequest(static_cast<uint32_t>
        (DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_STOP_DHCP_SERVER), datas, reply, option);
}

void OnSetDhcpNameTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pDhcpServerStub->OnRemoteRequest(static_cast<uint32_t>
        (DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_SET_DHCP_NAME), datas, reply, option);
}

void OnSetDhcpRangeTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pDhcpServerStub->OnRemoteRequest(static_cast<uint32_t>
        (DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_SET_DHCP_RANGE), datas, reply, option);
}

void OnRemoveAllDhcpRangeTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pDhcpServerStub->OnRemoteRequest(static_cast<uint32_t>
        (DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REMOVE_ALL_DHCP_RANGE), datas, reply, option);
}

void OnRemoveDhcpRangeTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pDhcpServerStub->OnRemoteRequest(static_cast<uint32_t>
        (DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REMOVE_DHCP_RANGE), datas, reply, option);
}

void OnGetDhcpClientInfosTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pDhcpServerStub->OnRemoteRequest(static_cast<uint32_t>
        (DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_GET_DHCP_CLIENT_INFO), datas, reply, option);
}

void OnUpdateLeasesTimeTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pDhcpServerStub->OnRemoteRequest(static_cast<uint32_t>
        (DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_UPDATE_RENEW_TIME), datas, reply, option);
}

void OnPutDhcpRangeTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pDhcpServerStub->OnRemoteRequest(static_cast<uint32_t>
        (DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_PUT_DHCP_RANGE), datas, reply, option);
}

#define TWO 2
void SingleCallbackTest(const uint8_t* data, size_t size)
{
    bool isSingleCallback = (static_cast<int>(data[0]) % TWO) ? true : false;
    pDhcpServerStub->IsSingleCallback();
    pDhcpServerStub->SetSingleCallback(isSingleCallback);
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::DHCP::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    sleep(DHCP_SLEEP_1);
    OHOS::DHCP::OnGetSupportedFeaturesTest(data, size);
    OHOS::DHCP::OnRegisterCallBackTest(data, size);
    OHOS::DHCP::OnStopDhcpServerTest(data, size);
    OHOS::DHCP::OnSetDhcpNameTest(data, size);
    OHOS::DHCP::OnSetDhcpRangeTest(data, size);
    OHOS::DHCP::OnRemoveAllDhcpRangeTest(data, size);
    OHOS::DHCP::OnRemoveDhcpRangeTest(data, size);
    OHOS::DHCP::OnGetDhcpClientInfosTest(data, size);
    OHOS::DHCP::OnUpdateLeasesTimeTest(data, size);
    OHOS::DHCP::OnPutDhcpRangeTest(data, size);
    OHOS::DHCP::SingleCallbackTest(data, size);
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS
