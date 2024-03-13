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

#include "dhcpservercbkstub_fuzzer.h"
#include "../../../interfaces/inner_api/dhcp_client.h"
#include "../../include/dhcp_event.h"
#include "dhcp_manager_service_ipc_interface_code.h"
#include "../../../frameworks/native/src/dhcp_server_callback_stub.h"
#include "dhcp_fuzz_common_func.h"


namespace OHOS {
namespace Wifi {
constexpr size_t U32_AT_SIZE_ZERO = 4;
constexpr size_t MAP_SCAN_NUMS = 5;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IDhcpServerCallBack";
std::shared_ptr<DhcpServreCallBackStub> pDhcpServerCbkStub = std::make_shared<DhcpServreCallBackStub>();

void OnGetSupportedFeaturesTest(const uint8_t* data, size_t size)
{
    uint32_t code = u32_AT(data) % MAP_SCAN_NUMS + static_cast<uint32_t>
    (DhcpServerInterfaceCode::DHCP_SERVER_CBK_SERVER_STATUS_CHANGE);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pDhcpClientCbkStub->OnRemoteRequest(code, datas, reply, option);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    OHOS::Wifi::OnGetSupportedFeaturesTest(data, size);
    return 0;
}
}  // namespace Wifi
}  // namespace OHOS

