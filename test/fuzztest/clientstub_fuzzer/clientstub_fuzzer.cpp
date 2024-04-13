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
constexpr size_t MAP_SCAN_NUMS = 10;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IDhcpClient";
sptr<DhcpClientStub> pDhcpClientStub = DhcpClientServiceImpl::GetInstance();

void OnGetSupportedFeaturesTest(const uint8_t* data, size_t size)
{
    uint32_t code = U32_AT(data) % MAP_SCAN_NUMS + static_cast<uint32_t>
    (DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_REG_CALL_BACK);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
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
    OHOS::DHCP::OnGetSupportedFeaturesTest(data, size);
    // duliqun
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS
