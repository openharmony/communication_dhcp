/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_DHCP_SERVER_STUB_H
#define OHOS_DHCP_SERVER_STUB_H

#include <map>
#ifndef OHOS_ARCH_LITE
#include "iremote_stub.h"
#include <iremote_broker.h>
#include "message_parcel.h"
#include "message_option.h"
#endif
#include "i_dhcp_server.h"

namespace OHOS {
namespace DHCP {
class DhcpServerStub : public IRemoteStub<IDhcpServer> {
public:
    using handleFunc = std::function<int(uint32_t &, MessageParcel &, MessageParcel &, MessageOption &)>;
    using HandleFuncMap = std::map<int, handleFunc>;
    DhcpServerStub();

    virtual ~DhcpServerStub();

    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

    bool IsSingleCallback() const;
    void SetSingleCallback(const bool isSingleCallback);

    int OnRegisterCallBack(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnStartDhcpServer(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnStopDhcpServer(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnUpdateDhcpRange(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnSetDhcpName(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnSetDhcpRange(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnRemoveAllDhcpRange(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnRemoveDhcpRange(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnGetDhcpClientInfos(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnUpdateLeasesTime(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnPutDhcpRange(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

private:
    void InitHandleMap(void);

private:
    HandleFuncMap handleFuncMap;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
    bool mSingleCallback;
    sptr<IDhcpServerCallBack> callback_;
};
}  // namespace DHCP
}  // namespace OHOS
#endif