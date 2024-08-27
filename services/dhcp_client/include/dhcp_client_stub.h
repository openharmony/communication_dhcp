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

#ifndef OHOS_DHCP_CLIENT_STUB_H
#define OHOS_DHCP_CLIENT_STUB_H

#include <map>
#include <string_ex.h>
#ifndef OHOS_ARCH_LITE
#include "iremote_stub.h"
#include <iremote_broker.h>
#include "message_parcel.h"
#include "message_option.h"
#endif
#include "i_dhcp_client.h"
#include "dhcp_client_callback_stub.h"

namespace OHOS {
namespace DHCP {
class DhcpClientStub : public IRemoteStub<IDhcpClient> {
public:
    using handleFunc = int (DhcpClientStub::*)(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);1
    using HandleFuncMap = std::map<int, handleFunc>;
    using RemoteDeathMap = std::map<sptr<IRemoteObject>, sptr<IRemoteObject::DeathRecipient>>;
    DhcpClientStub();

    virtual ~DhcpClientStub();
    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
private:
    void InitHandleMap(void);
    int OnRegisterCallBack(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnStartDhcpClient(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnSetConfiguration(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnStopDhcpClient(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
#ifndef OHOS_ARCH_LITE
public:
    class ClientDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit ClientDeathRecipient(DhcpClientStub &client) : client_(client) {}
        ~ClientDeathRecipient() override = default;
        virtual void OnRemoteDied(const wptr<IRemoteObject>& remote) override
        {
            client_.OnRemoteDied(remote);
        }
    private:
        DhcpClientStub &client_;
    };
    void OnRemoteDied(const wptr<IRemoteObject> &remoteObject);
    void RemoveDeviceCbDeathRecipient(void);
    void RemoveDeviceCbDeathRecipient(const wptr<IRemoteObject> &remoteObject);

    RemoteDeathMap remoteDeathMap;
    std::mutex mutex_;
#endif
private:
    HandleFuncMap handleFuncMap;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
};
}  // namespace DHCP
}  // namespace OHOS
#endif