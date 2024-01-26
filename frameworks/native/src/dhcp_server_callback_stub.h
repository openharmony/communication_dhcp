/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#ifndef OHOS_DHCP_SERVER_CALLBACK_STUB_H
#define OHOS_DHCP_SERVER_CALLBACK_STUB_H

#include <map>
#ifdef OHOS_ARCH_LITE
#include "serializer.h"
#else
#include "iremote_stub.h"
#include "iremote_object.h"
#endif
#include "../interfaces/i_dhcp_server_callback.h"
#include "dhcp_errcode.h"

namespace OHOS {
namespace DHCP {
#ifdef OHOS_ARCH_LITE
class DhcpServreCallBackStub : public IDhcpServerCallBack {
#else
class DhcpServreCallBackStub : public IRemoteStub<IDhcpServerCallBack> {
#endif
public:
    DhcpServreCallBackStub();
    virtual ~DhcpServreCallBackStub();

#ifdef OHOS_ARCH_LITE
    int OnRemoteRequest(uint32_t code, IpcIo *data);
    void RegisterCallBack(const std::shared_ptr<IDhcpServerCallBack> &callBack);
#else
    virtual int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override;
    void RegisterCallBack(const sptr<IDhcpServerCallBack> &callBack);
#endif
    bool IsRemoteDied() const;
    void SetRemoteDied(bool val);

    virtual void OnServerStatusChanged(int status) override;
    virtual void OnServerLeasesChanged(const std::string& ifname, std::vector<std::string>& leases) override;
    virtual void OnServerSerExitChanged(const std::string& ifname) override;
    virtual void OnServerSuccess(const std::string& ifname, std::vector<DhcpStationInfo>& stationInfos) override;
private:
#ifdef OHOS_ARCH_LITE
    int RemoteOnServerStatusChanged(uint32_t code, IpcIo *data);
    int RemoteOnServerLeasesChanged(uint32_t code, IpcIo *data);
    int RemoteOnServerSerExitChanged(uint32_t code, IpcIo *data);
    int RemoteOnOnServerSuccess(uint32_t code, IpcIo *data);
    std::shared_ptr<IDhcpServerCallBack> callback_;
#else
    int RemoteOnServerStatusChanged(uint32_t code, MessageParcel &data, MessageParcel &reply);
    int RemoteOnServerLeasesChanged(uint32_t code, MessageParcel &data, MessageParcel &reply);
    int RemoteOnServerSerExitChanged(uint32_t code, MessageParcel &data, MessageParcel &reply);
    int RemoteOnServerSuccess(uint32_t code, MessageParcel &data, MessageParcel &reply);
    sptr<IDhcpServerCallBack> callback_;
#endif
    bool mRemoteDied;
};
}  // namespace DHCP
}  // namespace OHOS
#endif