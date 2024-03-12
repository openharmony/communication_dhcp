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
#ifndef OHOS_DHCP_CLIENT_CALLBACK_STUB_LITE_H
#define OHOS_DHCP_CLIENT_CALLBACK_STUB_LITE_H

#include "serializer.h"
#include "../interfaces/i_dhcp_client_callback.h"

namespace OHOS {
namespace DHCP {
class DhcpClientCallBackStub : public IDhcpClientCallBack {
public:
    DhcpClientCallBackStub();
    virtual ~DhcpClientCallBackStub();

    int OnRemoteRequest(uint32_t code, IpcIo *data);
    void RegisterCallBack(const std::shared_ptr<IDhcpClientCallBack> &callBack);
    bool IsRemoteDied() const;
    void SetRemoteDied(bool val);
    void OnIpSuccessChanged(int status, const std::string& ifname, DhcpResult& result) override;
    void OnIpFailChanged(int status, const std::string& ifname, const std::string& reason) override;
private:
    int OnRemoteInterfaceToken(uint32_t code, IpcIo *data);
    int RemoteOnIpSuccessChanged(uint32_t code, IpcIo *data);
    int RemoteOnIpFailChanged(uint32_t code, IpcIo *data);

    std::shared_ptr<IDhcpClientCallBack> callback_;
    bool mRemoteDied;
};
}  // namespace DHCP
}  // namespace OHOS
#endif