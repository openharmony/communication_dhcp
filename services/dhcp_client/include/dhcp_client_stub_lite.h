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

#ifndef OHOS_DHCP_CLIENT_STUB_LITE_H
#define OHOS_DHCP_CLIENT_STUB_LITE_H

#include <map>
#include "i_dhcp_client.h"
#ifndef  OHOS_EUPDATER
#include "serializer.h"
#endif

namespace OHOS {
namespace Wifi {
class DhcpClientStub : public IDhcpClient {
public:
    DhcpClientStub();
    virtual ~DhcpClientStub();
#ifndef OHOS_EUPDATER
    using handleFunc = int (DhcpClientStub::*)(uint32_t code, IpcIo *req, IpcIo *reply);
    using HandleFuncMap = std::map<int, handleFunc>;
    virtual int OnRemoteRequest(uint32_t code, IpcIo *req, IpcIo *reply);
private:
    void InitHandleMap(void);
    int OnRegisterCallBack(uint32_t code, IpcIo *req, IpcIo *reply);
    int OnStartDhcpClient(uint32_t code, IpcIo *req, IpcIo *reply);
    int OnStopDhcpClient(uint32_t code, IpcIo *req, IpcIo *reply);
    int OnGetDhcpInfo(uint32_t code, IpcIo *req, IpcIo *reply);
    int OnRenewDhcpClient(uint32_t code, IpcIo *req, IpcIo *reply);
private:
    HandleFuncMap handleFuncMap;
#endif
};
}  // namespace Wifi
}  // namespace OHOS
#endif