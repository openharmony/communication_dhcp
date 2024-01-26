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

#ifndef OHOS_DHCP_SERVER_STUB_LITE_H
#define OHOS_DHCP_SERVER_STUB_LITE_H

#include <map>
#include "i_dhcp_server.h"
#include "serializer.h"
namespace OHOS {
namespace DHCP {
    
#define MAX_READ_EVENT_SIZE     512

class DhcpServerStub : public IDhcpServer {
public:
    DhcpServerStub();
    virtual ~DhcpServerStub();
    virtual int OnRemoteRequest(uint32_t code, IpcIo *req, IpcIo *reply);
public:
    const int MAC_ADDR_MAX_LEN = 17;
    const int DHCP_LEASE_FORMAT_SIZE = 5;
    const int DHCP_LEASE_MAC_ADDR_POS = 0;
    const int DHCP_LEASE_IP_ADDR_POS = 1;
    const int DHCP_LEASE_HOSTNAME_POS = 2;

private:
    int CheckInterfaceToken(uint32_t code, IpcIo *req);
    int OnRegisterCallBack(uint32_t code, IpcIo *req, IpcIo *reply);
    int OnStartDhcpServer(uint32_t code, IpcIo *req, IpcIo *reply);
    int OnStopDhcpServer(uint32_t code, IpcIo *req, IpcIo *reply);
    int OnSetDhcpName(uint32_t code, IpcIo *req, IpcIo *reply);
    int OnSetDhcpRange(uint32_t code, IpcIo *req, IpcIo *reply);
    int OnRemoveAllDhcpRange(uint32_t code, IpcIo *req, IpcIo *reply);
    int OnRemoveDhcpRange(uint32_t code, IpcIo *req, IpcIo *reply);
    int OnGetDhcpClientInfos(uint32_t code, IpcIo *req, IpcIo *reply);
    int OnUpdateLeasesTime(uint32_t code, IpcIo *req, IpcIo *reply);
    int OnPutDhcpRange(uint32_t code, IpcIo *req, IpcIo *reply);
private:
    //sptr<IRemoteObject::DeathRecipient> deathRecipient_;
};
}  // namespace DHCP
}  // namespace OHOS
#endif