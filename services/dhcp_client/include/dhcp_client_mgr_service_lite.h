/*
 * Copyright (c) 2026 Shenzhen Kaihong Digital Industry Development Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef DHCP_CLIENT_MGR_SERVICE_LITE_H
#define DHCP_CLIENT_MGR_SERVICE_LITE_H

#include "nocopyable.h"
#include "service.h"

namespace OHOS {
class DhcpClientMgrService : public Service {
public:
    static DhcpClientMgrService *GetInstance()
    {
        static DhcpClientMgrService instance;
        return &instance;
    }
    ~DhcpClientMgrService() = default;
    const Identity *GetIdentity();

private:
    DhcpClientMgrService();
    static const char *GetServiceName(Service *service);
    static BOOL ServiceInitialize(Service *service, Identity identity);
    static TaskConfig GetServiceTaskConfig(Service *service);
    static BOOL ServiceMessageHandle(Service *service, Request *request);

private:
    Identity identity_;
    DISALLOW_COPY_AND_MOVE(DhcpClientMgrService);
};
} // namespace OHOS
#endif // DHCP_CLIENT_MGR_SERVICE_LITE_H