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
#include "dhcp_client_mgr_service_lite.h"
#include "dhcp_ipc_lite_adapter.h"
#include "ohos_init.h"
#include "samgr_lite.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpClientMgrLite");
namespace OHOS {
const int QUEUE_SIZE = 20;
const int DHCP_CLIENT_TASK_STACK_SIZE = 1024;

DhcpClientMgrService::DhcpClientMgrService() : Service(), identity_()
{
    this->Service::GetName = DhcpClientMgrService::GetServiceName;
    this->Service::Initialize = DhcpClientMgrService::ServiceInitialize;
    this->Service::MessageHandle = DhcpClientMgrService::ServiceMessageHandle;
    this->Service::GetTaskConfig = DhcpClientMgrService::GetServiceTaskConfig;
}

static void Init()
{
    SamgrLite *sm = SAMGR_GetInstance();
    if (sm == nullptr) {
        DHCP_LOGE("get samgr error");
        return;
    }
    BOOL result = sm->RegisterService(DhcpClientMgrService::GetInstance());
    DHCP_LOGI("DhcpClientMgrService starts %{public}s", result ? "successfully" : "unsuccessfully");
}
SYSEX_SERVICE_INIT(Init);

const char *DhcpClientMgrService::GetServiceName(Service *service)
{
    (void)service;
    return DHCP_CLIENT_LITE;
}

const Identity *DhcpClientMgrService::GetIdentity()
{
    return &identity_;
}

BOOL DhcpClientMgrService::ServiceInitialize(Service *service, Identity identity)
{
    if (service == nullptr) {
        return FALSE;
    }
    DhcpClientMgrService *dhcpClientManagerService = static_cast<DhcpClientMgrService *>(service);
    dhcpClientManagerService->identity_ = identity;
    return TRUE;
}

BOOL DhcpClientMgrService::ServiceMessageHandle(Service *service, Request *request)
{
    if (request == nullptr) {
        return FALSE;
    }
    return TRUE;
}

TaskConfig DhcpClientMgrService::GetServiceTaskConfig(Service *service)
{
    TaskConfig config = {LEVEL_HIGH, PRI_NORMAL, DHCP_CLIENT_TASK_STACK_SIZE, QUEUE_SIZE, SINGLE_TASK};
    return config;
}

}

