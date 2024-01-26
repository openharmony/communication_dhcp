/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include <cstdlib>

#include "iproxy_server.h"
#include "ohos_errno.h"
#include "ohos_init.h"
#include "samgr_lite.h"
#include "service.h"
#include "dhcp_ipc_lite_adapter.h"
#include "dhcp_server_service_impl.h"
#include "dhcp_logger.h"
DEFINE_DHCPLOG_DHCP_LABEL("DhcpServerFeature");
using namespace OHOS::DHCP;

static std::shared_ptr<DhcpServerServiceImpl> g_dhcpServerServiceImpl = DhcpServerServiceImpl::GetInstance();

typedef struct DhcpServerApi {
    INHERIT_SERVER_IPROXY;
} DhcpServerApi;

typedef struct DhcpServerFeature {
    INHERIT_FEATURE;
    INHERIT_IUNKNOWNENTRY(DhcpServerApi);
    Identity identity;
    Service *parent;
} DhcpServerFeature;

static const char *GetName(Feature *feature)
{
    return DHCP_FEATRUE_SERVER;
}

static void OnInitialize(Feature *feature, Service *parent, Identity identity)
{
    if (feature != nullptr) {
        DhcpServerFeature *serverFeature = (DhcpServerFeature *)feature;
        serverFeature->identity = identity;
        serverFeature->parent = parent;
    }
    if (g_dhcpServerServiceImpl != nullptr) {
        g_dhcpServerServiceImpl->OnStart();
    }
}

static void OnStop(Feature *feature, Identity identity)
{
    if (g_dhcpServerServiceImpl != nullptr) {
        g_dhcpServerServiceImpl->OnStop();
    }
    if (feature != nullptr) {
        DhcpServerFeature *serverFeature = (DhcpServerFeature *)feature;
        serverFeature->identity.queueId = nullptr;
        serverFeature->identity.featureId = -1;
        serverFeature->identity.serviceId = -1;
    }
}

static BOOL OnMessage(Feature *feature, Request *request)
{
    return TRUE;
}

static int Invoke(IServerProxy *proxy, int funcId, void *origin, IpcIo *req, IpcIo *reply)
{
    DHCP_LOGI("[DhcpServerFeature] begin to call Invoke, funcId is %{public}d", funcId);
    if (g_dhcpServerServiceImpl != nullptr) {
        return g_dhcpServerServiceImpl->OnRemoteRequest(funcId, req, reply);
    }
    return EC_FAILURE;
}

static DhcpServerFeature g_serverFeature = {
    .GetName = GetName,
    .OnInitialize = OnInitialize,
    .OnStop = OnStop,
    .OnMessage = OnMessage,
    SERVER_IPROXY_IMPL_BEGIN,
    .Invoke = Invoke,
    IPROXY_END,
    .identity = {-1, -1, nullptr},
};

static void Init(void)
{
    DHCP_LOGI("[DhcpServerFeature] Init start.");
    BOOL ret = SAMGR_GetInstance()->RegisterFeature(WIFI_SERVICE_LITE, (Feature *)&g_serverFeature);
    if (ret == FALSE) {
        DHCP_LOGE("[DhcpServerFeature] register feature fail.");
        return;
    }
    ret = SAMGR_GetInstance()->RegisterFeatureApi(WIFI_SERVICE_LITE,
        DHCP_FEATRUE_SERVER, GET_IUNKNOWN(g_serverFeature));
    if (ret == FALSE) {
        DHCP_LOGE("[DhcpServerFeature] register feature api fail.");
    }
}
SYSEX_FEATURE_INIT(Init);
