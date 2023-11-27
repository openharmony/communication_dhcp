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
#include "dhcp_client_service_impl.h"

using namespace OHOS::Wifi;
static std::shared_ptr<DhcpClientServiceImpl> g_dhcpClientServiceImpl = DhcpClientServiceImpl::GetInstance();

typedef struct DhcpClientApi {
    INHERIT_SERVER_IPROXY;
} DhcpClientApi;

typedef struct DhcpClientFeature {
    INHERIT_FEATURE;
    INHERIT_IUNKNOWNENTRY(DhcpClientApi);
    Identity identity;
    Service *parent;
} DhcpClientFeature;

static const char *GetName(Feature *feature)
{
    return DHCP_FEATRUE_CLIENT;
}

static void OnInitialize(Feature *feature, Service *parent, Identity identity)
{
    if (feature != NULL) {
        DhcpClientFeature *serverFeature = (DhcpClientFeature *)feature;
        serverFeature->identity = identity;
        serverFeature->parent = parent;
    }
    if (g_dhcpClientServiceImpl != NULL) {
        g_dhcpClientServiceImpl->OnStart();
    }
}

static void OnStop(Feature *feature, Identity identity)
{
    if (g_dhcpClientServiceImpl != NULL) {
        g_dhcpClientServiceImpl->OnStop();
    }
    if (feature != NULL) {
        DhcpClientFeature *serverFeature = (DhcpClientFeature *)feature;
        serverFeature->identity.queueId = NULL;
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
    LOGI("[DhcpClientFeature] begin to call Invoke, funcId is %{public}d", funcId);
    if (g_dhcpClientServiceImpl != NULL) {
        return g_dhcpClientServiceImpl->OnRemoteRequest(funcId, req, reply);
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
    .identity = {-1, -1, NULL},
};

static void Init(void)
{
    LOGI("[DhcpClientFeature] Init start.");
    BOOL ret = SAMGR_GetInstance()->RegisterFeature(DHCP_CLIENT_LITE, (Feature *)&g_serverFeature);
    if (ret == FALSE) {
        LOGE("[DhcpClientFeature] register feature fail.");
        return;
    }
    ret = SAMGR_GetInstance()->RegisterFeatureApi(DHCP_CLIENT_LITE,
        DHCP_FEATRUE_CLIENT, GET_IUNKNOWN(g_serverFeature));
    if (ret == FALSE) {
        LOGE("[DhcpClientFeature] register feature api fail.");
    }
}
SYSEX_FEATURE_INIT(Init);
