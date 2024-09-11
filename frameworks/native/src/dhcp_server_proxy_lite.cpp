/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
#include "dhcp_server_proxy.h"
#include "dhcp_manager_service_ipc_interface_code.h"
#include "dhcp_server_callback_stub.h"
#include "dhcp_c_utils.h"
#include "dhcp_errcode.h"
#include "dhcp_logger.h"
#include "dhcp_sdk_define.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpServerProxyLite");

namespace OHOS {
namespace DHCP {
constexpr int MAX_SIZE = 512;

static SvcIdentity g_sid;
static IpcObjectStub g_objStub;
static DhcpServreCallBackStub g_dhcpServerCallBackStub;

static ErrCode ParseDhcpClientInfos(IpcIo *reply, std::vector<std::string> &infos)
{
    int tmpsize = 0;
    (void)ReadInt32(reply, &tmpsize);
    if (tmpsize > MAX_SIZE) {
        DHCP_LOGE("ParseDhcpClientInfos tmpsize error: %{public}d", tmpsize);
        return DHCP_E_FAILED;
    }
    unsigned int readLen;
    for (int i = 0; i < tmpsize; ++i) {
        std::string str = (char *)ReadString(reply, &readLen);
        infos.emplace_back(str);
    }
    return DHCP_E_SUCCESS;
}

static int IpcCallback(void *owner, int code, IpcIo *reply)
{
    if (code != 0 || owner == nullptr || reply == nullptr) {
        DHCP_LOGE("Callback error, code:%{public}d, owner:%{public}d, reply:%{public}d",
            code, owner == nullptr, reply == nullptr);
        return DHCP_E_FAILED;
    }

    struct IpcOwner *data = (struct IpcOwner *)owner;
    (void)ReadInt32(reply, &data->exception);
    (void)ReadInt32(reply, &data->retCode);
    if (data->exception != 0 || data->retCode != DHCP_E_SUCCESS || data->variable == nullptr) {
        return DHCP_E_FAILED;
    }

    switch (data->funcId) {
        case static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_GET_DHCP_CLIENT_INFO): {
            data->retCode = ParseDhcpClientInfos(reply, *((std::vector<std::string> *)data->variable));
            break;
        }
        default:
            break;
    }
    return DHCP_E_SUCCESS;
}

static int AsyncCallback(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    if (data == nullptr) {
        DHCP_LOGE("AsyncCallback error, data is null");
        return DHCP_E_FAILED;
    }
    return g_dhcpServerCallBackStub.OnRemoteRequest(code, data);
}

static void OnRemoteSrvDied(void *arg)
{
    DHCP_LOGE("%{public}s called.", __func__);
    DhcpServerProxy *client = DhcpServerProxy::GetInstance();
    if (client != nullptr) {
        client->OnRemoteDied();
    }
    return;
}

DhcpServerProxy *DhcpServerProxy::g_instance = nullptr;
DhcpServerProxy::DhcpServerProxy() : remote_(nullptr), remoteDied_(false)
{}

DhcpServerProxy::~DhcpServerProxy()
{}

DhcpServerProxy *DhcpServerProxy::GetInstance(void)
{
    if (g_instance != nullptr) {
        return g_instance;
    }

    DhcpServerProxy *tempInstance = new(std::nothrow) DhcpServerProxy();
    g_instance = tempInstance;
    return g_instance;
}

void DhcpServerProxy::ReleaseInstance(void)
{
    if (g_instance != nullptr) {
        delete g_instance;
        g_instance = nullptr;
    }
}

ErrCode DhcpServerProxy::Init(void)
{
    IUnknown *iUnknown = SAMGR_GetInstance()->GetFeatureApi(DHCP_SERVICE_LITE, DHCP_FEATRUE_SERVER);
    if (iUnknown == nullptr) {
        DHCP_LOGE("GetFeatureApi failed.");
        return DHCP_E_FAILED;
    }
    IClientProxy *proxy = nullptr;
    int result = iUnknown->QueryInterface(iUnknown, CLIENT_PROXY_VER, reinterpret_cast<void **>(&proxy));
    if (result != 0) {
        DHCP_LOGE("QueryInterface failed.");
        return DHCP_E_FAILED;
    }
    remote_ = proxy;

    // Register SA Death Callback
    uint32_t deadId = 0;
    svcIdentity_ = SAMGR_GetRemoteIdentity(DHCP_SERVICE_LITE, DHCP_FEATRUE_SERVER);
    result = AddDeathRecipient(svcIdentity_, OnRemoteSrvDied, nullptr, &deadId);
    if (result != 0) {
        DHCP_LOGE("Register SA Death Callback failed, errorCode[%d]", result);
    }
    return DHCP_E_SUCCESS;
}

bool DhcpServerProxy::IsRemoteDied(void)
{
    if (remoteDied_) {
        DHCP_LOGI("IsRemoteDied! remote is died now!");
    }
    return remoteDied_;
}

void WifiScanProxy::OnRemoteDied(void)
{
    DHCP_LOGW("Remote service is died!");
    remoteDied_ = true;
    g_dhcpServerCallBackStub.SetRemoteDied(true);
}

ErrCode DhcpServerProxy::RegisterDhcpServerCallBack(const std::string& ifname,
    const std::shared_ptr<IDhcpServerCallBack> &callback)
{
    if (remoteDied_ || remote_ == nullptr) {
        DHCP_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return DHCP_E_FAILED;
    }
    DHCP_LOGD("RegisterCallBack start!");
    g_objStub.func = AsyncCallback;
    g_objStub.args = nullptr;
    g_objStub.isRemote = false;

    g_sid.handle = IPC_INVALID_HANDLE;
    g_sid.token = SERVICE_TYPE_ANONYMOUS;
    g_sid.cookie = (uintptr_t)&g_objStub;

    IpcIo request;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&request, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&request, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    (void)WriteInt32(&request, 0);
    (void)WriteRemoteObject(&request, &g_sid);
    (void)WriteString(&request, ifname.c_str());
    owner.funcId = static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REG_CALL_BACK);
    int error = remote_->Invoke(remote_,
        static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REG_CALL_BACK),
        &request, &owner, IpcCallback);
    if (error != DHCP_E_SUCCESS) {
        DHCP_LOGE("RegisterCallBack failed, error code is %{public}d", error);
        return DHCP_E_FAILED;
    }
    DHCP_LOGD("RegisterCallBack is finished: result=%{public}d", owner.exception);
    if (owner.exception) {
        return DHCP_E_FAILED;
    }
    g_dhcpServerCallBackStub.RegisterCallBack(callback);
    return DHCP_E_SUCCESS;
}

ErrCode DhcpServerProxy::StartDhcpServer(const std::string& ifname)
{
    DHCP_LOGI("DhcpServerProxy enter StartDhcpServer mRemoteDied:%{public}d", mRemoteDied);
    if (remoteDied_ || remote_ == nullptr) {
        DHCP_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return DHCP_E_FAILED;
    }

    IpcIo request;
    char data[IPC_DATA_SIZE_MID];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&request, data, IPC_DATA_SIZE_MID, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&request, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    (void)WriteInt32(&request, 0);
    (void)WriteString(&request, ifname.c_str());

    owner.funcId = static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_START_DHCP_SERVER);
    int error = remote_->Invoke(remote_,
        static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_START_DHCP_SERVER),
        &request, &owner,  IpcCallback);
    if (error != DHCP_E_SUCCESS) {
        DHCP_LOGW("Set Attr(%{public}d) failed",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_START_DHCP_SERVER));
        return DHCP_E_FAILED;
    }

    if (owner.exception) {
        return DHCP_E_FAILED;
    }

    return ErrCode(owner.retCode);
}

ErrCode DhcpServerProxy::StopDhcpServer(const std::string& ifname)
{
    DHCP_LOGI("DhcpServerProxy enter StopDhcpServer mRemoteDied:%{public}d", mRemoteDied);
    if (remoteDied_ || remote_ == nullptr) {
        DHCP_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return DHCP_E_FAILED;
    }

    IpcIo request;
    char data[IPC_DATA_SIZE_MID];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&request, data, IPC_DATA_SIZE_MID, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&request, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    (void)WriteInt32(&request, 0);
    (void)WriteString(&request, ifname.c_str());

    owner.funcId = static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_STOP_DHCP_SERVER);
    int error = remote_->Invoke(remote_,
        static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_STOP_DHCP_SERVER),
        &request, &owner,  IpcCallback);
    if (error != DHCP_E_SUCCESS) {
        DHCP_LOGW("Set Attr(%{public}d) failed",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_STOP_DHCP_SERVER));
        return DHCP_E_FAILED;
    }

    if (owner.exception) {
        return DHCP_E_FAILED;
    }

    return ErrCode(owner.retCode);
}

ErrCode DhcpServerProxy::SetDhcpRange(const std::string& ifname, const DhcpRange& range)
{
    DHCP_LOGI("DhcpServerProxy enter SetDhcpRange mRemoteDied:%{public}d", mRemoteDied);
    DHCP_LOGI("DhcpServerProxy enter StopDhcpServer mRemoteDied:%{public}d", mRemoteDied);
    if (remoteDied_ || remote_ == nullptr) {
        DHCP_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return DHCP_E_FAILED;
    }

    IpcIo request;
    char data[IPC_DATA_SIZE_MID];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&request, data, IPC_DATA_SIZE_MID, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&request, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    (void)WriteInt32(&request, 0);
    (void)WriteInt32(&request, range.iptype);
    (void)WriteInt32(&request, range.leaseHours);
    (void)WriteString(&request, range.strTagName.c_str());
    (void)WriteString(&request, range.strStartip.c_str());
    (void)WriteString(&request, range.strEndip.c_str());
    (void)WriteString(&request, range.strSubnet.c_str());
    (void)WriteString(&request, ifname.c_str());

    owner.funcId = static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_SET_DHCP_RANGE);
    int error = remote_->Invoke(remote_,
        static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_SET_DHCP_RANGE),
        &request, &owner,  IpcCallback);
    if (error != DHCP_E_SUCCESS) {
        DHCP_LOGW("Set Attr(%{public}d) failed",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_SET_DHCP_RANGE));
        return DHCP_E_FAILED;
    }

    if (owner.exception) {
        return DHCP_E_FAILED;
    }

    return ErrCode(owner.retCode);
}

ErrCode DhcpServerProxy::SetDhcpName(const std::string& ifname, const std::string& tagName)
{

    DHCP_LOGI("DhcpServerProxy enter SetDhcpName mRemoteDied:%{public}d", mRemoteDied);
    if (remoteDied_ || remote_ == nullptr) {
        DHCP_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return DHCP_E_FAILED;
    }

    IpcIo request;
    char data[IPC_DATA_SIZE_MID];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&request, data, IPC_DATA_SIZE_MID, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&request, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    (void)WriteInt32(&request, 0);
    (void)WriteString(&request, tagName.c_str());
    (void)WriteString(&request, ifname.c_str());

    owner.funcId = static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_SET_DHCP_NAME);
    int error = remote_->Invoke(remote_,
        static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_SET_DHCP_NAME),
        &request, &owner,  IpcCallback);
    if (error != DHCP_E_SUCCESS) {
        DHCP_LOGW("Set Attr(%{public}d) failed",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_SET_DHCP_NAME));
        return DHCP_E_FAILED;
    }

    if (owner.exception) {
        return DHCP_E_FAILED;
    }

    return ErrCode(owner.retCode);
}

ErrCode DhcpServerProxy::PutDhcpRange(const std::string& tagName, const DhcpRange& range)
{
    DHCP_LOGI("DhcpServerProxy enter PutDhcpRange mRemoteDied:%{public}d", mRemoteDied);
    if (remoteDied_ || remote_ == nullptr) {
        DHCP_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return DHCP_E_FAILED;
    }

    IpcIo request;
    char data[IPC_DATA_SIZE_MID];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&request, data, IPC_DATA_SIZE_MID, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&request, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    (void)WriteInt32(&request, 0);
    (void)WriteInt32(&request, range.iptype);
    (void)WriteInt32(&request, range.leaseHours);
    (void)WriteString(&request, range.strTagName.c_str());
    (void)WriteString(&request, range.strStartip.c_str());
    (void)WriteString(&request, range.strEndip.c_str());
    (void)WriteString(&request, range.strSubnet.c_str());
    (void)WriteString(&request, tagName.c_str());

    owner.funcId = static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_PUT_DHCP_RANGE);
    int error = remote_->Invoke(remote_,
        static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_PUT_DHCP_RANGE),
        &request, &owner,  IpcCallback);
    if (error != DHCP_E_SUCCESS) {
        DHCP_LOGW("Set Attr(%{public}d) failed",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_PUT_DHCP_RANGE));
        return DHCP_E_FAILED;
    }

    if (owner.exception) {
        return DHCP_E_FAILED;
    }

    return ErrCode(owner.retCode);
}

ErrCode DhcpServerProxy::RemoveAllDhcpRange(const std::string& tagName)
{
    DHCP_LOGI("DhcpServerProxy enter RemoveAllDhcpRange mRemoteDied:%{public}d", mRemoteDied);
    if (remoteDied_ || remote_ == nullptr) {
        DHCP_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return DHCP_E_FAILED;
    }

    IpcIo request;
    char data[IPC_DATA_SIZE_MID];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&request, data, IPC_DATA_SIZE_MID, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&request, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    (void)WriteInt32(&request, 0);
    (void)WriteString(&request, tagName.c_str());

    owner.funcId = static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REMOVE_ALL_DHCP_RANGE);
    int error = remote_->Invoke(remote_,
        static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REMOVE_ALL_DHCP_RANGE),
        &request, &owner,  IpcCallback);
    if (error != DHCP_E_SUCCESS) {
        DHCP_LOGW("Set Attr(%{public}d) failed",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REMOVE_ALL_DHCP_RANGE));
        return DHCP_E_FAILED;
    }

    if (owner.exception) {
        return DHCP_E_FAILED;
    }

    return ErrCode(owner.retCode);
}

ErrCode DhcpServerProxy::UpdateLeasesTime(const std::string& leaseTime)
{
    DHCP_LOGI("DhcpServerProxy enter UpdateLeasesTime mRemoteDied:%{public}d", mRemoteDied);
    if (remoteDied_ || remote_ == nullptr) {
        DHCP_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return DHCP_E_FAILED;
    }

    IpcIo request;
    char data[IPC_DATA_SIZE_MID];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&request, data, IPC_DATA_SIZE_MID, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&request, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    (void)WriteInt32(&request, 0);
    (void)WriteString(&request, leaseTime.c_str());

    owner.funcId = static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_UPDATE_RENEW_TIME);
    int error = remote_->Invoke(remote_,
        static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_UPDATE_RENEW_TIME),
        &request, &owner,  IpcCallback);
    if (error != DHCP_E_SUCCESS) {
        DHCP_LOGW("Set Attr(%{public}d) failed",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_UPDATE_RENEW_TIME));
        return DHCP_E_FAILED;
    }

    if (owner.exception) {
        return DHCP_E_FAILED;
    }

    return ErrCode(owner.retCode);
}

ErrCode DhcpServerProxy::RemoveDhcpRange(const std::string& tagName, const DhcpRange& range)
{
    DHCP_LOGI("DhcpServerProxy enter RemoveDhcpRange mRemoteDied:%{public}d", mRemoteDied);
    if (remoteDied_ || remote_ == nullptr) {
        DHCP_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return DHCP_E_FAILED;
    }

    IpcIo request;
    char data[IPC_DATA_SIZE_MID];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&request, data, IPC_DATA_SIZE_MID, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&request, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    (void)WriteInt32(&request, 0);
    (void)WriteInt32(&request, range.iptype);
    (void)WriteInt32(&request, range.leaseHours);
    (void)WriteString(&request, range.strTagName.c_str());
    (void)WriteString(&request, range.strStartip.c_str());
    (void)WriteString(&request, range.strEndip.c_str());
    (void)WriteString(&request, range.strSubnet.c_str());
    (void)WriteString(&request, tagName.c_str());

    owner.funcId = static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REMOVE_DHCP_RANGE);
    int error = remote_->Invoke(remote_,
        static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REMOVE_DHCP_RANGE),
        &request, &owner,  IpcCallback);
    if (error != DHCP_E_SUCCESS) {
        DHCP_LOGW("Set Attr(%{public}d) failed",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REMOVE_DHCP_RANGE));
        return DHCP_E_FAILED;
    }

    if (owner.exception) {
        return DHCP_E_FAILED;
    }

    return ErrCode(owner.retCode);
}

ErrCode DhcpServerProxy::GetDhcpClientInfos(const std::string& ifname, std::vector<std::string>& dhcpClientInfo)
{
    DHCP_LOGI("DhcpServerProxy enter GetDhcpClientInfos mRemoteDied:%{public}d", mRemoteDied);
    if (remoteDied_ || remote_ == nullptr) {
        DHCP_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return DHCP_E_FAILED;
    }

    IpcIo request;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&request, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&request, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    (void)WriteInt32(&request, 0);
    WriteString(&request, ifname.c_str());
    owner.variable = &dhcpClientInfo;
    owner.funcId = static_cast<int32_t>(ScanInterfaceCode::DHCP_SERVER_SVR_CMD_GET_DHCP_CLIENT_INFO);
    int error = remote_->Invoke(remote_,
        static_cast<int32_t>(ScanInterfaceCode::DHCP_SERVER_SVR_CMD_GET_DHCP_CLIENT_INFO),
        &request, &owner, IpcCallback);
    if (error != DHCP_E_SUCCESS) {
        DHCP_LOGW("Set Attr(%{public}d) failed",
            static_cast<int32_t>(ScanInterfaceCode::DHCP_SERVER_SVR_CMD_GET_DHCP_CLIENT_INFO));
        return DHCP_E_FAILED;
    }

    if (owner.exception) {
        return DHCP_E_FAILED;
    }
    return ErrCode(owner.retCode);
}
}  // namespace DHCP
}  // namespace OHOS