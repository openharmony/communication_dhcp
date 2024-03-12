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
#include "dhcp_server_impl.h"
#include "dhcp_server_proxy.h"
#ifndef OHOS_ARCH_LITE
#include "dhcp_sa_manager.h"
#include "i_dhcp_server.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#endif
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpServerImpl");

namespace OHOS {
namespace DHCP {
#define RETURN_IF_FAIL(cond)                          \
    do {                                              \
        if (!(cond)) {                                \
            DHCP_LOGI("'%{public}s' failed.", #cond); \
            return DHCP_E_FAILED;                     \
        }                                             \
    } while (0)

DhcpServerImpl::DhcpServerImpl() : client_(nullptr)
{}

DhcpServerImpl::~DhcpServerImpl()
{
#ifdef OHOS_ARCH_LITE
    DhcpServerProxy::ReleaseInstance();
#endif   
}

bool DhcpServerImpl::Init(int systemAbilityId)
{
    DHCP_LOGI("DhcpServerImpl enter Init!");
#ifdef OHOS_ARCH_LITE
    DhcpServerProxy *serverProxy = DhcpServerProxy::GetInstance();
    if (serverProxy == nullptr) {
        DHCP_LOGE("get dhcp server proxy failed.");
        return false;
    }
    if (clientProxy->Init() != DHCP_OPT_SUCCESS) {
        DHCP_LOGE("dhcp server proxy init failed.");
        DhcpServerProxy::ReleaseInstance();
        return false;
    }
    client_ = clientProxy;
    return true;
#else
    systemAbilityId_ = systemAbilityId;
    return true;
#endif
}

bool DhcpServerImpl::GetDhcpServerProxy()
{
#ifdef OHOS_ARCH_LITE
    return (client_ != nullptr);
#else
    DhcpSaLoadManager::GetInstance().LoadWifiSa(systemAbilityId_);
    if (IsRemoteDied() == false) {
        DHCP_LOGE("remote died false, %{public}d", systemAbilityId_);
        return true;
    }
    sptr<ISystemAbilityManager> sa_mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sa_mgr == nullptr) {
        DHCP_LOGE("failed to get SystemAbilityManager");
        return false;
    }
    sptr<IRemoteObject> object = sa_mgr->GetSystemAbility(systemAbilityId_);
    if (object == nullptr) {
        DHCP_LOGE("failed to get DEVICE_SERVICE");
        return false;
    }
    client_ = iface_cast<OHOS::DHCP::IDhcpServer>(object);
    if (client_ == nullptr) {
        client_ = new (std::nothrow)DhcpServerProxy(object);
    }

    if (client_ == nullptr) {
        DHCP_LOGE("wifi device init failed. %{public}d", systemAbilityId_);
        return false;
    }
    DHCP_LOGI("DhcpServerImpl GetDhcpClientProxy ok");
    return true;
#endif
}

bool DhcpServerImpl::IsRemoteDied(void)
{
    return (client_ == nullptr) ? true : client_->IsRemoteDied();
}

#ifdef OHOS_ARCH_LITE
ErrCode DhcpServerImpl::RegisterDhcpServerCallBack(const std::string& ifname,
    const std::shared_ptr<IDhcpServerCallBack> &callback)
#else
ErrCode DhcpServerImpl::RegisterDhcpServerCallBack(const std::string& ifname,
    const sptr<IDhcpServerCallBack> &callback)
#endif
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetDhcpServerProxy());
    return client_->RegisterDhcpServerCallBack(ifname, callback);
}

ErrCode DhcpServerImpl::StartDhcpServer(const std::string& ifname)
{
    DHCP_LOGI("%{public}s  %{public}d  start", __func__, __LINE__);
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetDhcpServerProxy());
    return client_->StartDhcpServer(ifname);
}

ErrCode DhcpServerImpl::StopDhcpServer(const std::string& ifname)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetDhcpServerProxy());
    return client_->StopDhcpServer(ifname);
}

ErrCode DhcpServerImpl::PutDhcpRange(const std::string& tagName, const DhcpRange& range)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetDhcpServerProxy());
    return client_->PutDhcpRange(tagName, range);
}

ErrCode DhcpServerImpl::RemoveDhcpRange(const std::string& tagName, const DhcpRange& range)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetDhcpServerProxy());
    return client_->RemoveDhcpRange(tagName, range);
}

ErrCode DhcpServerImpl::RemoveAllDhcpRange(const std::string& tagName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetDhcpServerProxy());
    return client_->RemoveAllDhcpRange(tagName);
}

ErrCode DhcpServerImpl::SetDhcpRange(const std::string& ifname, const DhcpRange& range)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetDhcpServerProxy());
    return client_->SetDhcpRange(ifname, range);
}

ErrCode DhcpServerImpl::SetDhcpName(const std::string& ifname, const std::string& tagName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetDhcpServerProxy());
    return client_->SetDhcpName(ifname, tagName);
}

ErrCode DhcpServerImpl::GetDhcpClientInfos(const std::string& ifname, std::vector<std::string>& dhcpClientInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetDhcpServerProxy());
    return client_->GetDhcpClientInfos(ifname, dhcpClientInfo);
}

ErrCode DhcpServerImpl::UpdateLeasesTime(const std::string& leaseTime)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetDhcpServerProxy());
    return client_->UpdateLeasesTime(leaseTime);
}
}  // namespace DHCP
}  // namespace OHOS
