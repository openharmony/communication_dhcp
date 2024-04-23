/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "dhcp_sa_manager.h"
#include "dhcp_errcode.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpSaLoadManager");
namespace OHOS {
namespace DHCP {
static constexpr int32_t DHCP_LOADSA_TIMEOUT_MS = 1000;
DhcpSaLoadManager& DhcpSaLoadManager::GetInstance()
{
    static auto instance = new DhcpSaLoadManager();
    return *instance;
}

ErrCode DhcpSaLoadManager::LoadWifiSa(int32_t systemAbilityId) __attribute__((no_sanitize("cfi")))
{
    DHCP_LOGD("%{public}s enter, systemAbilityId = [%{public}d] loading", __func__, systemAbilityId);
    sptr<ISystemAbilityManager> samgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        DHCP_LOGE("%{public}s: get system ability manager failed!", __func__);
        return DHCP_E_FAILED;
    }
    auto object = samgr->CheckSystemAbility(systemAbilityId);
    if (object != nullptr) {
        return DHCP_E_SUCCESS;
    }
    InitLoadState();
    sptr<DhcpSaLoadCallback> loadCallback = new (std::nothrow)DhcpSaLoadCallback();
    if (loadCallback == nullptr) {
        DHCP_LOGE("%{public}s: dhcp sa load callback failed!", __func__);
        return DHCP_E_FAILED;
    }
    int32_t ret = samgr->LoadSystemAbility(systemAbilityId, loadCallback);
    if (ret != DHCP_E_SUCCESS) {
        DHCP_LOGE("%{public}s: Failed to load system ability, SA Id = [%{public}d], ret = [%{public}d].",
            __func__, systemAbilityId, ret);
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("DhcpSaLoadManager LoadWifiSa");
    return WaitLoadStateChange(systemAbilityId);
}

void DhcpSaLoadManager::InitLoadState()
{
    std::unique_lock<std::mutex> lock(locatorMutex_);
    state_ = false;
}

ErrCode DhcpSaLoadManager::WaitLoadStateChange(int32_t systemAbilityId)
{
    std::unique_lock<std::mutex> lock(locatorMutex_);
    auto wait = locatorCon_.wait_for(lock, std::chrono::milliseconds(DHCP_LOADSA_TIMEOUT_MS), [this] {
        DHCP_LOGI("DhcpSaLoadManager wait_for");
        return state_ == true;
    });
    if (!wait) {
        DHCP_LOGE("locator sa [%{public}d] start time out.", systemAbilityId);
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("DhcpSaLoadManager WaitLoadStateChange ok");
    return DHCP_E_SUCCESS;
}

ErrCode DhcpSaLoadManager::UnloadWifiSa(int32_t systemAbilityId)
{
    DHCP_LOGI("%{public}s enter, systemAbilityId = [%{public}d] unloading", __func__, systemAbilityId);
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        DHCP_LOGE("%{public}s: get system ability manager failed!", __func__);
        return DHCP_E_FAILED;
    }
    int32_t ret = samgr->UnloadSystemAbility(systemAbilityId);
    if (ret != DHCP_E_SUCCESS) {
        DHCP_LOGE("%{public}s: Failed to unload system ability, SA Id = [%{public}d], ret = [%{public}d].",
            __func__, systemAbilityId, ret);
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("DhcpSaLoadManager UnloadWifiSa ok");
    return DHCP_E_SUCCESS;
}

void DhcpSaLoadManager::LoadSystemAbilitySuccess()
{
    std::unique_lock<std::mutex> lock(locatorMutex_);
    state_ = true;
    DHCP_LOGI("DhcpSaLoadManager LoadSystemAbilitySuccess notify_one");
    locatorCon_.notify_one();
}

void DhcpSaLoadManager::LoadSystemAbilityFail()
{
    std::unique_lock<std::mutex> lock(locatorMutex_);
    state_ = false;
    DHCP_LOGI("DhcpSaLoadManager LoadSystemAbilityFail notify_one");
    locatorCon_.notify_one();
}

void DhcpSaLoadCallback::OnLoadSystemAbilitySuccess(int32_t systemAbilityId, const sptr<IRemoteObject> &remoteObject)
{
    DHCP_LOGI("DhcpSaLoadManager Load SA success, systemAbilityId = [%{public}d]", systemAbilityId);
    DhcpSaLoadManager::GetInstance().LoadSystemAbilitySuccess();
}

void DhcpSaLoadCallback::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    DHCP_LOGI("DhcpSaLoadManager Load SA failed, systemAbilityId = [%{public}d]", systemAbilityId);
    DhcpSaLoadManager::GetInstance().LoadSystemAbilityFail();
}
}  // namespace DHCP
}  // namespace OHOS
