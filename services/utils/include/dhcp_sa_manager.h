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

#ifndef OHOS_DHCP_SA_MANAGER_H
#define OHOS_DHCP_SA_MANAGER_H

#include <condition_variable>
#include "iremote_object.h"
#include "system_ability_load_callback_stub.h"
#include "dhcp_errcode.h"

namespace OHOS {
namespace DHCP {
class DhcpSaLoadCallback : public SystemAbilityLoadCallbackStub {
public:
    void OnLoadSystemAbilitySuccess(int systemAbilityId, const sptr<IRemoteObject>& remoteObject) override;
    void OnLoadSystemAbilityFail(int systemAbilityId) override;
};

class DhcpSaLoadManager {
public:
    static DhcpSaLoadManager& GetInstance();
    ErrCode LoadWifiSa(int systemAbilityId);
    ErrCode UnloadWifiSa(int systemAbilityId);
    void LoadSystemAbilitySuccess();
    void LoadSystemAbilityFail();
private:
    DhcpSaLoadManager() = default;
    ~DhcpSaLoadManager() = default;
    void InitLoadState();
    ErrCode WaitLoadStateChange(int32_t systemAbilityId);

    std::condition_variable locatorCon_;
    std::mutex locatorMutex_;
    bool state_ = false;
};
}  // namespace DHCP
}  // namespace OHOS
#endif