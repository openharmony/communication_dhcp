/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef DHCP_V6_FEATURE_SWITCH_H
#define DHCP_V6_FEATURE_SWITCH_H

#include <string>
#include <atomic>

namespace OHOS {
namespace DHCP {

class DhcpV6FeatureSwitch {
public:
    static DhcpV6FeatureSwitch& GetInstance();
    bool IsDhcpV6Enabled() const;

    DhcpV6FeatureSwitch(const DhcpV6FeatureSwitch&) = delete;
    DhcpV6FeatureSwitch& operator=(const DhcpV6FeatureSwitch&) = delete;

private:
    DhcpV6FeatureSwitch();

    std::atomic<bool> dhcpV6Enabled_;
};

} // namespace DHCP
} // namespace OHOS

#endif // DHCP_V6_FEATURE_SWITCH_H
