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

#include "dhcp_v6_feature_switch.h"
#include "dhcp_logger.h"
#include "securec.h"
#include <fstream>
#include <string>

#ifdef INIT_LIB_ENABLE
#include "parameter.h"
#endif

namespace OHOS {
namespace DHCP {

DEFINE_DHCPLOG_DHCP_LABEL("DhcpV6FeatureSwitch");

static constexpr int FEATURE_VALUE_LEN = 16;
static constexpr const char *FEATURE_NAME = "const.wifi.dhcpv6_feature_enable";

static bool GetParamValue(const char *key, const char *def, char *value, uint32_t len)
{
    if (key == nullptr || value == nullptr) {
        return false;
    }
#ifdef INIT_LIB_ENABLE
    char paramValue[FEATURE_VALUE_LEN + 1] = { 0 };
    int ret = GetParameter(key, def, paramValue, FEATURE_VALUE_LEN);
    if (ret > 0) {
        if (strncpy_s(value, len, paramValue, FEATURE_VALUE_LEN) != EOK) {
            return false;
        }
        return true;
    }
#endif
    return false;
}

static bool CheckDataLegal(const std::string &data)
{
    if (data.empty() || data.size() > FEATURE_VALUE_LEN) {
        return false;
    }
    for (char c : data) {
        if (!isdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return true;
}

DhcpV6FeatureSwitch& DhcpV6FeatureSwitch::GetInstance()
{
    static DhcpV6FeatureSwitch instance;
    return instance;
}

DhcpV6FeatureSwitch::DhcpV6FeatureSwitch() : dhcpV6Enabled_(false)
{
    char featureValue[FEATURE_VALUE_LEN + 1] = { 0 };
    int code = GetParamValue(FEATURE_NAME, "0", featureValue, FEATURE_VALUE_LEN);
    std::string featureStr(featureValue);
    dhcpV6Enabled_ = (code > 0 && CheckDataLegal(featureStr) && featureStr == "1");
    DHCP_LOGI("DhcpV6FeatureSwitch: feature=%{public}s, enabled=%{public}d", featureStr.c_str(), dhcpV6Enabled_.load());
}

bool DhcpV6FeatureSwitch::IsDhcpV6Enabled() const
{
    return dhcpV6Enabled_.load();
}

} // namespace DHCP
} // namespace OHOS
