/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_DHCP_RESULT_STORE_MANAGER_H
#define OHOS_DHCP_RESULT_STORE_MANAGER_H

#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>
#include "dhcp_client_def.h"

namespace OHOS {
namespace DHCP {
class DhcpResultStoreManager {
public:
    DhcpResultStoreManager();
    ~DhcpResultStoreManager();
    static DhcpResultStoreManager &GetInstance();
    int32_t SaveIpInfoInLocalFile(const IpInfoCached ipInfo);
    int32_t GetCachedIp(const std::string targetBssid, IpInfoCached &outIpResult);

private:
    void SetConfigFilePath(const std::string &fileName);
    int32_t LoadAllIpCached(const std::string &fileName);
    int32_t ReadNetworkSection(IpInfoCached &item, std::ifstream &fs, std::string &line);
    int32_t ReadNetwork(IpInfoCached &item, std::ifstream &fs, std::string &line);
    int32_t SaveConfig();
    int32_t SetClassKeyValue(IpInfoCached &item, const std::string &key, const std::string &value);
    std::string GetClassName();
    std::string OutClassString(IpInfoCached &item);
    void ClearClass(IpInfoCached &item);
    
private:
    std::mutex m_ipResultMutex;
    std::vector<IpInfoCached> m_allIpCached;
    std::string m_fileName;
};

static inline void TrimString(std::string &str)
{
    int32_t i = 0;
    int32_t j = static_cast<int32_t>(str.length()) - 1;
    while (i < static_cast<int32_t>(str.length()) && str[i] == ' ') {
        ++i;
    }
    while (j >= 0 && str[j] == ' ') {
        --j;
    }
    str = ((i > j) ? "" : str.substr(i, j - i + 1));
}
}  // namespace Wifi
}  // namespace OHOS
#endif
