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

#include "dhcp_result_store_manager.h"
#include "dhcp_common_utils.h"
#include "dhcp_errcode.h"
#include "dhcp_logger.h"
#include "securec.h"

namespace OHOS {
namespace DHCP {
DEFINE_DHCPLOG_DHCP_LABEL("DhcpResultStoreManager");
constexpr int MAC_ADDR_SIZE = 17;
DhcpResultStoreManager::DhcpResultStoreManager()
{
    DHCP_LOGI("DhcpResultStoreManager()");
}

DhcpResultStoreManager::~DhcpResultStoreManager()
{
    DHCP_LOGI("~DhcpResultStoreManager()");
}

DhcpResultStoreManager &DhcpResultStoreManager::GetInstance()
{
    static DhcpResultStoreManager g_ipInstance;
    return g_ipInstance;
}

static void TrimString(std::string &str)
{
    int32_t i = 0;
    int32_t j = static_cast<int32_t>(str.length()) - 1;
    while (i < static_cast<int32_t>(str.length()) && (str[i] == ' ' || str[i] == '\n')) {
        ++i;
    }
    while (j >= 0 && (str[j] == ' '|| str[j] == '\n')) {
        --j;
    }
    str = ((i > j) ? "" : str.substr(i, j - i + 1));
}

static int32_t SetClassKeyValue(IpInfoCached &item, const std::string &key, const std::string &value)
{
    int32_t errorKeyValue = 0;
    std::string valueTmp = value;
    if (key == "bssid") {
        item.bssid = value;
    } else if (key == "ssid") {
        item.ssid = value;
    } else if (key == "absoluteLeasetime") {
        item.absoluteLeasetime = static_cast<int64_t>(CheckDataLegal(valueTmp));
    } else if (key == "strYiaddr") {
        if (strncpy_s(item.ipResult.strYiaddr, sizeof(item.ipResult.strYiaddr), value.c_str(), value.size()) != EOK) {
            errorKeyValue++;
        }
    } else if (key == "strOptServerId") {
        if (strncpy_s(
            item.ipResult.strOptServerId, sizeof(item.ipResult.strOptServerId), value.c_str(), value.size()) != EOK) {
            errorKeyValue++;
        }
    } else if (key == "strOptSubnet") {
        if (strncpy_s(
            item.ipResult.strOptSubnet, sizeof(item.ipResult.strOptSubnet), value.c_str(), value.size()) != EOK) {
            errorKeyValue++;
        }
    } else if (key == "strOptDns1") {
        if (strncpy_s(
            item.ipResult.strOptDns1, sizeof(item.ipResult.strOptDns1), value.c_str(), value.size()) != EOK) {
            errorKeyValue++;
        }
    } else if (key == "strOptDns2") {
        if (strncpy_s(
            item.ipResult.strOptDns2, sizeof(item.ipResult.strOptDns2), value.c_str(), value.size()) != EOK) {
            errorKeyValue++;
        }
    } else if (key == "strOptRouter1") {
        if (strncpy_s(
            item.ipResult.strOptRouter1, sizeof(item.ipResult.strOptRouter1), value.c_str(), value.size()) != EOK) {
            errorKeyValue++;
        }
    } else if (key == "strOptRouter2") {
        if (strncpy_s(
            item.ipResult.strOptRouter2, sizeof(item.ipResult.strOptRouter2), value.c_str(), value.size()) != EOK) {
            errorKeyValue++;
        }
    } else if (key == "uOptLeasetime") {
        item.ipResult.uOptLeasetime = static_cast<uint32_t>(CheckDataLegal(valueTmp));
    } else {
        errorKeyValue++;
    }
    return errorKeyValue;
}

static std::string OutClassString(IpInfoCached &item)
{
    std::string buffer = "";
    buffer += "    <IpInfoCached>\n";
    buffer += "    bssid=" + std::string(item.bssid) + "\n";
    buffer += "    ssid=" + std::string(item.ssid) + "\n";
    buffer += "    absoluteLeasetime=" + std::to_string(item.absoluteLeasetime) + "\n";
    buffer += "    strYiaddr=" + std::string(item.ipResult.strYiaddr) + "\n";
    buffer += "    strOptServerId=" + std::string(item.ipResult.strOptServerId) + "\n";
    buffer += "    strOptSubnet=" + std::string(item.ipResult.strOptSubnet) + "\n";
    buffer += "    strOptDns1=" + std::string(item.ipResult.strOptDns1) + "\n";
    buffer += "    strOptDns2=" + std::string(item.ipResult.strOptDns2) + "\n";
    buffer += "    strOptRouter1=" + std::string(item.ipResult.strOptRouter1) + "\n";
    buffer += "    strOptRouter2=" + std::string(item.ipResult.strOptRouter2) + "\n";
    buffer += "    uOptLeasetime=" + std::to_string(item.ipResult.uOptLeasetime) + "\n";
    buffer += "    <IpInfoCached>\n";
    return buffer;
}

static void ClearClass(IpInfoCached &item)
{
    item.bssid.clear();
    item.absoluteLeasetime = 0;
    item.ipResult.uOptLeasetime = 0;
}

static int32_t ReadNetworkSection(IpInfoCached &item, FILE *fp, char *line, size_t lineSize)
{
    int32_t sectionError = 0;
    while (fgets(line, lineSize, fp) != nullptr) {
        std::string strLine = line;
        TrimString(strLine);
        if (strLine.empty()) {
            continue;
        }
        if (strLine[0] == '<' && ((strLine.length() > 0) && (strLine[strLine.length() - 1] == '>'))) {
            return sectionError;
        }
        std::string::size_type npos = strLine.find("=");
        if (npos == std::string::npos) {
            DHCP_LOGE("Invalid config line");
            sectionError++;
            continue;
        }
        std::string key = strLine.substr(0, npos);
        std::string value = strLine.substr(npos + 1);
        TrimString(key);
        TrimString(value);
        /* template function, needing specialization */
        sectionError += SetClassKeyValue(item, key, value);
    }
    DHCP_LOGE("Section config not end correctly");
    sectionError++;
    return sectionError;
}

static int32_t ReadNetwork(IpInfoCached &item, FILE *fp, char *line, size_t lineSize)
{
    int32_t networkError = 0;
    while (fgets(line, lineSize, fp) != nullptr) {
        std::string strLine = line;
        TrimString(strLine);
        if (strLine.empty()) {
            continue;
        }
        if (strLine[0] == '<' && ((strLine.length() > 0) && (strLine[strLine.length() - 1] == '>'))) {
            networkError += ReadNetworkSection(item, fp, line, lineSize);
        } else if (strLine.compare("}") == 0) {
            return networkError;
        } else {
            DHCP_LOGE("Invalid config line");
            networkError++;
        }
    }
    DHCP_LOGE("Network config not end correctly");
    networkError++;
    return networkError;
}


int32_t DhcpResultStoreManager::SaveIpInfoInLocalFile(const IpInfoCached ipResult)
{
    std::unique_lock<std::mutex> lock(m_ipResultMutex);
    for (auto it = m_allIpCached.begin(); it != m_allIpCached.end(); it++) {
        if (ipResult.bssid == it->bssid) {
            m_allIpCached.erase(it);
            break;
        }
    }
    m_allIpCached.push_back(ipResult);
    return SaveConfig();
}

int32_t DhcpResultStoreManager::RemoveCachedIp(const IpInfoCached &cacheInfo)
{
    LoadAllIpCached(DHCP_CACHE_FILE);
    DHCP_LOGE("RemoveCachedIp, m_allIpCached size is %{public}d", static_cast<int32_t>(m_allIpCached.size()));
    if (cacheInfo.ssid.empty()) {
        DHCP_LOGE("RemoveCachedIp, ssid is empty");
        return DHCP_E_FAILED;
    }
    std::unique_lock<std::mutex> lock(m_ipResultMutex);
    if (m_allIpCached.empty()) {
        DHCP_LOGE("m_allIpCached is empty");
        return DHCP_E_FAILED;
    }
    m_allIpCached.erase(std::remove_if(m_allIpCached.begin(), m_allIpCached.end(),
        [cacheInfo](IpInfoCached x) { return x.ssid == cacheInfo.ssid; }), m_allIpCached.end());
    return SaveConfig();
}

int32_t DhcpResultStoreManager::AddCachedIp(const IpInfoCached &cacheInfo)
{
    LoadAllIpCached(DHCP_CACHE_FILE);
    DHCP_LOGE("AddCachedIp, m_allIpCached size is %{public}d", static_cast<int32_t>(m_allIpCached.size()));
    std::unique_lock<std::mutex> lock(m_ipResultMutex);
    if (m_allIpCached.empty()) {
        DHCP_LOGE("m_allIpCached is empty");
        return DHCP_E_FAILED;
    }
    if (cacheInfo.ssid.empty() || (cacheInfo.bssid.size() != MAC_ADDR_SIZE)) {
        DHCP_LOGE("ssid or bssid is invalid");
        return DHCP_E_FAILED;
    }
    for (auto it = m_allIpCached.begin(); it != m_allIpCached.end(); it++) {
        if (cacheInfo.bssid == it->bssid) {
            it->ssid = cacheInfo.ssid;
            break;
        }
    }
    return SaveConfig();
}

int32_t DhcpResultStoreManager::GetCachedIp(const std::string targetBssid, IpInfoCached &outIpResult)
{
    std::string fileName = DHCP_CACHE_FILE;
    LoadAllIpCached(fileName);
    std::unique_lock<std::mutex> lock(m_ipResultMutex);
    for (auto it = m_allIpCached.begin(); it != m_allIpCached.end(); it++) {
        if (targetBssid == it->bssid) {
            outIpResult = static_cast<IpInfoCached>(*it);
            return 0;
        }
    }
    return -1;
}

void DhcpResultStoreManager::SetConfigFilePath(const std::string &fileName)
{
    m_fileName = fileName;
}

int32_t DhcpResultStoreManager::LoadAllIpCached(const std::string &fileName)
{
    std::unique_lock<std::mutex> lock(m_ipResultMutex);
    SetConfigFilePath(fileName);
    if (m_fileName.empty()) {
        DHCP_LOGE("File name is empty.");
        return -1;
    }
    char *realPaths = realpath(m_fileName.c_str(), nullptr);
    if (realPaths == nullptr) {
        DHCP_LOGE("realpath failed error");  
    }
    FILE *fp = fopen(m_fileName.c_str(), "r");
    if (!fp) {
        DHCP_LOGE("Loading config file: %{public}s, fopen() failed!", m_fileName.c_str());
        return -1;
    }
    m_allIpCached.clear();
    std::vector<IpInfoCached>().swap(m_allIpCached);
    IpInfoCached item;
    char line[1024];
    int32_t configError;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        std::string strLine = line;
        TrimString(strLine);
        if (strLine.empty()) {
            continue;
        }
        if (strLine[0] == '[' && ((strLine.length() > 0) && (strLine[strLine.length() - 1] == '{'))) {
            ClearClass(item); /* template function, needing specialization */
            configError = ReadNetwork(item, fp, line, sizeof(line));
            if (configError > 0) {
                DHCP_LOGE("Parse network failed.");
                continue;
            }
            m_allIpCached.push_back(item);
        }
    }

    (void)fclose(fp);
    return 0;
}


int32_t DhcpResultStoreManager::SaveConfig()
{
    if (m_fileName.empty()) {
        DHCP_LOGE("File name is empty.");
        return -1;
    }
    char *realPaths = realpath(m_fileName.c_str(), nullptr);
    if (realPaths == nullptr) {
        DHCP_LOGE("realpath failed error");  
    }
    FILE* fp = fopen(m_fileName.c_str(), "w");
    if (!fp) {
        DHCP_LOGE("Save config file: %{public}s, fopen() failed!", m_fileName.c_str());
        return -1;
    }
    std::string content = "";
    for (std::size_t i = 0; i < m_allIpCached.size(); ++i) {
        IpInfoCached &item = m_allIpCached[i];
        content += "[IpInfoCached_" + std::to_string(i + 1) + "] {\n";
        content += OutClassString(item) + "\n";
        content += "}\n";
    }
    uint32_t ret = fwrite(content.c_str(), 1, content.length(), fp);
    if (ret != static_cast<uint32_t>(content.length())) {
        DHCP_LOGE("Save config file: %{public}s, fwrite() failed!", m_fileName.c_str());
    }
    (void)fflush(fp);
    (void)fsync(fileno(fp));
    (void)fclose(fp);
    m_allIpCached.clear(); /* clear values */
    std::vector<IpInfoCached>().swap(m_allIpCached);
    return 0;
}

}  // namespace DHCP
}  // namespace OHOS