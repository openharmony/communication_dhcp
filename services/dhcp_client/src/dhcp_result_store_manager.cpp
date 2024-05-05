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
#include "dhcp_logger.h"
#include "securec.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpResultStoreManager");

namespace OHOS {
namespace DHCP {
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
    std::ifstream fs(m_fileName.c_str());
    if (!fs.is_open()) {
        DHCP_LOGE("Loading config file: %{public}s, fs.is_open() failed!", m_fileName.c_str());
        return -1;
    }
    m_allIpCached.clear();
    IpInfoCached item;
    std::string line;
    int32_t configError;
    while (std::getline(fs, line)) {
        TrimString(line);
        if (line.empty()) {
            continue;
        }
        if (line[0] == '[' && line[line.length() - 1] == '{') {
            ClearClass(item); /* template function, needing specialization */
            configError = ReadNetwork(item, fs, line);
            if (configError > 0) {
                DHCP_LOGE("Parse network failed.");
                continue;
            }
            m_allIpCached.push_back(item);
        }
    }
    fs.close();
    return 0;
}

int32_t DhcpResultStoreManager::ReadNetworkSection(IpInfoCached &item, std::ifstream &fs, std::string &line)
{
    int32_t sectionError = 0;
    while (std::getline(fs, line)) {
        TrimString(line);
        if (line.empty()) {
            continue;
        }
        if (line[0] == '<' && line[line.length() - 1] == '>') {
            return sectionError;
        }
        std::string::size_type npos = line.find("=");
        if (npos == std::string::npos) {
            DHCP_LOGE("Invalid config line");
            sectionError++;
            continue;
        }
        std::string key = line.substr(0, npos);
        std::string value = line.substr(npos + 1);
        TrimString(key);
        TrimString(value);
        /* template function, needing specialization */
        sectionError += SetClassKeyValue(item, key, value);
    }
    DHCP_LOGE("Section config not end correctly");
    sectionError++;
    return sectionError;
}

int32_t DhcpResultStoreManager::ReadNetwork(IpInfoCached &item, std::ifstream &fs, std::string &line)
{
    int32_t networkError = 0;
    while (std::getline(fs, line)) {
        TrimString(line);
        if (line.empty()) {
            continue;
        }
        if (line[0] == '<' && line[line.length() - 1] == '>') {
            networkError += ReadNetworkSection(item, fs, line);
        } else if (line.compare("}") == 0) {
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

int32_t DhcpResultStoreManager::SaveConfig()
{
    if (m_fileName.empty()) {
        DHCP_LOGE("File name is empty.");
        return -1;
    }
    FILE* fp = fopen(m_fileName.c_str(), "w");
    if (!fp) {
        DHCP_LOGE("Save config file: %{public}s, fopen() failed!", m_fileName.c_str());
        return -1;
    }
    std::ostringstream ss;
    for (std::size_t i = 0; i < m_allIpCached.size(); ++i) {
        IpInfoCached &item = m_allIpCached[i];
        ss << "[" << GetClassName() << "_" << (i + 1) << "] {" << std::endl;
        ss << OutClassString(item) << std::endl;
        ss << "}" << std::endl;
    }
    std::string content = ss.str();
    int32_t ret = fwrite(content.c_str(), 1, content.length(), fp);
    if (ret != (int32_t)content.length()) {
        DHCP_LOGE("Save config file: %{public}s, fwrite() failed!", m_fileName.c_str());
    }
    (void)fflush(fp);
    (void)fsync(fileno(fp));
    (void)fclose(fp);
    m_allIpCached.clear(); /* clear values */
    return 0;
}

int32_t DhcpResultStoreManager::SetClassKeyValue(IpInfoCached &item, const std::string &key, const std::string &value)
{
    int32_t errorKeyValue = 0;
    if (key == "bssid") {
        item.bssid = value;
    } else if (key == "absoluteLeasetime") {
        item.absoluteLeasetime = std::stoi(value);
    } else if (key == "strYiaddr") {
        if (strncpy_s(
            item.ipResult.strYiaddr, sizeof(item.ipResult.strYiaddr), value.c_str(), value.size()) != EOK) {
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
        item.ipResult.uOptLeasetime = std::stoi(value);
    } else {
        DHCP_LOGE("Invalid config key value");
        errorKeyValue++;
    }
    return errorKeyValue;
}

std::string DhcpResultStoreManager::GetClassName()
{
    return "IpInfoCached";
}

std::string DhcpResultStoreManager::OutClassString(IpInfoCached &item)
{
    std::ostringstream ss;
    ss << "    " <<"<IpInfoCached>" << std::endl;
    ss << "    " <<"bssid=" << item.bssid << std::endl;
    ss << "    " <<"absoluteLeasetime=" << item.absoluteLeasetime << std::endl;
    ss << "    " <<"strYiaddr=" << item.ipResult.strYiaddr << std::endl;
    ss << "    " <<"strOptServerId=" << item.ipResult.strOptServerId << std::endl;
    ss << "    " <<"strOptSubnet=" << item.ipResult.strOptSubnet << std::endl;
    ss << "    " <<"strOptDns1=" << item.ipResult.strOptDns1 << std::endl;
    ss << "    " <<"strOptDns2=" << item.ipResult.strOptDns2 << std::endl;
    ss << "    " <<"strOptRouter1=" << item.ipResult.strOptRouter1 << std::endl;
    ss << "    " <<"strOptRouter2=" << item.ipResult.strOptRouter2 << std::endl;
    ss << "    " <<"uOptLeasetime=" << item.ipResult.uOptLeasetime << std::endl;
    ss << "    " <<"<IpInfoCached>" << std::endl;
    return ss.str();
}

void DhcpResultStoreManager::ClearClass(IpInfoCached &item)
{
    item.bssid.clear();
    item.absoluteLeasetime = 0;
    item.ipResult.uOptLeasetime = 0;
}
}  // namespace Wifi
}  // namespace OHOS