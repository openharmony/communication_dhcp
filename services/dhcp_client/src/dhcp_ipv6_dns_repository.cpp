/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include <securec.h>
#include "dhcp_ipv6_dns_repository.h"
#include "dhcp_logger.h"
namespace OHOS {
namespace DHCP {
DEFINE_DHCPLOG_DHCP_LABEL("DnsServerRepository");
const int FIRST_DNS_SERVER = 0;
const int SECOND_DNS_SERVER = 1;
DnsServerRepository::DnsServerRepository(int minLifeTime)
{
    currentServers_ = std::unordered_set<std::string>();
    allServers_ = std::vector<DnsServerEntry>();
    minLifetime_ = minLifeTime;
}

DnsServerRepository::~DnsServerRepository()
{
}

bool DnsServerRepository::Clear()
{
    std::lock_guard<std::mutex> lock(mutex);
    currentServers_.clear();
    allServers_.clear();
    return true;
}

bool DnsServerRepository::AddServers(uint32_t lifetime, const std::vector<std::string>& addresses)
{
    std::lock_guard<std::mutex> lock(mutex);
    // ingnore lifetime < minLifetime RDNSS, if is 0, need to update exsiting
    if (lifetime != 0 && lifetime < minLifetime_) {
        DHCP_LOGE("invalid lifetime, do not use these dns %{public}u", lifetime);
        return false;
    }

    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    uint64_t expiry = now + static_cast<uint64_t>(lifetime) * 1000; // to ms

    for (const std::string& addressString : addresses) {
        //if exsiting, update expiry time
        if (!UpdateExistingEntry(addressString, expiry)) {
            if (expiry > now) { // if not exsiting, add
                DnsServerEntry entry = {addressString, expiry};
                allServers_.push_back(entry);
            }
        }
    }

    std::sort(allServers_.begin(), allServers_.end(),
        [](const DnsServerEntry& a, const DnsServerEntry& b) {
            return a.expiry > b.expiry;
        });

    return UpdateCurrentServers();
}

bool DnsServerRepository::SetCurrentServers(DhcpIpv6Info &ipv6Info)
{
    std::lock_guard<std::mutex> lock(mutex);
    ipv6Info.vectorDnsAddr.clear();
    int ret  = memset_s(ipv6Info.dnsAddr, DHCP_INET6_ADDRSTRLEN, 0, DHCP_INET6_ADDRSTRLEN);
    if (ret != EOK) {
        DHCP_LOGE("SetCurrentServers() memset_s failed!");
    }
    ret = memset_s(ipv6Info.dnsAddr2, DHCP_INET6_ADDRSTRLEN, 0, DHCP_INET6_ADDRSTRLEN);
    if (ret != EOK) {
        DHCP_LOGE("SetCurrentServers() memset_s failed!");
    }
    int index = 0;
    for (auto dnsServer: currentServers_) {
        DHCP_LOGI("SetCurrentServers() dnsServer: %{private}s", dnsServer.c_str());
        ipv6Info.vectorDnsAddr.push_back(dnsServer);
        if (index == FIRST_DNS_SERVER) {
            ret = memcpy_s(ipv6Info.dnsAddr, DHCP_INET6_ADDRSTRLEN, dnsServer.c_str(), DHCP_INET6_ADDRSTRLEN);
            if (ret != EOK) {
                DHCP_LOGE("SetCurrentServers() memcpy_s failed!");
            }
        }
        if (index == SECOND_DNS_SERVER) {
            ret = memcpy_s(ipv6Info.dnsAddr2, DHCP_INET6_ADDRSTRLEN, dnsServer.c_str(), DHCP_INET6_ADDRSTRLEN);
            if (ret != EOK) {
                DHCP_LOGE("SetCurrentServers() memcpy_s failed!");
            }
        }
    }
    return true;
}

bool DnsServerRepository::UpdateExistingEntry(const std::string& address, uint64_t expiry)
{
    for (auto& it : allServers_) {
        if (it.address == address) {
            it.expiry = expiry;
            return true;
        }
    }
    return false;
}

bool DnsServerRepository::UpdateCurrentServers()
{
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    bool changed = false;
    if (allServers_.empty()) {
        return changed;
    }
    for (int i = static_cast<int>(allServers_.size()) - 1; i >= 0; --i) {
        DHCP_LOGI("DhcpIpv6 UpdateCurrentServers() %{public}d", i);
        if (i >= NUM_SERVERS || allServers_[i].expiry <= now) {
            DHCP_LOGI("DhcpIpv6 UpdateCurrentServers() remove server %{private}s", allServers_[i].address.c_str());
            // remove expired or too many servers
            const std::string& address = allServers_[i].address;
            allServers_.erase(allServers_.begin() + i);
            if (currentServers_.erase(address)) {
                changed = true;
            }
        } else {
            break;
        }
    }

    for (const DnsServerEntry& entry : allServers_) {
        if (currentServers_.size() < NUM_CURRENT_SERVERS) {
            DHCP_LOGI("DhcpIpv6 UpdateCurrentServers() add server %{private}s", entry.address.c_str());
            if (currentServers_.insert(entry.address).second) {
                changed = true;
            }
        } else {
            break;
        }
    }

    return changed;
}
}
}