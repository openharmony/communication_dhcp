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
#include "dhcp_ipv6_define.h"
#include "dhcp_ipv6_info.h"
#include "dhcp_logger.h"
namespace OHOS {
namespace DHCP {
DEFINE_DHCPLOG_DHCP_LABEL("DhcpIpv6InfoManager");

bool DhcpIpv6InfoManager::AddRoute(DhcpIpv6Info &dhcpIpv6Info, std::string defaultRouteAddr)
{
    if (std::find(dhcpIpv6Info.defaultRouteAddr.begin(), dhcpIpv6Info.defaultRouteAddr.end(), defaultRouteAddr) !=
        dhcpIpv6Info.defaultRouteAddr.end()) {
        return false;
    }
    DHCP_LOGI("AddRoute addr %{private}s", defaultRouteAddr.c_str());
    dhcpIpv6Info.defaultRouteAddr.push_back(defaultRouteAddr);
    if (memset_s(dhcpIpv6Info.routeAddr, DHCP_INET6_ADDRSTRLEN, 0, DHCP_INET6_ADDRSTRLEN) != EOK) {
        DHCP_LOGE("AddRoute memset_s failed");
        return false;
    }
    for (auto route : dhcpIpv6Info.defaultRouteAddr) {
        if (memcpy_s(dhcpIpv6Info.routeAddr, DHCP_INET6_ADDRSTRLEN, route.c_str(), route.length() + 1) == EOK) {
            return true;
        }
    }
    return false;
}

bool DhcpIpv6InfoManager::RemoveRoute(DhcpIpv6Info &dhcpIpv6Info, std::string defaultRoute)
{
    if (memset_s(dhcpIpv6Info.routeAddr, DHCP_INET6_ADDRSTRLEN, 0, DHCP_INET6_ADDRSTRLEN) != EOK) {
        return false;
    }
    DHCP_LOGI("RemoveRoute addr %{private}s", defaultRoute.c_str());
    if (dhcpIpv6Info.defaultRouteAddr.size() == 0) {
        DHCP_LOGI("RemoveRoute empty list");
        return false;
    }
    bool isChanged = false;
    for (int i = static_cast<int>(dhcpIpv6Info.defaultRouteAddr.size()) - 1; i >=0 ; i--) {
        if (dhcpIpv6Info.defaultRouteAddr[i] == defaultRoute) {
            dhcpIpv6Info.defaultRouteAddr.erase(dhcpIpv6Info.defaultRouteAddr.begin() + i);
            isChanged = true;
        }
    }
    for (auto route : dhcpIpv6Info.defaultRouteAddr) {
        if (memcpy_s(dhcpIpv6Info.routeAddr, DHCP_INET6_ADDRSTRLEN, route.c_str(), route.length() + 1) == EOK) {
            return true;
        }
    }
    return isChanged;
}

static bool UpdateAddress(char *dest, const std::string &addr, AddrType type)
{
    if (memset_s(dest, DHCP_INET6_ADDRSTRLEN, 0, DHCP_INET6_ADDRSTRLEN) != EOK) {
        DHCP_LOGE("UpdateAddr memset_s failed for type %{public}d", static_cast<int>(type));
        return false;
    }
    if (memcpy_s(dest, DHCP_INET6_ADDRSTRLEN, addr.c_str(), addr.length() + 1) != EOK) {
        DHCP_LOGE("UpdateAddr memcpy_s failed for type %{public}d", static_cast<int>(type));
        return false;
    }
    return true;
}

inline bool UpdateAddrInline(DhcpIpv6Info &dhcpIpv6Info, std::string addr, AddrType type)
{
    switch (type) {
        case AddrType::DEFAULT: return UpdateAddress(dhcpIpv6Info.linkIpv6Addr, addr, type);
        case AddrType::GLOBAL: return UpdateAddress(dhcpIpv6Info.globalIpv6Addr, addr, type);
        case AddrType::RAND: return UpdateAddress(dhcpIpv6Info.randIpv6Addr, addr, type);
        case AddrType::UNIQUE: return UpdateAddress(dhcpIpv6Info.uniqueLocalAddr1, addr, type);
        case AddrType::UNIQUE2: return UpdateAddress(dhcpIpv6Info.uniqueLocalAddr2, addr, type);
        default: return false;
    }
}

bool DhcpIpv6InfoManager::UpdateAddr(DhcpIpv6Info &dhcpIpv6Info, std::string addr, AddrType type)
{
    if (addr.length() == 0 || addr.length() > DHCP_INET6_ADDRSTRLEN) {
        DHCP_LOGE("UpdateAddr invalid addr");
        return false;
    }
    bool existingKey = (dhcpIpv6Info.IpAddrMap.find(addr) != dhcpIpv6Info.IpAddrMap.end());
    if (existingKey && dhcpIpv6Info.IpAddrMap[addr] == static_cast<int>(type)) {
        DHCP_LOGI("UpdateAddr existing addr");
        return false;
    }
    if (existingKey) {
        DhcpIpv6InfoManager::RemoveAddr(dhcpIpv6Info, addr);
    }
    dhcpIpv6Info.IpAddrMap.insert({addr, static_cast<int>(type)});
    if (!UpdateAddrInline(dhcpIpv6Info, addr, type)) {
        DHCP_LOGE("UpdateAddr failed %{public}d", static_cast<int>(type));
        return false;
    }
    DHCP_LOGI("UpdateAddr addr %{private}s, type %{public}d", addr.c_str(), static_cast<int>(type));
    return true;
}

static bool ClearAddress(char *addr, AddrType type)
{
    if (memset_s(addr, DHCP_INET6_ADDRSTRLEN, 0, DHCP_INET6_ADDRSTRLEN) != EOK) {
        DHCP_LOGE("RemoveAddr memset_s failed %{public}d", static_cast<int>(type));
        return false;
    }
    return true;
}

inline bool RemoveAddrInline(DhcpIpv6Info &dhcpIpv6Info, AddrType type)
{
    switch (type) {
        case AddrType::DEFAULT: return ClearAddress(dhcpIpv6Info.linkIpv6Addr, type);
        case AddrType::GLOBAL: return ClearAddress(dhcpIpv6Info.globalIpv6Addr, type);
        case AddrType::RAND: return ClearAddress(dhcpIpv6Info.randIpv6Addr, type);
        case AddrType::UNIQUE: return ClearAddress(dhcpIpv6Info.uniqueLocalAddr1, type);
        case AddrType::UNIQUE2: return ClearAddress(dhcpIpv6Info.uniqueLocalAddr2, type);
        default: return false;
    }
}

bool DhcpIpv6InfoManager::RemoveAddr(DhcpIpv6Info &dhcpIpv6Info, std::string addr)
{
    if (addr.length() == 0 || addr.length() > DHCP_INET6_ADDRSTRLEN) {
        DHCP_LOGE("RemoveAddr invalid addr");
        return false;
    }
    DHCP_LOGI("RemoveAddr addr %{private}s", addr.c_str());
    if (dhcpIpv6Info.IpAddrMap.find(addr) == dhcpIpv6Info.IpAddrMap.end()) {
        DHCP_LOGI("RemoveAddr unexisting addr");
        return false;
    }
    AddrType type = static_cast<AddrType>(dhcpIpv6Info.IpAddrMap[addr]);
    dhcpIpv6Info.IpAddrMap.erase(addr);
    return RemoveAddrInline(dhcpIpv6Info, type);
}
}
}