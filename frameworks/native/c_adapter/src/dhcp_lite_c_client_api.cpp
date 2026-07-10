/*
 * Copyright (c) 2026 Shenzhen Kaihong Digital Industry Development Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "kits/c/dhcp_lite_c_client_api.h"
#include "inner_api/dhcp_client.h"
#include "dhcp_sdk_define.h"
#include "dhcp_c_utils.h"
#include "dhcp_event.h"
#include "dhcp_logger.h"
#include "dhcp_errcode.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpLiteCClient");
namespace {
    std::shared_ptr<OHOS::DHCP::DhcpClient> dhcpClientPtr = nullptr;
}

static std::shared_ptr<DhcpClientCallBack> dhcpClientCallBack = nullptr;

DhcpErrorCode RegisterDhcpClientCallBack(const char *ifname, const ClientCallBack *event)
{
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(event, DHCP_INVALID_PARAM);
    if (dhcpClientPtr == nullptr) {
        dhcpClientPtr = OHOS::DHCP::DhcpClient::GetInstance(DHCP_CLIENT_ABILITY_ID);
    }
    CHECK_PTR_RETURN(dhcpClientPtr, DHCP_INVALID_PARAM);
    if (dhcpClientCallBack == nullptr) {
        dhcpClientCallBack = std::make_shared<DhcpClientCallBack>();
    }
    CHECK_PTR_RETURN(dhcpClientCallBack, DHCP_INVALID_PARAM);
    dhcpClientCallBack->RegisterCallBack(ifname, event);
    return GetCErrorCode(dhcpClientPtr->RegisterDhcpClientCallBack(ifname, dhcpClientCallBack));
}

DhcpErrorCode StartDhcpClient(const RouterConfig &config)
{
    CHECK_PTR_RETURN(dhcpClientPtr, DHCP_INVALID_PARAM);
    OHOS::DHCP::RouterConfig routerConfig;
    routerConfig.ifname = config.ifname;
    routerConfig.bssid = config.bssid;
    routerConfig.prohibitUseCacheIp = config.prohibitUseCacheIp;
    routerConfig.bIpv6 = config.bIpv6;
    routerConfig.bSpecificNetwork = config.bSpecificNetwork;
    routerConfig.isStaticIpv4 = config.isStaticIpv4;
    routerConfig.bIpv4 = config.bIpv4;
    return GetCErrorCode(dhcpClientPtr->StartDhcpClient(routerConfig));
}

DhcpErrorCode DealWifiDhcpCache(int32_t cmd, const IpCacheInfo &ipCacheInfo)
{
    CHECK_PTR_RETURN(ipCacheInfo.ssid, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(ipCacheInfo.bssid, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpClientPtr, DHCP_INVALID_PARAM);
    OHOS::DHCP::IpCacheInfo cacheInfo;
    cacheInfo.ssid = ipCacheInfo.ssid;
    cacheInfo.bssid = ipCacheInfo.bssid;
    return GetCErrorCode(dhcpClientPtr->DealWifiDhcpCache(cmd, cacheInfo));
}

DhcpErrorCode StopDhcpClient(const char *ifname, bool bIpv6)
{
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpClientPtr, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpClientCallBack, DHCP_INVALID_PARAM);
    DhcpErrorCode ret = GetCErrorCode(dhcpClientPtr->StopDhcpClient(ifname, bIpv6));
    if (ret == DHCP_SUCCESS) {
        dhcpClientCallBack->UnRegisterCallBack(ifname);
    }
    return ret;
}
