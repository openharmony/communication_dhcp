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
#ifndef DHCP_LITE_C_CLIENT_API_H
#define DHCP_LITE_C_CLIENT_API_H

#include "dhcp_error_code.h"
#include "dhcp_result_event.h"

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * @Description : Obtain the dhcp result of specified interface asynchronously.
     *
     * @param ifname - interface name, eg:wlan0 [in]
     * @param pResultNotify - dhcp result notify [in]
     * @Return : success - DHCP_SUCCESS, failed - others.
     */
    DhcpErrorCode RegisterDhcpClientCallBack(const char *ifname, const ClientCallBack *event);

    /**
     * @Description : add dhcp cache
     *
     * @param ipCacheInfo - ip Cache Infomation
     * @Return : success - DHCP_SUCCESS, failed - others.
     */
    DhcpErrorCode DealWifiDhcpCache(int32_t cmd, const IpCacheInfo &ipCacheInfo);

    /**
     * @Description : Start dhcp client service of specified interface.
     *
     * @param config - config
     * @Return : success - DHCP_SUCCESS, failed - others.
     */
    DhcpErrorCode StartDhcpClient(const RouterConfig &config);

    /**
     * @Description : Stop dhcp client service of specified interface.
     *
     * @param ifname - interface name, eg:wlan0 [in]
     * @param bIpv6 - can or not get ipv6 [in]
     * @Return : success - DHCP_SUCCESS, failed - others.
     */
    DhcpErrorCode StopDhcpClient(const char *ifname, bool bIpv6);

#ifdef __cplusplus
}
#endif
#endif