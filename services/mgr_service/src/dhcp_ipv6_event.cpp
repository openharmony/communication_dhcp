/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include "dhcp_ipv6_client.h"

#include <linux/rtnetlink.h>
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_DHCP_LABEL("WifiDhcpIpv6Event");

const int KERNEL_SOCKET_FAMILY = 16;
const int KERNEL_SOCKET_IFA_FAMILY = 10;
const int KERNEL_ICMP_TYPE = 134;

void DhcpIpv6Client::setSocketFilter(void* addr)
{
    if (!addr) {
        WIFI_LOGE("setSocketFilter failed, addr invalid.");
        return;
    }
    struct sockaddr_nl *nladdr = (struct sockaddr_nl*)addr;
    nladdr->nl_family = KERNEL_SOCKET_FAMILY;
    nladdr->nl_pid = 0;
    nladdr->nl_groups = RTMGRP_IPV6_IFADDR | (1 << (RTNLGRP_ND_USEROPT - 1));
}

void DhcpIpv6Client::parseNdUserOptMessage(void* data, int len)
{
    if (!data) {
        WIFI_LOGE("parseNdUserOptMessage failed, msg invalid.");
        return;
    }
    struct nduseroptmsg *msg = (struct nduseroptmsg *)data;
    if (msg->nduseropt_opts_len > len) {
        WIFI_LOGE("invliad len msg->nduseropt_opts_len:%{public}d > len:%{public}d",
            msg->nduseropt_opts_len, len);
        return;
    }
    int optlen = msg->nduseropt_opts_len;
    if (msg->nduseropt_family != KERNEL_SOCKET_IFA_FAMILY) {
        WIFI_LOGE("invliad nduseropt_family:%{public}d", msg->nduseropt_family);
        return;
    }
    if (msg->nduseropt_icmp_type != KERNEL_ICMP_TYPE || msg->nduseropt_icmp_code != 0) {
        WIFI_LOGE("invliad nduseropt_icmp_type:%{public}d, nduseropt_icmp_type:%{public}d",
            msg->nduseropt_icmp_type, msg->nduseropt_icmp_code);
        return;
    }
    onIpv6DnsAddEvent((void*)(msg + 1), optlen, msg->nduseropt_ifindex);
}

void DhcpIpv6Client::handleKernelEvent(const uint8_t* data, int len)
{
    if (!data) {
        WIFI_LOGE("handleKernelEvent failed, data invalid.");
        return;
    }
    WIFI_LOGI("handleKernelEvent recv enter.");
    if (len < (int32_t)sizeof(struct nlmsghdr)) {
        WIFI_LOGE("recv kernel data not full continue.");
        return;
    }
    struct nlmsghdr *nlh = (struct nlmsghdr*)data;
    while (NLMSG_OK(nlh, len) && nlh->nlmsg_type != NLMSG_DONE) {
        WIFI_LOGI("handleKernelEvent nlmsg_type:%{public}d.", nlh->nlmsg_type);
        if (nlh->nlmsg_type == RTM_NEWADDR) {
            struct ifaddrmsg *ifa = (struct ifaddrmsg*)NLMSG_DATA(nlh);
            struct rtattr *rth = IFA_RTA(ifa);
            int rtl = IFA_PAYLOAD(nlh);
            while (rtl && RTA_OK(rth, rtl)) {
                if (rth->rta_type != IFA_ADDRESS || ifa->ifa_family != KERNEL_SOCKET_IFA_FAMILY) {
                    rth = RTA_NEXT(rth, rtl);
                    continue;
                }
                onIpv6AddressAddEvent(RTA_DATA(rth), ifa->ifa_prefixlen, ifa->ifa_index);
                rth = RTA_NEXT(rth, rtl);
            }
        } else if (nlh->nlmsg_type == RTM_NEWNDUSEROPT) {
            int optLen = nlh->nlmsg_len - sizeof(*nlh);
            struct nduseroptmsg* ndmsg = (struct nduseroptmsg*)NLMSG_DATA(nlh);
            if (sizeof(*ndmsg) > (size_t)optLen) {
                WIFI_LOGE("ndoption get invalid length.");
                continue;
            }
            size_t optsize = NLMSG_PAYLOAD(nlh, sizeof(*ndmsg));
            parseNdUserOptMessage((void*)ndmsg, optsize);
        }
        nlh = NLMSG_NEXT(nlh, len);
    }
}
}  // namespace Wifi
}  // namespace OHOS