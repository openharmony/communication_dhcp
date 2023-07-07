/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0ys/socket.h
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <unistd.h>
#include <linux/rtnetlink.h>
#include "securec.h"
#include "wifi_log.h"
#include "dhcp_ipv6_kernel.h"

#undef LOG_TAG
#define LOG_TAG "WifiDhcp6KernelClient"

#define KERNEL_SOCKET_FAMILY 16
#define KERNEL_SOCKET_IFA_FAMILY 10

void setSocketFilter(void* addr)
{
    struct sockaddr_nl *nladdr = (struct sockaddr_nl*)addr;
    nladdr->nl_family = KERNEL_SOCKET_FAMILY;
    nladdr->nl_pid = 0;
    nladdr->nl_groups = RTMGRP_IPV6_IFADDR | (1 << (RTNLGRP_ND_USEROPT - 1));
}

void handleKernelEvent(const uint8_t* data, int len, onIpv6AddressEvent addrCallback)
{
    if (len < (int32_t)sizeof(struct nlmsghdr)) {
        LOGE("recv kernel data not full continue.");
        return;
    }
    struct nlmsghdr *nlh = (struct nlmsghdr*)data;
    while (NLMSG_OK(nlh, len) && nlh->nlmsg_type != NLMSG_DONE) {
        if (nlh->nlmsg_type == RTM_NEWADDR) {
            struct ifaddrmsg *ifa = (struct ifaddrmsg*)NLMSG_DATA(nlh);
            struct rtattr *rth = IFA_RTA(ifa);
            int rtl = IFA_PAYLOAD(nlh);
            while (rtl && RTA_OK(rth, rtl)) {
                if (rth->rta_type != IFA_ADDRESS || ifa->ifa_family != KERNEL_SOCKET_IFA_FAMILY) {
                    rth = RTA_NEXT(rth, rtl);
                    continue;
                }
                addrCallback(RTA_DATA(rth));
                rth = RTA_NEXT(rth, rtl);
            }
        }
        nlh = NLMSG_NEXT(nlh, len);
    }
}
