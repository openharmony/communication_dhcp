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

#include <unistd.h>
#include <linux/rtnetlink.h>
#include "dhcp_logger.h"

namespace OHOS {
namespace DHCP {
DEFINE_DHCPLOG_DHCP_LABEL("WifiDhcpIpv6Event");

const int KERNEL_SOCKET_FAMILY = 16;
const int KERNEL_SOCKET_IFA_FAMILY = 10;
const int KERNEL_ICMP_TYPE = 134;

void DhcpIpv6Client::setSocketFilter(void* addr)
{
    if (!addr) {
        DHCP_LOGE("setSocketFilter failed, addr invalid.");
        return;
    }
    struct sockaddr_nl *nladdr = (struct sockaddr_nl*)addr;
    nladdr->nl_family = KERNEL_SOCKET_FAMILY;
    nladdr->nl_pid = 0;
    nladdr->nl_groups = RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE | (1 << (RTNLGRP_ND_USEROPT - 1));
}

void DhcpIpv6Client::parseNdUserOptMessage(void* data, int len)
{
    if (!data) {
        DHCP_LOGE("parseNdUserOptMessage failed, msg invalid.");
        return;
    }
    struct nduseroptmsg *msg = (struct nduseroptmsg *)data;
    if (msg->nduseropt_opts_len > len) {
        DHCP_LOGE("invliad len msg->nduseropt_opts_len:%{public}d > len:%{public}d",
            msg->nduseropt_opts_len, len);
        return;
    }
    int optlen = msg->nduseropt_opts_len;
    if (msg->nduseropt_family != KERNEL_SOCKET_IFA_FAMILY) {
        DHCP_LOGE("invliad nduseropt_family:%{public}d", msg->nduseropt_family);
        return;
    }
    if (msg->nduseropt_icmp_type != KERNEL_ICMP_TYPE || msg->nduseropt_icmp_code != 0) {
        DHCP_LOGE("invliad nduseropt_icmp_type:%{public}d, nduseropt_icmp_type:%{public}d",
            msg->nduseropt_icmp_type, msg->nduseropt_icmp_code);
        return;
    }
    onIpv6DnsAddEvent((void*)(msg + 1), optlen, msg->nduseropt_ifindex);
}

void DhcpIpv6Client::parseNDRouteMessage(void* msg)
{
    if (msg == NULL) {
        return;
    }
    struct nlmsghdr *hdrMsg = (struct nlmsghdr*)msg;
    struct rtmsg* rtMsg = reinterpret_cast<struct rtmsg*>(NLMSG_DATA(hdrMsg));
    if (hdrMsg->nlmsg_len < sizeof(struct rtmsg) + NLMSG_LENGTH(0)) {
        DHCP_LOGE("invliad msglen:%{public}d", hdrMsg->nlmsg_len);
        return;
    }
    if ((rtMsg->rtm_protocol != RTPROT_KERNEL && rtMsg->rtm_protocol != RTPROT_RA) ||
        (rtMsg->rtm_scope != RT_SCOPE_UNIVERSE) || (rtMsg->rtm_type != RTN_UNICAST) ||
        (rtMsg->rtm_src_len != 0) || (rtMsg->rtm_flags & RTM_F_CLONED)) {
        DHCP_LOGE("invliad arg");
        return;
    }
    char dst[DHCP_INET6_ADDRSTRLEN] = {0};
    char gateway[DHCP_INET6_ADDRSTRLEN] = {0};
    int32_t rtmFamily = rtMsg->rtm_family;
    size_t size = RTM_PAYLOAD(hdrMsg);
    int ifindex = -1;
    rtattr *rtaInfo = NULL;
    for (rtaInfo = RTM_RTA(rtMsg); RTA_OK(rtaInfo, (int)size); rtaInfo = RTA_NEXT(rtaInfo, size)) {
        switch (rtaInfo->rta_type) {
            case RTA_GATEWAY:
                if (rtaInfo->rta_len < (RTA_LENGTH(0) + sizeof(gateway))) {
                    return;
                }
                if (GetIpFromS6Address(RTA_DATA(rtaInfo), rtmFamily, gateway, sizeof(gateway)) != 0) {
                    DHCP_LOGE("inet_ntop RTA_GATEWAY failed.");
                    return;
                }
                break;
            case RTA_DST:
                if (rtaInfo->rta_len < (RTA_LENGTH(0) + sizeof(dst))) {
                    return;
                }
                if (GetIpFromS6Address(RTA_DATA(rtaInfo), rtmFamily, dst, sizeof(dst)) != 0) {
                    DHCP_LOGE("inet_ntop RTA_DST failed.");
                    return;
                }
                break;
            case RTA_OIF:
                if (rtaInfo->rta_len < (RTA_LENGTH(0) + sizeof(uint32_t))) {
                    return;
                }
                ifindex = *(reinterpret_cast<int32_t*>(RTA_DATA(rtaInfo)));
                break;
            default:
                break;
        }
    }
    onIpv6RouteAddEvent(gateway, dst, ifindex);
}

void DhcpIpv6Client::parseNewneighMessage(void* msg)
{
    if (!msg) {
        return;
    }
    struct nlmsghdr *nlh = (struct nlmsghdr*)msg;
    if (nlh->nlmsg_len < sizeof(struct ndmsg) + sizeof(struct nlmsghdr)) {
        return;
    }
    struct ndmsg *ndm = (struct ndmsg *)NLMSG_DATA(nlh);
    if (!ndm) {
        return;
    }
    if (ndm->ndm_family == KERNEL_SOCKET_IFA_FAMILY &&
        ndm->ndm_state == NUD_REACHABLE) {
        struct rtattr *rta = RTM_RTA(ndm);
        int rtl = static_cast<int>(RTM_PAYLOAD(nlh));
        while (RTA_OK(rta, rtl)) {
            if (rta->rta_type == NDA_DST) {
                if (rta->rta_len < (RTA_LENGTH(0) + DHCP_INET6_ADDRSTRLEN)) {
                    return;
                }
                struct in6_addr *addr = (struct in6_addr *)RTA_DATA(rta);
                char gateway[DHCP_INET6_ADDRSTRLEN] = {0};
                char dst[DHCP_INET6_ADDRSTRLEN] = {0};
                if (GetIpFromS6Address(addr, ndm->ndm_family, gateway,
                    DHCP_INET6_ADDRSTRLEN) != 0) {
                    DHCP_LOGE("inet_ntop routeAddr failed.");
                    return;
                }
                onIpv6RouteAddEvent(gateway, dst, ndm->ndm_ifindex);
                DHCP_LOGD("getIpv6RouteAddr: %{public}s", gateway);
                break;
            }
            rta = RTA_NEXT(rta, rtl);
        }
    }
}

void DhcpIpv6Client::fillRouteData(char* buff, int &len)
{
    if (!buff) {
        return;
    }
    struct nlmsghdr *nlh = (struct nlmsghdr *)buff;
    nlh->nlmsg_len = NLMSG_SPACE(static_cast<unsigned int>(sizeof(struct ndmsg)));
    nlh->nlmsg_type = RTM_GETNEIGH;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = static_cast<unsigned int>(getpid());
    len = nlh->nlmsg_len;
}

void DhcpIpv6Client::handleKernelEvent(const uint8_t* data, int len)
{
    if (!data) {
        DHCP_LOGE("handleKernelEvent failed, data invalid.");
        return;
    }
    if (len < (int32_t)sizeof(struct nlmsghdr)) {
        DHCP_LOGE("recv kernel data not full continue.");
        return;
    }
    struct nlmsghdr *nlh = (struct nlmsghdr*)data;
    while (nlh && NLMSG_OK(nlh, len) && nlh->nlmsg_type != NLMSG_DONE) {
        DHCP_LOGD("handleKernelEvent nlmsg_type:%{public}d.", nlh->nlmsg_type);
        if (nlh->nlmsg_type == NLMSG_DONE) {
            break;
        }
        if (nlh->nlmsg_type == RTM_NEWADDR) {
            struct ifaddrmsg *ifa = (struct ifaddrmsg*)NLMSG_DATA(nlh);
            struct rtattr *rth = IFA_RTA(ifa);
            int rtl = static_cast<int>(IFA_PAYLOAD(nlh));
            while (rtl && RTA_OK(rth, rtl)) {
                if (rth->rta_type != IFA_ADDRESS || ifa->ifa_family != KERNEL_SOCKET_IFA_FAMILY) {
                    rth = RTA_NEXT(rth, rtl);
                    continue;
                }
                onIpv6AddressAddEvent(RTA_DATA(rth), ifa->ifa_prefixlen, ifa->ifa_index);
                rth = RTA_NEXT(rth, rtl);
            }
        } else if (nlh->nlmsg_type == RTM_NEWNDUSEROPT) {
            unsigned int optLen = 0;
            if (nlh->nlmsg_len >= sizeof(*nlh)) {
                optLen = nlh->nlmsg_len - sizeof(*nlh);
            } else {
                return;
            }
            struct nduseroptmsg* ndmsg = (struct nduseroptmsg*)NLMSG_DATA(nlh);
            if (sizeof(*ndmsg) > (size_t)optLen) {
                DHCP_LOGE("ndoption get invalid length.");
                return;
            }
            size_t optsize = NLMSG_PAYLOAD(nlh, sizeof(*ndmsg));
            parseNdUserOptMessage((void*)ndmsg, optsize);
        } else if (nlh->nlmsg_type == RTM_NEWROUTE) {
            parseNDRouteMessage((void*)nlh);
        } else if (nlh->nlmsg_type == RTM_NEWNEIGH) {
            parseNewneighMessage((void*)nlh);
        }
        nlh = NLMSG_NEXT(nlh, len);
    }
}
}  // namespace DHCP
}  // namespace OHOS
