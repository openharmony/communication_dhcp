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
#include "securec.h"
#include <unistd.h>
#include <linux/rtnetlink.h>
#include "dhcp_logger.h"

namespace OHOS {
namespace DHCP {
DEFINE_DHCPLOG_DHCP_LABEL("WifiDhcpIpv6Event");

const int KERNEL_SOCKET_FAMILY = 16;
const int KERNEL_SOCKET_IFA_FAMILY = 10;
const int KERNEL_ICMP_TYPE = 134;
const int IPV6_LENGTH_BYTES = 16;
constexpr int ND_OPT_HDR_LENGTH_BYTES = 2;

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
    if (len < (static_cast<int>(sizeof(struct nduseroptmsg)) + ND_OPT_HDR_LENGTH_BYTES)) {
        DHCP_LOGE("parseNdUserOptMessage invalid len:%{public}d.", len);
        return;
    }
    struct nduseroptmsg *msg = (struct nduseroptmsg *)data;
    if (msg->nduseropt_opts_len > len) {
        DHCP_LOGE("invalid len msg->nduseropt_opts_len:%{public}d > len:%{public}d",
            msg->nduseropt_opts_len, len);
        return;
    }
    int optlen = msg->nduseropt_opts_len;
    if (msg->nduseropt_family != KERNEL_SOCKET_IFA_FAMILY) {
        DHCP_LOGE("invalid nduseropt_family:%{public}d", msg->nduseropt_family);
        return;
    }
    if (msg->nduseropt_icmp_type != KERNEL_ICMP_TYPE || msg->nduseropt_icmp_code != 0) {
        DHCP_LOGE("invalid nduseropt_icmp_type:%{public}d, nduseropt_icmp_type:%{public}d",
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
    if (hdrMsg->nlmsg_len < sizeof(struct ndmsg) + sizeof(struct rtmsg)) {
        return;
    }
    struct rtmsg* rtMsg = reinterpret_cast<struct rtmsg*>(NLMSG_DATA(hdrMsg));
    if (hdrMsg->nlmsg_len < sizeof(struct rtmsg) + NLMSG_LENGTH(0)) {
        DHCP_LOGE("invalid msglen:%{public}d", hdrMsg->nlmsg_len);
        return;
    }
    // Ignore static routes we've set up ourselves.
    if ((rtMsg->rtm_protocol != RTPROT_KERNEL && rtMsg->rtm_protocol != RTPROT_RA) ||
     // We're only interested in global unicast routes.
        (rtMsg->rtm_scope != RT_SCOPE_UNIVERSE) || (rtMsg->rtm_type != RTN_UNICAST) ||
        // We don't support source routing.
        // Cloned routes aren't real routes.
        (rtMsg->rtm_src_len != 0) || (rtMsg->rtm_flags & RTM_F_CLONED)) {
        DHCP_LOGE("invalid arg");
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
                if (rtaInfo->rta_len < (RTA_LENGTH(IPV6_LENGTH_BYTES))) {
                    return;
                }
                if (GetIpFromS6Address(RTA_DATA(rtaInfo), rtmFamily, gateway, sizeof(gateway)) != 0) {
                    DHCP_LOGE("inet_ntop RTA_GATEWAY failed.");
                    return;
                }
                break;
            case RTA_DST:
                if (rtaInfo->rta_len < (RTA_LENGTH(IPV6_LENGTH_BYTES))) {
                    return;
                }
                if (GetIpFromS6Address(RTA_DATA(rtaInfo), rtmFamily, dst, sizeof(dst)) != 0) {
                    DHCP_LOGE("inet_ntop RTA_DST failed.");
                    return;
                }
                break;
            case RTA_OIF:
                if (rtaInfo->rta_len < (RTA_LENGTH(sizeof(int32_t)))) {
                    return;
                }
                ifindex = *(reinterpret_cast<int32_t*>(RTA_DATA(rtaInfo)));
                break;
            default:
                break;
        }
    }
    OnIpv6RouteUpdateEvent(gateway, dst, ifindex, hdrMsg->nlmsg_type == RTM_NEWROUTE);
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
    if (ndm->ndm_family != KERNEL_SOCKET_IFA_FAMILY ||
        ndm->ndm_state != NUD_REACHABLE) {
        return;
    }
    struct rtattr *rta = RTM_RTA(ndm);
    int rtl = static_cast<int>(RTM_PAYLOAD(nlh));
    while (RTA_OK(rta, rtl)) {
        if (rta->rta_type == NDA_DST) {
            if (rta->rta_len < (RTA_LENGTH(IPV6_LENGTH_BYTES))) {
                return;
            }
            struct in6_addr *addr = (struct in6_addr *)RTA_DATA(rta);
            char gateway[DHCP_INET6_ADDRSTRLEN] = {0};
            if (GetIpFromS6Address(addr, ndm->ndm_family, gateway,
                DHCP_INET6_ADDRSTRLEN) != 0) {
                DHCP_LOGE("inet_ntop routeAddr failed.");
                return;
            }
            DHCP_LOGD("parseNewneighMessage: %{public}s", gateway);
            break;
        }
        rta = RTA_NEXT(rta, rtl);
    }
}

void DhcpIpv6Client::fillRouteData(char* buff, int &len)
{
    if (!buff) {
        return;
    }
    struct nlmsghdr *nlh = (struct nlmsghdr *)buff;
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct ndmsg));
    nlh->nlmsg_type = RTM_GETNEIGH;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = static_cast<unsigned int>(getpid());
    len = nlh->nlmsg_len;
}

void DhcpIpv6Client::handleKernelEvent(const uint8_t* data, int len)
{
    if (!data || len < static_cast<int32_t>(sizeof(struct nlmsghdr))) {
        DHCP_LOGE("handleKernelEvent failed, data invalid, len:%{public}d.", len);
        return;
    }
    struct nlmsghdr *nlh = (struct nlmsghdr*)data;
    while (nlh && NLMSG_OK(nlh, len) && nlh->nlmsg_type != static_cast<__u32>(NLMSG_DONE)) {
        DHCP_LOGD("handleKernelEvent nlmsg_type:%{public}d.", nlh->nlmsg_type);
        if (nlh->nlmsg_type == RTM_NEWADDR) {
            DHCP_LOGI("handleKernelEvent nlmsg_type: RTM_NEWADDR.");
            ParseAddrMessage((void *)nlh);
        } else if (nlh->nlmsg_type == RTM_DELADDR) {
            DHCP_LOGI("handleKernelEvent nlmsg_type: RTM_DELADDR");
            ParseAddrMessage((void *)nlh);
        } else if (nlh->nlmsg_type == RTM_NEWNDUSEROPT) {
            DHCP_LOGI("handleKernelEvent nlmsg_type: RTM_NEWNDUSEROPT.");
            if (nlh->nlmsg_len < (sizeof(struct nlmsghdr) + sizeof(struct nduseroptmsg))) {
                DHCP_LOGE("handleKernelEvent nlmsg_len:%{public}u is invalid.", nlh->nlmsg_len);
                return;
            }
            struct nduseroptmsg* ndmsg = (struct nduseroptmsg*)NLMSG_DATA(nlh);
            size_t optsize = NLMSG_PAYLOAD(nlh, sizeof(*ndmsg));
            parseNdUserOptMessage((void*)ndmsg, optsize);
        } else if (nlh->nlmsg_type == RTM_NEWROUTE) {
            DHCP_LOGI("handleKernelEvent nlmsg_type: RTM_NEWROUTE.");
            parseNDRouteMessage((void*)nlh);
        } else if (nlh->nlmsg_type == RTM_DELROUTE) {
            DHCP_LOGI("handleKernelEvent nlmsg_type: RTM_DELROUTE");
            parseNDRouteMessage((void*)nlh);
        } else if (nlh->nlmsg_type == RTM_NEWNEIGH) {
            parseNewneighMessage((void*)nlh);
        }
        nlh = NLMSG_NEXT(nlh, len);
    }
}
void DhcpIpv6Client::ParseAddrMessage(void *msg)
{
    if (msg == nullptr) {
        DHCP_LOGE("ParseAddrMessage msg is nullptr.");
        return;
    }

    struct nlmsghdr *hdrMsg = (struct nlmsghdr*)msg;
    if (hdrMsg->nlmsg_len < (sizeof(struct nlmsghdr) + sizeof(struct ifaddrmsg))) {
        DHCP_LOGE("ParseAddrMessage nlmsg_len:%{public}u is invalid.", hdrMsg->nlmsg_len);
        return;
    }

    int32_t nlType = hdrMsg->nlmsg_type;
    if (nlType != RTM_NEWADDR && nlType != RTM_DELADDR) {
        DHCP_LOGE("ParseAddrMessage on incorrect message nlType 0x%{public}x\n", nlType);
        return;
    }
    ifaddrmsg *addrMsg = reinterpret_cast<ifaddrmsg *>(NLMSG_DATA(hdrMsg));
    char addresses[DHCP_INET6_ADDRSTRLEN];
    memset_s(addresses, DHCP_INET6_ADDRSTRLEN, 0, DHCP_INET6_ADDRSTRLEN);
    int scope = IPV6_ADDR_LINKLOCAL;
    int32_t len = IFA_PAYLOAD(hdrMsg);
    for (rtattr *rtAttr = IFA_RTA(addrMsg); RTA_OK(rtAttr, len); rtAttr = RTA_NEXT(rtAttr, len)) {
        if (rtAttr == nullptr) {
            DHCP_LOGE("Invalid ifaddrmsg\n");
            return;
        }
        if (rtAttr->rta_type == IFA_ADDRESS) {
            if (rtAttr->rta_len < RTA_LENGTH(IPV6_LENGTH_BYTES)) {
                DHCP_LOGI("handleKernelEvent rta_len:%{public}u is invalid.", rtAttr->rta_len);
                continue;
            }
            if (GetIpFromS6Address(RTA_DATA(rtAttr), addrMsg->ifa_family, addresses, DHCP_INET6_ADDRSTRLEN) != 0) {
                DHCP_LOGE("inet_ntop addresses failed.");
                return;
            }
            scope = GetAddrScope(RTA_DATA(rtAttr));
            DHCP_LOGI("ParseAddrMessage %{private}s\n", addresses);
        }
    }
    if (addresses[0] == '\0') {
        return;
    }
    OnIpv6AddressUpdateEvent(addresses, DHCP_INET6_ADDRSTRLEN, addrMsg->ifa_prefixlen, addrMsg->ifa_index,
        scope, nlType == RTM_NEWADDR);
    return;
}
}  // namespace DHCP
}  // namespace OHOS
