/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "dhcp_function.h"
#include <arpa/inet.h>
#include <sys/time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstdlib>
#include <sys/socket.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <cstdio>
#include <cerrno>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include "securec.h"
#include "dhcp_client_def.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpFunction");

bool Ip4StrConToInt(const char *strIp, uint32_t *uIp, bool bHost)
{
    if ((strIp == NULL) || (strlen(strIp) == 0)) {
        DHCP_LOGE("Ip4StrConToInt failed, strIp == NULL or \"\"!");
        return false;
    }

    struct in_addr addr4;
    int nRet = inet_pton(AF_INET, strIp, &addr4);
    if (nRet != 1) {
        DHCP_LOGE("Ip4StrConToInt strIp:%{private}s failed, inet_pton nRet:%{public}d!", strIp, nRet);
        if (nRet == 0) {
            DHCP_LOGE("Ip4StrConToInt strIp:%{private}s not in presentation format!", strIp);
        } else {
            DHCP_LOGE("Ip4StrConToInt strIp:%{private}s inet_pton does not contain a valid address family!", strIp);
        }
        return false;
    }

    if (bHost) {
        *uIp = ntohl(addr4.s_addr);
    } else {
        *uIp = addr4.s_addr;
    }

    return true;
}

bool Ip6StrConToChar(const char *strIp, uint8_t chIp[], size_t chlen)
{
    if ((strIp == NULL) || (strlen(strIp) == 0)) {
        DHCP_LOGE("Ip6StrConToChar failed, strIp == NULL or \"\"!");
        return false;
    }

    struct in6_addr addr6;
    if (memset_s(&addr6, sizeof(addr6), 0, sizeof(addr6)) != EOK) {
        return false;
    }
    int nRet = inet_pton(AF_INET6, strIp, &addr6);
    if (nRet != 1) {
        DHCP_LOGE("Ip6StrConToChar strIp:%{private}s failed, inet_pton nRet:%{public}d!", strIp, nRet);
        if (nRet == 0) {
            DHCP_LOGE("Ip6StrConToChar strIp:%{private}s not in presentation format!", strIp);
        } else {
            DHCP_LOGE("Ip6StrConToChar strIp:%{private}s inet_pton does not contain a valid address family!", strIp);
        }
        return false;
    }

    DHCP_LOGI("Ip6StrConToChar strIp:%{private}s -> ", strIp);
    for (size_t i = 0; (i < chlen) && (i < sizeof(addr6.s6_addr)); i++) {
        DHCP_LOGI("Ip6StrConToChar addr6.s6_addr: %{private}zu - %{private}02x", i, addr6.s6_addr[i]);
        chIp[i] = addr6.s6_addr[i];
    }

    return true;
}

bool MacChConToMacStr(const unsigned char *pChMac, size_t chLen, char *pStrMac, size_t strLen)
{
    if ((pChMac == NULL) || (chLen == 0)) {
        DHCP_LOGE("MacChConToMacStr failed, pChMac == NULL or chLen == 0!");
        return false;
    }

    if ((pStrMac == NULL) || (strLen < (chLen * MAC_ADDR_CHAR_NUM))) {
        DHCP_LOGE("MacChConToMacStr failed, pStrMac == NULL or strLen:%{public}d error!", (int)strLen);
        return false;
    }

    if (chLen > MAC_ADDR_LEN) {
        DHCP_LOGE("MacChConToMacStr failed, chLen:%{public}zu error!", chLen);
        return false;
    }

    const unsigned char *pSrc = pChMac;
    const unsigned char *pSrcEnd = pSrc + chLen;
    char *pDest = pStrMac;
    for (; pSrc < pSrcEnd; pSrc++) {
        /* The first character of pStrMac starts with a letter, not ':'. */
        if (pSrc != pChMac) {
            *(pDest++) = ':';
        }
        int ret = snprintf_s(pDest, MAC_ADDR_CHAR_NUM, MAC_ADDR_CHAR_NUM - 1, "%.2x", *pSrc);
        if (ret < 0) {
            DHCP_LOGE("snprintf_s failed!");
            return false;
        }
        pDest += ret;
    }
    /* The last character of pStrMac ends with '\0'. */
    *(pDest++) = '\0';
    return true;
}

int GetLocalInterface(const char *ifname, int *ifindex, unsigned char *hwaddr, uint32_t *ifaddr4)
{
    if ((ifname == NULL) || (strlen(ifname) == 0) || hwaddr == NULL) {
        DHCP_LOGE("GetLocalInterface() failed, ifname == NULL or hwaddr is NULL");
        return DHCP_OPT_FAILED;
    }

    int fd;
    struct ifreq iface;
    struct sockaddr_in *pSockIn = NULL;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        DHCP_LOGE("GetLocalInterface() ifname:%{public}s failed, socket err:%{public}d!", ifname, errno);
        return DHCP_OPT_FAILED;
    }

    if (memset_s(&iface, sizeof(iface), 0, sizeof(iface)) != EOK) {
        DHCP_LOGE("GetLocalInterface() ifname:%{public}s failed, memset_s error!", ifname);
        close(fd);
        return DHCP_OPT_FAILED;
    }
    if (strncpy_s(iface.ifr_name, sizeof(iface.ifr_name), ifname, strlen(ifname)) != EOK) {
        DHCP_LOGE("GetLocalInterface() ifname:%{public}s failed, strncpy_s error!", ifname);
        close(fd);
        return DHCP_OPT_FAILED;
    }

    if (ioctl(fd, SIOCGIFINDEX, &iface) != 0) {
        DHCP_LOGE("GetLocalInterface() %{public}s failed, SIOCGIFINDEX err:%{public}d!", ifname, errno);
        close(fd);
        return DHCP_OPT_FAILED;
    }
    *ifindex = iface.ifr_ifindex;

    if (ioctl(fd, SIOCGIFHWADDR, &iface) != 0) {
        DHCP_LOGE("GetLocalInterface() %{public}s failed, SIOCGIFHWADDR err:%{public}d!", ifname, errno);
        close(fd);
        return DHCP_OPT_FAILED;
    }
    if (memcpy_s(hwaddr, MAC_ADDR_LEN, iface.ifr_hwaddr.sa_data, MAC_ADDR_LEN) != EOK) {
        DHCP_LOGE("GetLocalInterface() ifname:%{public}s failed, memcpy_s error!", ifname);
        close(fd);
        return DHCP_OPT_FAILED;
    }

    if (ifaddr4 != NULL) {
        if (ioctl(fd, SIOCGIFADDR, &iface) < 0) {
            DHCP_LOGE("GetLocalInterface() %{public}s failed, SIOCGIFADDR err:%{public}d!", ifname, errno);
            close(fd);
            return DHCP_OPT_FAILED;
        }
        pSockIn = (struct sockaddr_in *)&iface.ifr_addr;
        *ifaddr4 = pSockIn->sin_addr.s_addr;
    }
    close(fd);
    return DHCP_OPT_SUCCESS;
}

int GetLocalIp(const char *ifname, uint32_t *ifaddr4)
{
    if ((ifname == NULL) || (strlen(ifname) == 0)) {
        DHCP_LOGE("GetLocalIp() failed, ifname == NULL or \"\"!");
        return DHCP_OPT_FAILED;
    }

    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa = NULL;
    int family, s;
    char strIp[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        DHCP_LOGE("GetLocalIp() ifname:%{public}s failed, getifaddrs error:%{public}d!", ifname, errno);
        return DHCP_OPT_FAILED;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, ifname) != 0) {
            continue;
        }

        if (ifa->ifa_addr == NULL) {
            DHCP_LOGE("GetLocalIp() ifname:%{public}s failed, ifa->ifa_addr == NULL!", ifname);
            continue;
        }

        family = ifa->ifa_addr->sa_family;
        if ((family != AF_INET) && (family != AF_INET6)) {
            continue;
        }

        if (memset_s(strIp, sizeof(strIp), 0, sizeof(strIp)) != EOK) {
            return DHCP_OPT_FAILED;
        }
        s = getnameinfo(ifa->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
            strIp, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        if (s != 0) {
            DHCP_LOGE("GetLocalIp() %{public}s failed, getnameinfo error:%{public}s!", ifname, gai_strerror(s));
            return DHCP_OPT_FAILED;
        }

        /* Output all ip with ifa_name is ifname and family is AF_INET or AF_INET6. */
        if (family == AF_INET) {
            uint32_t hostIp = 0;
            if (!Ip4StrConToInt(strIp, &hostIp, true)) {
                DHCP_LOGE("GetLocalIp() %{public}s failed, Ip4StrConToInt strIp:%{private}s error!", ifname, strIp);
                return DHCP_OPT_FAILED;
            }
            DHCP_LOGI("GetLocalIp() %{public}s, AF_INET str:%{private}s -> host:%{private}u.", ifname, strIp, hostIp);
            *ifaddr4 = hostIp;
        } else {
            DHCP_LOGI("GetLocalIp() %{public}s, AF_INET6 strIp:%{private}s.", ifname, strIp);
        }
    }

    freeifaddrs(ifaddr);
    return DHCP_OPT_SUCCESS;
}

int SetIpOrMask(const char *ifname, int fd, uint32_t netAddr, unsigned long cmd)
{
    struct ifreq ifr;
    struct sockaddr_in sin;
    if (memset_s(&ifr, sizeof(struct ifreq), 0, sizeof(struct ifreq)) != EOK) {
        DHCP_LOGE("SetIpOrMask() failed, memset_s ifr error!");
        return DHCP_OPT_FAILED;
    }

    if (strncpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), ifname, strlen(ifname)) != EOK) {
        DHCP_LOGE("SetIpOrMask() %{public}s failed, , strncpy_s ifr.ifr_name error!", ifname);
        return DHCP_OPT_FAILED;
    }

    if (memset_s(&sin, sizeof(struct sockaddr_in), 0, sizeof(struct sockaddr_in)) != EOK) {
        DHCP_LOGE("SetIpOrMask() failed, memset_s sin error!");
        return DHCP_OPT_FAILED;
    }
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = netAddr;
    if (memcpy_s(&ifr.ifr_addr, sizeof(ifr.ifr_addr), &sin, sizeof(struct sockaddr)) != EOK) {
        DHCP_LOGE("SetIpOrMask() failed, memcpy_s ifr.ifr_addr error!");
        return DHCP_OPT_FAILED;
    }

    if (ioctl(fd, cmd, &ifr) < 0) {
        DHCP_LOGE("SetIpOrMask() %{public}s failed!", ifname);
        return DHCP_OPT_FAILED;
    }
    return DHCP_OPT_SUCCESS;
}

int SetLocalInterface(const char *ifname, uint32_t ipAddr, uint32_t netMask)
{
    if ((ifname == NULL) || (strlen(ifname) == 0)) {
        DHCP_LOGE("SetLocalInterface() failed, ifname == NULL or \"\"!");
        return DHCP_OPT_FAILED;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        DHCP_LOGE("SetLocalInterface() ifname:%{public}s failed, socket error:%{public}d!", ifname, errno);
        return DHCP_OPT_FAILED;
    }

    if (SetIpOrMask(ifname, fd, ipAddr, SIOCSIFADDR) != DHCP_OPT_SUCCESS) {
        close(fd);
        return DHCP_OPT_FAILED;
    }

    if (SetIpOrMask(ifname, fd, netMask, SIOCSIFNETMASK) != DHCP_OPT_SUCCESS) {
        close(fd);
        return DHCP_OPT_FAILED;
    }
    close(fd);
    return DHCP_OPT_SUCCESS;
}

int CreateDirs(const char *dirs, int mode)
{
    if ((dirs == NULL) || (strlen(dirs) == 0) || (strlen(dirs) >= DIR_MAX_LEN)) {
        DHCP_LOGE("CreateDirs() dirs:%{public}s error!", dirs);
        return DHCP_OPT_FAILED;
    }

    int nSrcLen = (int)strlen(dirs);
    char strDir[DIR_MAX_LEN] = {0};
    if (strncpy_s(strDir, sizeof(strDir), dirs, strlen(dirs)) != EOK) {
        DHCP_LOGE("CreateDirs() strncpy_s dirs:%{public}s failed!", dirs);
        return DHCP_OPT_FAILED;
    }
    if (strDir[nSrcLen - 1] != '/') {
        if (nSrcLen == (DIR_MAX_LEN - 1)) {
            DHCP_LOGE("CreateDirs() dirs:%{public}s len:%{public}d error!", dirs, nSrcLen);
            return DHCP_OPT_FAILED;
        }
        if (strcat_s(strDir, sizeof(strDir), "/") != EOK) {
            DHCP_LOGE("CreateDirs() strcat_s strDir:%{public}s failed!", strDir);
            return DHCP_OPT_FAILED;
        }
        nSrcLen++;
    }

    int i = (strDir[0] == '/') ? 1 : 0;
    for (; i <= nSrcLen - 1; i++) {
        if (strDir[i] == '/') {
            strDir[i] = 0;
            if ((access(strDir, F_OK) != 0) && (mkdir(strDir, mode) != 0)) {
                DHCP_LOGE("CreateDirs() mkdir %{public}s %{public}.4o failed:%{public}d!", strDir, mode, errno);
                return DHCP_OPT_FAILED;
            }
            strDir[i] = '/';
        }
    }
    DHCP_LOGI("CreateDirs() %{public}s %{public}.4o success.", dirs, mode);
    return DHCP_OPT_SUCCESS;
}
