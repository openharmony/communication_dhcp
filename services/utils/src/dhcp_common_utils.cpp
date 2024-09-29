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
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <unistd.h>

#include "dhcp_common_utils.h"
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <regex>
#include "securec.h"
#include "dhcp_logger.h"

namespace OHOS {
namespace DHCP {
DEFINE_DHCPLOG_DHCP_LABEL("DhcpCommonUtils");

constexpr int32_t GATEWAY_MAC_LENTH = 18;
constexpr int32_t MAC_INDEX_0 = 0;
constexpr int32_t MAC_INDEX_1 = 1;
constexpr int32_t MAC_INDEX_2 = 2;
constexpr int32_t MAC_INDEX_3 = 3;
constexpr int32_t MAC_INDEX_4 = 4;
constexpr int32_t MAC_INDEX_5 = 5;
constexpr int32_t MAC_LENTH = 6;

std::string Ipv4Anonymize(const std::string str)
{
    std::string strTemp = str;
    std::string::size_type begin = strTemp.find_last_of('.');
    while (begin < strTemp.length()) {
        if (strTemp[begin] != '.') {
            strTemp[begin] = '*';
        }
        begin++;
    }
    return strTemp;
}

char *UintIp4ToStr(uint32_t uIp, bool bHost)
{
    char bufIp4[INET_ADDRSTRLEN] = {0};
    struct in_addr addr4;
    if (bHost) {
        addr4.s_addr = htonl(uIp);
    } else {
        addr4.s_addr = uIp;
    }
    const char *p = inet_ntop(AF_INET, &addr4, bufIp4, INET_ADDRSTRLEN);
    if (p == nullptr) {
        DHCP_LOGE("UintIp4ToStr inet_ntop p == nullptr!");
        return nullptr;
    }
    char *strIp = static_cast<char *>(malloc(INET_ADDRSTRLEN));
    if (strIp == nullptr) {
        DHCP_LOGE("UintIp4ToStr strIp malloc failed!");
        return nullptr;
    }
    if (strncpy_s(strIp, INET_ADDRSTRLEN, bufIp4, strlen(bufIp4)) != EOK) {
        DHCP_LOGE("UintIp4ToStr strIp strncpy_s failed!");
        free(strIp);
        strIp = nullptr;
        return nullptr;
    }
    return strIp;
}

std::string IntIpv4ToAnonymizeStr(uint32_t ip)
{
    std::string strTemp = "";
    char *pIp = UintIp4ToStr(ip, false);
    if (pIp != nullptr) {
        strTemp = Ipv4Anonymize(pIp);
        free(pIp);
        pIp = nullptr;
    }
    return strTemp;
}

std::string MacArray2Str(uint8_t *macArray, int32_t len)
{
    if ((macArray == nullptr) || (len != ETH_ALEN)) {
        DHCP_LOGE("MacArray2Str arg is invalid!");
        return "";
    }

    char gwMacAddr[GATEWAY_MAC_LENTH] = {0};
    if (sprintf_s(gwMacAddr, sizeof(gwMacAddr), "%02x:%02x:%02x:%02x:%02x:%02x", macArray[MAC_INDEX_0],
        macArray[MAC_INDEX_1], macArray[MAC_INDEX_2], macArray[MAC_INDEX_3], macArray[MAC_INDEX_4],
        macArray[MAC_INDEX_5]) < 0) {
        DHCP_LOGE("MacArray2Str sprintf_s err");
        return "";
    }
    std::string ret = gwMacAddr;
    return ret;
}

int CheckDataLegal(std::string &data, int base)
{
    std::regex pattern("\\d+");
    if (!std::regex_search(data, pattern)) {
        return 0;
    }
    errno = 0;
    char *endptr = nullptr;
    long int num = std::strtol(data.c_str(), &endptr, base);
    if (errno == ERANGE) {
        DHCP_LOGE("CheckDataLegal errno == ERANGE, data:%{private}s", data.c_str());
        return 0;
    }
    return static_cast<int>(num);
}

unsigned int CheckDataToUint(std::string &data, int base)
{
    std::regex pattern("\\d+");
    std::regex patternTmp("-\\d+");
    if (!std::regex_search(data, pattern) || std::regex_search(data, patternTmp)) {
        DHCP_LOGE("CheckDataToUint regex unsigned int value fail, data:%{private}s", data.c_str());
        return 0;
    }
    errno = 0;
    char *endptr = nullptr;
    unsigned long int num = std::strtoul(data.c_str(), &endptr, base);
    if (errno == ERANGE) {
        DHCP_LOGE("CheckDataToUint errno == ERANGE, data:%{private}s", data.c_str());
        return 0;
    }
    return static_cast<unsigned int>(num);
}

long long CheckDataTolonglong(std::string &data, int base)
{
    std::regex pattern("\\d+");
    if (!std::regex_search(data, pattern)) {
        return 0;
    }
    errno = 0;
    char *endptr = nullptr;
    long long int num = std::strtoll(data.c_str(), &endptr, base);
    if (errno == ERANGE) {
        DHCP_LOGE("CheckDataTolonglong errno == ERANGE, data:%{private}s", data.c_str());
        return 0;
    }
    return num;
}

int64_t GetElapsedSecondsSinceBoot()
{
    struct timespec times = {0, 0};
    clock_gettime(CLOCK_BOOTTIME, &times);
    return static_cast<int64_t>(times.tv_sec);
}
}
}