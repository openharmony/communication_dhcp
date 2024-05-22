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

#include "dhcp_common_utils.h"
#include <string>

namespace OHOS {
namespace DHCP {

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
    char *strIp = (char *)malloc(INET_ADDRSTRLEN);
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
}
}
