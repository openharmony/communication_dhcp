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

#ifndef OHOS_FUNCTION_H
#define OHOS_FUNCTION_H

#include <cstring>
#include <iomanip>
#include <arpa/inet.h>
#include <string>
#include <cstdio>

#include "dhcp_define.h"

namespace OHOS {
namespace DHCP {
class DhcpFunction {
public:
    DhcpFunction() {}
    ~DhcpFunction() {}

    static bool Ip4StrConToInt(const std::string& strIp, uint32_t& uIp, bool bHost = true);
    static bool Ip6StrConToChar(const std::string& strIp, uint8_t chIp[], size_t uSize);
    static std::string Ip6CharConToStr(uint8_t chIp[], int size);
    static bool CheckIpStr(const std::string& strIp);
    static int GetLocalIp(const std::string strInf, std::string& strIp, std::string& strMask);
    static int GetLocalMac(const std::string ethInf, std::string& ethMac);
    static int CheckRangeNetwork(const std::string strInf, const std::string strBegin, const std::string strEnd);
    static bool CheckSameNetwork(const uint32_t srcIp, const uint32_t dstIp, const uint32_t maskIp);

    static bool IsExistFile(const std::string& filename);
    static bool CreateFile(const std::string& filename, const std::string& filedata);
    static bool RemoveFile(const std::string& filename);
    static int FormatString(struct DhcpPacketResult &result);
    static int CreateDirs(const std::string dirs, int mode = DIR_DEFAULT_MODE);
#ifdef OHOS_ARCH_LITE
    static int GetDhcpPacketResult(const std::string& filename, struct DhcpPacketResult &result);
#else
#endif
};
}  // namespace DHCP
}  // namespace OHOS
#endif