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

#include "dhcpfunction_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "securec.h"
#include "dhcp_function.h"

namespace OHOS {
namespace DHCP {
constexpr size_t DHCP_SLEEP_1 = 2;
constexpr int TWO = 2;

std::shared_ptr<DhcpFunction> pDhcpFunction = std::make_shared<DhcpFunction>();

void Ip4StrConToIntTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    uint32_t uIp = static_cast<uint32_t>(data[index++]);
    std::string strIp = std::string(reinterpret_cast<const char*>(data), size);
    bool bHost = (static_cast<int>(data[0]) % TWO) ? true : false;
    pDhcpFunction->Ip4StrConToInt(strIp, uIp, bHost);
}

void Ip6StrConToCharTest(const uint8_t* data, size_t size)
{
    std::string strIp = std::string(reinterpret_cast<const char*>(data), size);
    uint8_t	chIp[sizeof(struct in6_addr)] = {0};
    pDhcpFunction->Ip6StrConToChar(strIp, chIp, sizeof(struct in6_addr));
}

void CheckIpStrTest(const uint8_t* data, size_t size)
{
    std::string strIp = std::string(reinterpret_cast<const char*>(data), size);
    pDhcpFunction->CheckIpStr(strIp);
}

void IsExistFileTest(const uint8_t* data, size_t size)
{
    std::string filename = std::string(reinterpret_cast<const char*>(data), size);
    pDhcpFunction->IsExistFile(filename);
}

void CreateFileTest(const uint8_t* data, size_t size)
{
    std::string filename = std::string(reinterpret_cast<const char*>(data), size);
    std::string filedata = std::string(reinterpret_cast<const char*>(data), size);
    pDhcpFunction->CreateFile(filename, filedata);
}

void RemoveFileTest(const uint8_t* data, size_t size)
{
    std::string filename = std::string(reinterpret_cast<const char*>(data), size);
    pDhcpFunction->RemoveFile(filename);
}

void FormatStringTest(const uint8_t* data, size_t size)
{
    struct DhcpPacketResult result;
    memset_s(&result, sizeof(result), 0, sizeof(result));
    strncpy_s(result.strYiaddr, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1);
    strncpy_s(result.strOptServerId, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1);
    strncpy_s(result.strOptSubnet, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1);
    strncpy_s(result.strOptDns1, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1);
    strncpy_s(result.strOptDns2, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1);
    strncpy_s(result.strOptRouter1, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1);
    strncpy_s(result.strOptRouter2, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1);
    strncpy_s(result.strOptVendor, DHCP_FILE_MAX_BYTES, "*", DHCP_FILE_MAX_BYTES - 1);
    pDhcpFunction->FormatString(result);
}

void CreateDirsTest(const uint8_t* data, size_t size)
{
    int mode = DIR_DEFAULT_MODE;
    std::string dirs = std::string(reinterpret_cast<const char*>(data), size);
    pDhcpFunction->CreateDirs(dirs, mode);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    sleep(DHCP_SLEEP_1);
    OHOS::DHCP::Ip4StrConToIntTest(data, size);
    OHOS::DHCP::Ip6StrConToCharTest(data, size);
    OHOS::DHCP::CheckIpStrTest(data, size);
    OHOS::DHCP::IsExistFileTest(data, size);
    OHOS::DHCP::CreateFileTest(data, size);
    OHOS::DHCP::RemoveFileTest(data, size);
    OHOS::DHCP::FormatStringTest(data, size);
    OHOS::DHCP::CreateDirsTest(data, size);
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS
