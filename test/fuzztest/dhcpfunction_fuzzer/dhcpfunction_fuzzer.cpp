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
#include <algorithm>
#include "securec.h"
#include "dhcp_function.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace DHCP {
FuzzedDataProvider *FDP = nullptr;
const int32_t NUM_BYTES = 1;
constexpr size_t DHCP_SLEEP_1 = 2;
std::shared_ptr<DhcpFunction> pDhcpFunction = std::make_shared<DhcpFunction>();

void Ip4StrConToIntTest()
{
    uint32_t uIp = FDP->ConsumeIntegral<uint32_t>();
    std::string strIp = FDP->ConsumeBytesAsString(NUM_BYTES);
    bool bHost = FDP->ConsumeBool();
    pDhcpFunction->Ip4StrConToInt(strIp, uIp, bHost);
}

void Ip6StrConToCharTest()
{
    std::string strIp = FDP->ConsumeBytesAsString(NUM_BYTES);
    uint8_t	chIp[sizeof(struct in6_addr)] = {0};
    pDhcpFunction->Ip6StrConToChar(strIp, chIp, sizeof(struct in6_addr));
}

void CheckIpStrTest()
{
    std::string strIp = FDP->ConsumeBytesAsString(NUM_BYTES);
    pDhcpFunction->CheckIpStr(strIp);
}

void IsExistFileTest()
{
    std::string filename = FDP->ConsumeBytesAsString(NUM_BYTES);
    pDhcpFunction->IsExistFile(filename);
}

void CreateFileTest()
{
    std::string filename = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string filedata = FDP->ConsumeBytesAsString(NUM_BYTES);
    pDhcpFunction->CreateFile(filename, filedata);
}

void RemoveFileTest()
{
    std::string filename = FDP->ConsumeBytesAsString(NUM_BYTES);
    pDhcpFunction->RemoveFile(filename);
}

void FormatStringTest()
{
    struct DhcpPacketResult result;
    memset_s(&result, sizeof(result), 0, sizeof(result));
    std::string strYiaddr_str = FDP->ConsumeBytesAsString(INET_ADDRSTRLEN);
    strncpy_s(result.strYiaddr, INET_ADDRSTRLEN, strYiaddr_str.c_str(), INET_ADDRSTRLEN - 1);
    std::string strOptServerId_str = FDP->ConsumeBytesAsString(INET_ADDRSTRLEN);
    strncpy_s(result.strOptServerId, INET_ADDRSTRLEN, strOptServerId_str.c_str(), INET_ADDRSTRLEN - 1);
    std::string strOptSubnet_str = FDP->ConsumeBytesAsString(INET_ADDRSTRLEN);
    strncpy_s(result.strOptSubnet, INET_ADDRSTRLEN, strOptSubnet_str.c_str(), INET_ADDRSTRLEN - 1);
    std::string strOptDns1_str = FDP->ConsumeBytesAsString(INET_ADDRSTRLEN);
    strncpy_s(result.strOptDns1, INET_ADDRSTRLEN, strOptDns1_str.c_str(), INET_ADDRSTRLEN - 1);
    std::string strOptDns2_str = FDP->ConsumeBytesAsString(INET_ADDRSTRLEN);
    strncpy_s(result.strOptDns2, INET_ADDRSTRLEN, strOptDns2_str.c_str(), INET_ADDRSTRLEN - 1);
    std::string strOptRouter1_str = FDP->ConsumeBytesAsString(INET_ADDRSTRLEN);
    strncpy_s(result.strOptRouter1, INET_ADDRSTRLEN, strOptRouter1_str.c_str(), INET_ADDRSTRLEN - 1);
    std::string strOptRouter2_str = FDP->ConsumeBytesAsString(INET_ADDRSTRLEN);
    strncpy_s(result.strOptRouter2, INET_ADDRSTRLEN, strOptRouter2_str.c_str(), INET_ADDRSTRLEN - 1);
    std::string strOptVendor_str = FDP->ConsumeBytesAsString(DHCP_FILE_MAX_BYTES);
    strncpy_s(result.strOptVendor, DHCP_FILE_MAX_BYTES, strOptVendor_str.c_str(), DHCP_FILE_MAX_BYTES - 1);
    pDhcpFunction->FormatString(result);
}

void CreateDirsTest()
{
    int mode = DIR_DEFAULT_MODE;
    std::string dirs = FDP->ConsumeBytesAsString(NUM_BYTES);
    pDhcpFunction->CreateDirs(dirs, mode);
}


void GetLocalMacTest()
{
    std::string ethInf = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string ethMac = FDP->ConsumeBytesAsString(NUM_BYTES);
    pDhcpFunction->GetLocalMac(ethInf, ethMac);
}

void CheckRangeNetworkTest()
{
    std::string strInf = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string strBegin = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string strEnd = FDP->ConsumeBytesAsString(NUM_BYTES);
    pDhcpFunction->CheckRangeNetwork(strInf, strBegin, strEnd);
}

void CheckSameNetworkTest()
{
    uint32_t srcIp = FDP->ConsumeIntegral<uint32_t>();
    uint32_t dstIp = FDP->ConsumeIntegral<uint32_t>();
    uint32_t maskIp = FDP->ConsumeIntegral<uint32_t>();
    pDhcpFunction->CheckSameNetwork(srcIp, dstIp, maskIp);
}

void DhcpFunctionFuzzTest()
{
    OHOS::DHCP::Ip4StrConToIntTest();
    OHOS::DHCP::Ip6StrConToCharTest();
    OHOS::DHCP::CheckIpStrTest();
    OHOS::DHCP::IsExistFileTest();
    OHOS::DHCP::CreateFileTest();
    OHOS::DHCP::RemoveFileTest();
    OHOS::DHCP::FormatStringTest();
    OHOS::DHCP::CreateDirsTest();
    OHOS::DHCP::GetLocalMacTest();
    OHOS::DHCP::CheckRangeNetworkTest();
    OHOS::DHCP::CheckSameNetworkTest();
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }
    sleep(DHCP_SLEEP_1);
    FuzzedDataProvider fdp(data, size);
    FDP = &fdp;
    OHOS::DHCP::DhcpFunctionFuzzTest();
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS
