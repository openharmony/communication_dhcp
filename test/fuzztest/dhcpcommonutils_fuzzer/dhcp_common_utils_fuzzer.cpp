/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <regex>
#include <malloc.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>

#include "securec.h"
#include "dhcp_logger.h"
#include "dhcp_common_utils.h"
#include "dhcp_fuzz_common_func.h"
using namespace std;
namespace OHOS {
namespace DHCP {
constexpr size_t U32_AT_SIZE_ZERO = 4;
constexpr size_t INDEX = 4;
constexpr size_t SIZEOFHOST = 5;
void TestIpv6Anonymize(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < U32_AT_SIZE_ZERO) {
        return;
    }
    size_t pos = 0;
    uint32_t strLen = U32_AT(data);
    pos += sizeof(uint32_t);
    if (pos + strLen > size) {
        return;
    }
    string str(reinterpret_cast<const char*>(data + pos), strLen);
    
    Ipv6Anonymize(str);
}

void TestIpv4Anonymize(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < U32_AT_SIZE_ZERO) {
        return;
    }
    size_t pos = 0;
    uint32_t strLen = U32_AT(data);
    pos += sizeof(uint32_t);
    if (pos + strLen > size) {
        return;
    }
    string str(reinterpret_cast<const char*>(data + pos), strLen);
    
    Ipv4Anonymize(str);
}

void TestUintIp4ToStr(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < U32_AT_SIZE_ZERO) {
        return;
    }
    uint32_t uIp = U32_AT(data);
    // Check if the size is sufficient for the host flag
    // If size is less than 5, we assume the host flag is false
    bool bHost = (size >= SIZEOFHOST) ? (data[INDEX] != 0) : false;

    UintIp4ToStr(uIp, bHost);
}

void TestIntIpv4ToAnonymizeStr(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < U32_AT_SIZE_ZERO) {
        return;
    }
    uint32_t ip = U32_AT(data);
    
    IntIpv4ToAnonymizeStr(ip);
}

void TestMacArray2Str(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < U32_AT_SIZE_ZERO) {
        return;
    }
    size_t pos = 0;
    uint32_t macArrayLen = U32_AT(data);
    pos += sizeof(uint32_t);
    if (pos + macArrayLen > size) {
        return;
    }
    uint8_t macArray[ETH_ALEN];
    if (macArrayLen > 0) {
        if (memcpy_s(macArray, ETH_ALEN, data + pos, macArrayLen) != 0) {
            return;
        }
    }
    int32_t len = static_cast<int32_t>(macArrayLen);
    MacArray2Str(macArray, len);
}

void TestCheckDataLegal(const uint8_t* data, size_t size)
{
    if (size < U32_AT_SIZE_ZERO) {
        return;
    }
    size_t pos = 0;
    uint32_t dataLen = U32_AT(data);
    pos += sizeof(uint32_t);
    if (pos + dataLen > size) {
        return;
    }
    string dataStr(reinterpret_cast<const char*>(data + pos), dataLen);
    pos += dataLen;
    int base = (size >= pos + U32_AT_SIZE_ZERO) ? static_cast<int>(U32_AT(data + pos)) : DECIMAL_NOTATION;

    CheckDataLegal(dataStr, base);
}

void TestCheckDataToUint(const uint8_t* data, size_t size)
{
    if (size < U32_AT_SIZE_ZERO) {
        return;
    }
    size_t pos = 0;
    uint32_t dataLen = U32_AT(data);
    pos += sizeof(uint32_t);
    if (pos + dataLen > size) {
        return;
    }
    string dataStr(reinterpret_cast<const char*>(data + pos), dataLen);
    pos += dataLen;
    int base = (size >= pos + U32_AT_SIZE_ZERO) ? static_cast<int>(U32_AT(data + pos)) : DECIMAL_NOTATION;

    CheckDataToUint(dataStr, base);
}

void TestCheckDataTolonglong(const uint8_t* data, size_t size)
{
    if (size < U32_AT_SIZE_ZERO) {
        return;
    }
    size_t pos = 0;
    uint32_t dataLen = U32_AT(data);
    pos += sizeof(uint32_t);
    if (pos + dataLen > size) {
        return;
    }
    string dataStr(reinterpret_cast<const char*>(data + pos), dataLen);
    pos += dataLen;
    int base = (size >= pos + U32_AT_SIZE_ZERO) ? static_cast<int>(U32_AT(data + pos)) : DECIMAL_NOTATION;

    CheckDataTolonglong(dataStr, base);
}

void TestCheckDataToUint64(const uint8_t* data, size_t size)
{
    if (size < U32_AT_SIZE_ZERO) {
        return;
    }
    size_t pos = 0;
    uint32_t dataLen = U32_AT(data);
    pos += sizeof(uint32_t);
    if (pos + dataLen > size) {
        return;
    }
    string dataStr(reinterpret_cast<const char*>(data + pos), dataLen);
    pos += dataLen;
    int base = (size >= pos + U32_AT_SIZE_ZERO) ? static_cast<int>(U32_AT(data + pos)) : DECIMAL_NOTATION;

    CheckDataToUint64(dataStr, base);
}

void TestGetElapsedSecondsSinceBoot(const uint8_t* data, size_t size)
{
    GetElapsedSecondsSinceBoot();
}

void TestIp4IntConvertToStr(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < U32_AT_SIZE_ZERO) {
        return;
    }
    uint32_t uIp = U32_AT(data);
    bool bHost = (size >= SIZEOFHOST) ? (data[INDEX] != 0) : false;

    Ip4IntConvertToStr(uIp, bHost);
}

void TestAddArpEntry(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < U32_AT_SIZE_ZERO) {
        return;
    }
    size_t pos = 0;

    // Check if we have enough data for the first U32_AT call
    if (pos + sizeof(uint32_t) > size) {
        return;
    }
    uint32_t ifaceLen = U32_AT(data + pos);
    pos += sizeof(uint32_t);
    // Validate ifaceLen to prevent integer overflow and excessive memory allocation
    if (ifaceLen > size || pos + ifaceLen > size) {
        return;
    }
    string iface(reinterpret_cast<const char*>(data + pos), ifaceLen);
    pos += ifaceLen;

    // Check if we have enough data for the second U32_AT call
    if (pos + sizeof(uint32_t) > size) {
        return;
    }
    uint32_t ipAddrLen = U32_AT(data + pos);
    pos += sizeof(uint32_t);

    // Validate ipAddrLen to prevent integer overflow and excessive memory allocation
    if (ipAddrLen > size || pos + ipAddrLen > size) {
        return;
    }
    string ipAddr(reinterpret_cast<const char*>(data + pos), ipAddrLen);
    pos += ipAddrLen;

    // Check if we have enough data for the third U32_AT call
    if (pos + sizeof(uint32_t) > size) {
        return;
    }
    uint32_t macAddrLen = U32_AT(data + pos);
    pos += sizeof(uint32_t);

    // Validate macAddrLen to prevent integer overflow and excessive memory allocation
    if (macAddrLen > size || pos + macAddrLen > size) {
        return;
    }
    string macAddr(reinterpret_cast<const char*>(data + pos), macAddrLen);

    AddArpEntry(iface, ipAddr, macAddr);
}

void TestIsValidPath(const uint8_t* data, size_t size)
{
    if (size < U32_AT_SIZE_ZERO) {
        return;
    }
    size_t pos = 0;
    uint32_t filePathLen = U32_AT(data);
    pos += sizeof(uint32_t);
    if (pos + filePathLen > size) {
        return;
    }
    string filePath(reinterpret_cast<const char*>(data + pos), filePathLen);
    
    IsValidPath(filePath);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::DHCP::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    
    // 直接运行所有测试函数
    TestIpv6Anonymize(data, size);
    TestIpv4Anonymize(data, size);
    TestUintIp4ToStr(data, size);
    TestIntIpv4ToAnonymizeStr(data, size);
    TestMacArray2Str(data, size);
    TestCheckDataLegal(data, size);
    TestCheckDataToUint(data, size);
    TestCheckDataTolonglong(data, size);
    TestCheckDataToUint64(data, size);
    TestGetElapsedSecondsSinceBoot(data, size);
    TestIp4IntConvertToStr(data, size);
    TestAddArpEntry(data, size);
    TestIsValidPath(data, size);
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS
