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
#include <cstring>
 
#include "securec.h"
#include "dhcp_logger.h"
#include "dhcp_dhcpd.h"
#include "dhcp_config.h"
#include "address_utils.h"
#include "dhcp_fuzz_common_func.h"
#include "dhcpdhcpd_fuzzer.h"
 
using namespace std;
namespace OHOS {
namespace DHCP {
 
constexpr size_t U32_AT_SIZE_ZERO = 4;
constexpr size_t MIN_STRING_SIZE = 8;
constexpr size_t MAX_IP_STRING_SIZE = 16;
constexpr size_t MAX_INTERFACE_NAME_SIZE = 16;
 
void TestStartDhcpServerMain(const uint8_t* data, size_t size)
{
    if (size < U32_AT_SIZE_ZERO * 4 + MIN_STRING_SIZE * 4) {
        return;
    }
    
    size_t pos = 0;
    
    uint32_t ifNameLen = U32_AT(data + pos) % MAX_INTERFACE_NAME_SIZE;
    pos += sizeof(uint32_t);
    if (pos + ifNameLen > size) {
        return;
    }
    string ifName(reinterpret_cast<const char*>(data + pos), ifNameLen);
    pos += ifNameLen;
    
    if (pos + sizeof(uint32_t) > size) {
        return;
    }
    uint32_t netMaskLen = U32_AT(data + pos) % MAX_IP_STRING_SIZE;
    pos += sizeof(uint32_t);
    if (pos + netMaskLen > size) {
        return;
    }
    string netMask(reinterpret_cast<const char*>(data + pos), netMaskLen);
    pos += netMaskLen;
    
    if (pos + sizeof(uint32_t) > size) {
        return;
    }
    uint32_t ipRangeLen = U32_AT(data + pos) % (MAX_IP_STRING_SIZE * 2);
    pos += sizeof(uint32_t);
    if (pos + ipRangeLen > size) {
        return;
    }
    string ipRange(reinterpret_cast<const char*>(data + pos), ipRangeLen);
    pos += ipRangeLen;
    
    if (pos + sizeof(uint32_t) > size) {
        return;
    }
    uint32_t localIpLen = U32_AT(data + pos) % MAX_IP_STRING_SIZE;
    pos += sizeof(uint32_t);
    if (pos + localIpLen > size) {
        return;
    }
    string localIp(reinterpret_cast<const char*>(data + pos), localIpLen);
    
    if (!ifName.empty()) {
        ifName[ifName.length() - 1] = '\0';
    }
    if (!netMask.empty()) {
        netMask[netMask.length() - 1] = '\0';
    }
    if (!ipRange.empty()) {
        ipRange[ipRange.length() - 1] = '\0';
    }
    if (!localIp.empty()) {
        localIp[localIp.length() - 1] = '\0';
    }
    
}
 
void TestStopDhcpServerMain(const uint8_t* data, size_t size)
{

}
 
void TestRegisterDeviceConnectCallBack(const uint8_t* data, size_t size)
{
    DeviceConnectFun testCallback = [](const char* ifname) {
        if (ifname) {

        }
    };
    
    RegisterDeviceConnectCallBack(testCallback);
    
    RegisterDeviceConnectCallBack(nullptr);
}
 
void TestParseIpAddr(const uint8_t* data, size_t size)
{
    if (size < U32_AT_SIZE_ZERO) {
        return;
    }
    
    size_t pos = 0;
    uint32_t ipStringLen = U32_AT(data + pos) % MAX_IP_STRING_SIZE;
    pos += sizeof(uint32_t);
    
    if (pos + ipStringLen > size) {
        return;
    }
    
    string ipString(reinterpret_cast<const char*>(data + pos), ipStringLen);
    if (!ipString.empty()) {
        ipString[ipString.length() - 1] = '\0';
        
        ParseIpAddr(ipString.c_str());
    }
}
 
void TestDhcpConfigOperations(const uint8_t* data, size_t size)
{
    if (size < sizeof(DhcpConfig)) {
        return;
    }
    
    DhcpConfig config;
    if (memset_s(&config, sizeof(DhcpConfig), 0, sizeof(DhcpConfig)) != EOK) {
        return;
    }
    
    size_t pos = 0;
    if (size >= pos + sizeof(uint32_t)) {
        config.serverId = U32_AT(data + pos);
        pos += sizeof(uint32_t);
    }
    
    if (size >= pos + sizeof(uint32_t)) {
        config.netmask = U32_AT(data + pos);
        pos += sizeof(uint32_t);
    }
    
    if (size >= pos + sizeof(uint32_t)) {
        config.gateway = U32_AT(data + pos);
        pos += sizeof(uint32_t);
    }
    
    if (size >= pos + sizeof(uint32_t)) {
        config.pool.beginAddress = U32_AT(data + pos);
        pos += sizeof(uint32_t);
    }
    
    if (size >= pos + sizeof(uint32_t)) {
        config.pool.endAddress = U32_AT(data + pos);
        pos += sizeof(uint32_t);
    }
    
    if (size >= pos + sizeof(uint32_t)) {
        config.leaseTime = U32_AT(data + pos);
        pos += sizeof(uint32_t);
    }
    
    if (size >= pos + sizeof(uint32_t)) {
        config.renewalTime = U32_AT(data + pos);
        pos += sizeof(uint32_t);
    }
    
    if (size >= pos + sizeof(uint32_t)) {
        config.rebindingTime = U32_AT(data + pos);
        pos += sizeof(uint32_t);
    }
    
    if (size >= pos + IFACE_NAME_SIZE) {
        if (memcpy_s(config.ifname, IFACE_NAME_SIZE, data + pos, IFACE_NAME_SIZE) != EOK) {
            return;
        }
        config.ifname[IFACE_NAME_SIZE - 1] = '\0';
    }
    
}
 
void TestArgumentOperations(const uint8_t* data, size_t size)
{
    if (size < U32_AT_SIZE_ZERO + MIN_STRING_SIZE * 2) {
        return;
    }
    
    size_t pos = 0;
    uint32_t keyLen = U32_AT(data + pos) % 32;
    pos += sizeof(uint32_t);
    
    if (pos + keyLen > size) {
        return;
    }
    
    string argKey(reinterpret_cast<const char*>(data + pos), keyLen);
    pos += keyLen;
    
    if (pos + sizeof(uint32_t) > size) {
        return;
    }
    
    uint32_t valueLen = U32_AT(data + pos) % 64;
    pos += sizeof(uint32_t);
    
    if (pos + valueLen > size) {
        return;
    }
    
    string argValue(reinterpret_cast<const char*>(data + pos), valueLen);
    
    if (!argKey.empty()) {
        argKey[argKey.length() - 1] = '\0';
    }
    if (!argValue.empty()) {
        argValue[argValue.length() - 1] = '\0';
    }
    
}
 
void TestStringOperations(const uint8_t* data, size_t size)
{
    if (size < U32_AT_SIZE_ZERO) {
        return;
    }
    
    size_t pos = 0;
    uint32_t strLen = U32_AT(data + pos) % 256;
    pos += sizeof(uint32_t);
    
    if (pos + strLen > size) {
        return;
    }
    
    vector<char> testString(strLen + 1, 0);
    if (strLen > 0) {
        if (memcpy_s(testString.data(), strLen, data + pos, strLen) != EOK) {
            return;
        }
    }
    testString[strLen] = '\0';
    
    if (strLen > 0) {
        ParseIpAddr(testString.data());
    }
}
 
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::DHCP::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    
    TestStartDhcpServerMain(data, size);
    TestStopDhcpServerMain(data, size);
    TestRegisterDeviceConnectCallBack(data, size);
    TestParseIpAddr(data, size);
    TestDhcpConfigOperations(data, size);
    TestArgumentOperations(data, size);
    TestStringOperations(data, size);
    
    return 0;
}
 
}  // namespace DHCP
}  // namespace OHOS