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

#include "dhcpfunction2_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <algorithm>
#include <vector>
#include <string>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include "securec.h"
#include "dhcp_function.h"
#include "dhcp_client_def.h"

namespace OHOS {
namespace DHCP {
constexpr size_t DHCP_SLEEP_1 = 2;
constexpr int TWO = 2;

// Network address and buffer size constants
constexpr size_t IPV4_ADDR_SIZE = 4;
constexpr size_t IPV6_ADDR_SIZE = 16;
constexpr size_t MAC_ADDR_SIZE = 6;
constexpr size_t INTERFACE_NAME_MAX_LEN = 16;
constexpr size_t MAC_STRING_MAX_LEN = 20;
constexpr size_t MAC_STRING_LONG_LEN = 50;
constexpr size_t MAC_STRING_SHORT_LEN = 10;
constexpr size_t LARGE_BUFFER_SIZE = 1024;
constexpr size_t VERY_LARGE_BUFFER_SIZE = 2048;

// IP address range constants
constexpr size_t MAX_TEST_SIZE_RANGE = 20;
constexpr size_t MAX_MAC_TEST_LENGTH = 12;

// File permission constants
constexpr int DIR_MODE_755 = 0755;
constexpr int DIR_MODE_777 = 0777;
constexpr int DIR_MODE_644 = 0644;
constexpr int DIR_MODE_600 = 0600;
constexpr int DIR_MODE_700 = 0700;
constexpr int DIR_MODE_444 = 0444;
constexpr int DIR_PERMISSION_MASK = 0777;

// Array size and index constants
constexpr size_t PATH_COMPONENT_SIZE = 4;
constexpr size_t MIN_INTERFACE_TEST_SIZE = 9;
constexpr size_t LOOP_START_INDEX = 0;
constexpr int FUNCTION_SUCCESS = 0;
constexpr size_t DATA_PARTITION_COUNT = 3;  // For dividing input data into parts

void Ip4StrConToIntTest(const uint8_t* data, size_t size)
{
    if (size == LOOP_START_INDEX) {
        return;
    }
    
    // Create IP string from fuzz data
    std::string strIp = std::string(reinterpret_cast<const char*>(data), size);
    uint32_t uIp = LOOP_START_INDEX;
    bool bHost = (data[LOOP_START_INDEX] % TWO) ? true : false;
    
    // Test normal case
    Ip4StrConToInt(strIp.c_str(), &uIp, bHost);
    
    // Test with null pointer
    Ip4StrConToInt(nullptr, &uIp, bHost);
    Ip4StrConToInt(strIp.c_str(), nullptr, bHost);
    
    // Test with empty string
    Ip4StrConToInt("", &uIp, bHost);
    
    // Test with common IP addresses
    const std::vector<std::string> commonIps = {
        "127.0.0.1",
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "0.0.0.0",
    };
    
    for (const auto& ip : commonIps) {
        uint32_t testIp = LOOP_START_INDEX;
        Ip4StrConToInt(ip.c_str(), &testIp, true);
        Ip4StrConToInt(ip.c_str(), &testIp, false);
    }
    
    // Test with invalid IP addresses
    const std::vector<std::string> invalidIps = {
        "256.256.256.256",
        "999.999.999.999",
        "192.168.1",
        "192.168.1.1.1",
        "abc.def.ghi.jkl",
        "192.168.1.-1",
        "192.168.1.300"
    };
    
    for (const auto& ip : invalidIps) {
        uint32_t testIp = LOOP_START_INDEX;
        Ip4StrConToInt(ip.c_str(), &testIp, bHost);
    }
}

void Ip6StrConToCharTest(const uint8_t* data, size_t size)
{
    if (size == LOOP_START_INDEX) {
        return;
    }
    
    // Create IPv6 string from fuzz data
    std::string strIp = std::string(reinterpret_cast<const char*>(data), size);
    uint8_t chIp[IPV6_ADDR_SIZE] = {LOOP_START_INDEX};
    
    // Test normal case
    Ip6StrConToChar(strIp.c_str(), chIp, sizeof(chIp));
    
    // Test with null pointer
    Ip6StrConToChar(nullptr, chIp, sizeof(chIp));
    Ip6StrConToChar(strIp.c_str(), nullptr, sizeof(chIp));
    
    // Test with empty string
    Ip6StrConToChar("", chIp, sizeof(chIp));
    
    // Test with common IPv6 addresses
    const std::vector<std::string> commonIp6s = {
        "::1",
        "::",
        "2001:db8::1",
        "fe80::1",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "2001:db8:85a3::8a2e:370:7334",
        "::ffff:192.168.1.1"
    };
    
    for (const auto& ip6 : commonIp6s) {
        uint8_t testIp6[IPV6_ADDR_SIZE] = {LOOP_START_INDEX};
        Ip6StrConToChar(ip6.c_str(), testIp6, sizeof(testIp6));
    }
    
    // Test with different buffer sizes
    if (size > 1) {
        size_t testSize = (data[LOOP_START_INDEX] % MAX_TEST_SIZE_RANGE) + 1; // 1-20 bytes
        uint8_t testBuf[MAX_TEST_SIZE_RANGE] = {LOOP_START_INDEX};
        Ip6StrConToChar(strIp.c_str(), testBuf, testSize);
    }
    
    // Test with invalid IPv6 addresses
    const std::vector<std::string> invalidIp6s = {
        "gggg::1",
        "2001:db8::1::2",
        "2001:db8:85a3:0000:0000:8a2e:0370:7334:extra",
        "192.168.1.1",
        "invalid_ipv6"
    };
    
    for (const auto& ip6 : invalidIp6s) {
        uint8_t testIp6[IPV6_ADDR_SIZE] = {LOOP_START_INDEX};
        Ip6StrConToChar(ip6.c_str(), testIp6, sizeof(testIp6));
    }
}

void MacChConToMacStrTest(const uint8_t* data, size_t size)
{
    if (size < MAC_ADDR_SIZE) {
        return; // Need at least 6 bytes for MAC address
    }
    
    // Use first 6 bytes as MAC address
    unsigned char macBytes[MAC_ADDR_SIZE];
    int ret = memcpy_s(macBytes, sizeof(macBytes), data, MAC_ADDR_SIZE);
    if (ret != EOK) {
        return; // Memory copy failed, exit the test
    }
    
    // Test with different MAC buffer sizes
    char macStr[MAC_STRING_MAX_LEN] = {LOOP_START_INDEX}; // Standard MAC string format "xx:xx:xx:xx:xx:xx"
    
    // Normal case - 6 bytes MAC
    MacChConToMacStr(macBytes, MAC_ADDR_SIZE, macStr, sizeof(macStr));
    
    // Edge cases
    MacChConToMacStr(nullptr, MAC_ADDR_SIZE, macStr, sizeof(macStr)); // null MAC
    MacChConToMacStr(macBytes, LOOP_START_INDEX, macStr, sizeof(macStr)); // zero length
    MacChConToMacStr(macBytes, MAC_ADDR_SIZE, nullptr, LOOP_START_INDEX); // null output buffer
    
    // Test with different MAC lengths
    if (size > MAC_ADDR_SIZE) {
        size_t testLen = (data[MAC_ADDR_SIZE] % MAX_MAC_TEST_LENGTH) + 1; // 1-12 bytes
        char longMacStr[MAC_STRING_LONG_LEN] = {LOOP_START_INDEX};
        MacChConToMacStr(macBytes, testLen, longMacStr, sizeof(longMacStr));
    }
    
    // Test with small buffer
    char smallMacStr[MAC_STRING_SHORT_LEN] = {LOOP_START_INDEX};
    MacChConToMacStr(macBytes, MAC_ADDR_SIZE, smallMacStr, sizeof(smallMacStr));
    
    // Test with various MAC patterns
    unsigned char testMacs[][MAC_ADDR_SIZE] = {
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // all zeros
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, // all ones
        {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB}, // sequential
        {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}  // pattern
    };
    
    for (size_t i = LOOP_START_INDEX; i < sizeof(testMacs) / sizeof(testMacs[LOOP_START_INDEX]); i++) {
        char testMacStr[MAC_STRING_MAX_LEN] = {LOOP_START_INDEX};
        MacChConToMacStr(testMacs[i], MAC_ADDR_SIZE, testMacStr, sizeof(testMacStr));
    }
}

void GetLocalInterfaceTest(const uint8_t* data, size_t size)
{
    if (size < 1) {
        return;
    }
    
    // Create interface name from fuzz data
    std::string ifname = std::string(reinterpret_cast<const char*>(data),
        std::min(size, static_cast<size_t>(INTERFACE_NAME_MAX_LEN)));
    int ifindex = LOOP_START_INDEX;
    unsigned char hwaddr[MAC_ADDR_SIZE] = {LOOP_START_INDEX};
    uint32_t ifaddr4 = LOOP_START_INDEX;
    
    // Test normal case
    GetLocalInterface(ifname.c_str(), &ifindex, hwaddr, &ifaddr4);
    
    // Test with common interface names
    const std::vector<std::string> commonInterfaces = {"eth0", "wlan0", "lo", "enp0s3", "br0", "tun0"};
    size_t interfaceIndex = data[LOOP_START_INDEX] % commonInterfaces.size();
    GetLocalInterface(commonInterfaces[interfaceIndex].c_str(), &ifindex, hwaddr, &ifaddr4);
    
    // Test with null parameters
    GetLocalInterface(nullptr, &ifindex, hwaddr, &ifaddr4);
    GetLocalInterface(ifname.c_str(), nullptr, hwaddr, &ifaddr4);
    GetLocalInterface(ifname.c_str(), &ifindex, nullptr, &ifaddr4);
    GetLocalInterface(ifname.c_str(), &ifindex, hwaddr, nullptr); // ifaddr4 can be null
    
    // Test with empty string
    GetLocalInterface("", &ifindex, hwaddr, &ifaddr4);
    
    // Test with non-existent interface
    GetLocalInterface("nonexistent_12345", &ifindex, hwaddr, &ifaddr4);
    
    // Test with very long interface name
    std::string longInterface(LARGE_BUFFER_SIZE, 'X');
    GetLocalInterface(longInterface.c_str(), &ifindex, hwaddr, &ifaddr4);
    
    // Test with special characters
    GetLocalInterface("eth\x00test", &ifindex, hwaddr, &ifaddr4);
    GetLocalInterface("!@#$%^&*()", &ifindex, hwaddr, &ifaddr4);
}

void GetLocalIpTest(const uint8_t* data, size_t size)
{
    if (size < 1) {
        return;
    }
    
    // Create interface name from fuzz data
    std::string ifname = std::string(reinterpret_cast<const char*>(data),
        std::min(size, static_cast<size_t>(INTERFACE_NAME_MAX_LEN)));
    uint32_t ifaddr4 = LOOP_START_INDEX;
    
    // Test normal case
    GetLocalIp(ifname.c_str(), &ifaddr4);
    
    // Test with common interface names
    const std::vector<std::string> commonInterfaces = {"eth0", "wlan0", "lo", "enp0s3", "br0", "tun0"};
    size_t interfaceIndex = data[LOOP_START_INDEX] % commonInterfaces.size();
    GetLocalIp(commonInterfaces[interfaceIndex].c_str(), &ifaddr4);
    
    // Test with null parameters
    GetLocalIp(nullptr, &ifaddr4);
    GetLocalIp(ifname.c_str(), nullptr);
    
    // Test with empty string
    GetLocalIp("", &ifaddr4);
    
    // Test with non-existent interface
    GetLocalIp("nonexistent_interface_12345", &ifaddr4);
    
    // Test with very long interface name
    std::string longInterface(LARGE_BUFFER_SIZE, 'A');
    GetLocalIp(longInterface.c_str(), &ifaddr4);
    
    // Test with special characters
    GetLocalIp("!@#$%^&*()", &ifaddr4);
}

void SetLocalInterfaceTest(const uint8_t* data, size_t size)
{
    if (size < MIN_INTERFACE_TEST_SIZE) {
        return; // Need at least 9 bytes for interface name + 8 bytes for IPs
    }
    
    // Create interface name from first part of data
    std::string ifname = std::string(reinterpret_cast<const char*>(data),
        std::min(size / DATA_PARTITION_COUNT, static_cast<size_t>(INTERFACE_NAME_MAX_LEN)));
    
    // Extract IP address and netmask from remaining data
    uint32_t ipAddr;
    uint32_t netMask;
    int ret = memcpy_s(&ipAddr, sizeof(ipAddr), data + size / DATA_PARTITION_COUNT, sizeof(ipAddr));
    if (ret != EOK) {
        return; // Memory copy failed, exit the test
    }
    ret = memcpy_s(&netMask, sizeof(netMask), data + size / DATA_PARTITION_COUNT + IPV4_ADDR_SIZE, sizeof(netMask));
    if (ret != EOK) {
        return; // Memory copy failed, exit the test
    }

    // Test normal case (likely to fail due to permissions, but tests the logic)
    SetLocalInterface(ifname.c_str(), ipAddr, netMask);
    
    // Test with common interface names and IP ranges
    const std::vector<std::string> testInterfaces = {"eth0", "lo", "wlan0", "test123"};
    const std::vector<std::pair<uint32_t, uint32_t>> testIpPairs = {
        {htonl(0xC0A80101), htonl(0xFFFFFF00)}, // 192.168.1.1/24
        {htonl(0x0A000001), htonl(0xFF000000)}, // 10.0.0.1/8
        {htonl(0x7F000001), htonl(0xFF000000)}, // 127.0.0.1/8
        {0, 0}, // All zeros
        {0xFFFFFFFF, 0xFFFFFFFF} // All ones
    };
    
    for (const auto& interface : testInterfaces) {
        for (const auto& ipPair : testIpPairs) {
            SetLocalInterface(interface.c_str(), ipPair.first, ipPair.second);
        }
    }
    
    // Test with null interface name
    SetLocalInterface(nullptr, ipAddr, netMask);
    
    // Test with empty interface name
    SetLocalInterface("", ipAddr, netMask);
    
    // Test with very long interface name
    std::string longInterface(LARGE_BUFFER_SIZE, 'Y');
    SetLocalInterface(longInterface.c_str(), ipAddr, netMask);
    
    // Test with non-existent interface
    SetLocalInterface("nonexistent_interface_xyz", ipAddr, netMask);
}

void CreateDirsTest(const uint8_t* data, size_t size)
{
    if (size == LOOP_START_INDEX) {
        return;
    }
    
    int mode = DIR_DEFAULT_MODE;
    
    // Extract mode from data if available
    if (size >= IPV4_ADDR_SIZE) {
        int ret = memcpy_s(&mode, sizeof(mode), data, sizeof(mode));
        if (ret != EOK) {
            return; // Memory copy failed, exit the test
        }
        mode = mode % DIR_PERMISSION_MASK; // Keep it within valid mode range
        if (mode == LOOP_START_INDEX) mode = DIR_DEFAULT_MODE;
    }
    
    // Create directory path from remaining data
    size_t pathStart = std::min(size, static_cast<size_t>(PATH_COMPONENT_SIZE));
    std::string dirs = std::string(reinterpret_cast<const char*>(data + pathStart), size - pathStart);
    
    // Test normal case
    CreateDirs(dirs.c_str(), mode);
    
    // Test with null pointer
    CreateDirs(nullptr, mode);
    
    // Test with empty string
    CreateDirs("", mode);
    
    // Test with common directory patterns
    const std::vector<std::string> commonDirs = {
        "/tmp/test",
        "/tmp/test/nested/deep",
        "relative/path",
        "./current/dir",
        "../parent/dir",
        "/tmp/single",
        "/tmp/with spaces/dir",
        "/tmp/with-dashes/dir",
        "/tmp/with_underscores/dir"
    };
    
    for (const auto& dir : commonDirs) {
        CreateDirs(dir.c_str(), mode);
    }
    
    // Test with different modes
    const std::vector<int> testModes = {DIR_MODE_755, DIR_MODE_777, DIR_MODE_644,
        DIR_MODE_600, DIR_MODE_700, DIR_MODE_444};
    for (int testMode : testModes) {
        CreateDirs("/tmp/mode_test", testMode);
    }
    
    // Test with very long path
    std::string longPath(VERY_LARGE_BUFFER_SIZE, 'L');
    CreateDirs(longPath.c_str(), mode);
    
    // Test with special characters
    CreateDirs("/tmp/special!@#$%^&*()", mode);
    CreateDirs("/tmp/with\x00null", mode);
    CreateDirs("/tmp/with\ttab", mode);
    CreateDirs("/tmp/with\nnewline", mode);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return FUNCTION_SUCCESS;
    }
    sleep(DHCP_SLEEP_1);
    OHOS::DHCP::Ip4StrConToIntTest(data, size);
    OHOS::DHCP::Ip6StrConToCharTest(data, size);
    OHOS::DHCP::MacChConToMacStrTest(data, size);
    OHOS::DHCP::GetLocalInterfaceTest(data, size);
    OHOS::DHCP::GetLocalIpTest(data, size);
    OHOS::DHCP::SetLocalInterfaceTest(data, size);
    OHOS::DHCP::CreateDirsTest(data, size);
    return FUNCTION_SUCCESS;
}
}  // namespace DHCP
}  // namespace OHOS
