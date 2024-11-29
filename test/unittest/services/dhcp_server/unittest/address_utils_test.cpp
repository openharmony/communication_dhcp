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

#include <gtest/gtest.h>
#include <cstdint>
#include "dhcp_s_define.h"
#include "address_utils.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("AddressUtilsTest");

using namespace testing::ext;
namespace OHOS {
namespace DHCP {
const uint8_t netmask24[] =  {255, 255, 255, 0};
const uint8_t netmask25[] =  {255, 255, 255, 128};
const uint8_t netmask26[] =  {255, 255, 255, 192};

/**
* @tc.name: ParseIpAddrTest
* @tc.desc: test address translation.
* @tc.type: FUNC
* @tc.require: AR00000000 SR00000000
*/
HWTEST(AddressUtilsTest, ParseIpAddrTest, TestSize.Level1)
{
    DHCP_LOGE("enter ParseIpAddrTest");
    uint8_t ipData[] = {192, 168, 100, 1};
    uint32_t testIp = ParseIp(ipData);
    ASSERT_TRUE(testIp != 0);
    EXPECT_EQ(testIp, ParseIpAddr("192.168.100.1"));
}

HWTEST(AddressUtilsTest, ParseIpAddrFailedTest, TestSize.Level1)
{
    uint32_t expectVal = 0;
    EXPECT_EQ(expectVal, ParseIpAddr("192.168.100."));
    EXPECT_EQ(expectVal, ParseIpAddr("0"));
    EXPECT_EQ(expectVal, ParseIpAddr("abc.abc.abc.abc"));
}

HWTEST(AddressUtilsTest, ParseStrIpAddrTest, TestSize.Level1)
{
    uint8_t ipData[] = {192, 168, 100, 1};
    uint32_t testIp = ParseIp(ipData);
    EXPECT_TRUE(testIp != 0);
    EXPECT_STREQ("192.168.100.1", ParseStrIp(testIp));
}

/**
* @tc.name: NetworkAddressTest
* @tc.desc: test network address calculation.
* @tc.type: FUNC
* @tc.require: AR00000000 SR00000000
*/
HWTEST(AddressUtilsTest, NetworkAddressTest, TestSize.Level1)
{
    uint8_t srcNetData[] = {192, 168, 100, 0};
    uint32_t srcNet = ParseIp(srcNetData);
    ASSERT_TRUE(srcNet != 0);
    uint32_t testIp = ParseIpAddr("192.168.100.100");
    ASSERT_TRUE(testIp != 0);
    uint32_t testNetmask = ParseIp(netmask24);
    EXPECT_TRUE(testNetmask != 0);
    EXPECT_EQ(srcNet, NetworkAddress(testIp, testNetmask));
}

HWTEST(AddressUtilsTest, FirstIpAddressTest, TestSize.Level1)
{
    uint8_t srcData[] = {192, 168, 100, 1};
    uint32_t srcAddr = ParseIp(srcData);
    ASSERT_TRUE(srcAddr != 0);
    uint32_t testIp = ParseIpAddr("192.168.100.100");
    ASSERT_TRUE(testIp != 0);
    uint32_t testNetmask = ParseIp(netmask24);
    EXPECT_TRUE(testNetmask != 0);
    EXPECT_EQ(srcAddr, FirstIpAddress(testIp, testNetmask));
}

HWTEST(AddressUtilsTest, LastIpAddressTest, TestSize.Level1)
{
    uint8_t srcData[] = {192, 168, 100, 254};
    uint32_t srcAddr = ParseIp(srcData);
    ASSERT_TRUE(srcAddr != 0);
    uint32_t testIp = ParseIpAddr("192.168.100.100");
    ASSERT_TRUE(testIp != 0);
    uint32_t testNetmask = ParseIp(netmask24);
    EXPECT_TRUE(testNetmask != 0);
    EXPECT_EQ(srcAddr, LastIpAddress(testIp, testNetmask));
}

HWTEST(AddressUtilsTest, FirstNetIpAddressTest, TestSize.Level1)
{
    uint8_t srcData[] = {192, 168, 100, 1};
    uint32_t srcAddr = ParseIp(srcData);
    ASSERT_TRUE(srcAddr != 0);
    uint32_t testIp = ParseIpAddr("192.168.100.100");
    ASSERT_TRUE(testIp != 0);
    uint32_t testNetmask = ParseIp(netmask24);
    EXPECT_TRUE(testNetmask != 0);
    uint32_t network = NetworkAddress(testIp, testNetmask);
    ASSERT_TRUE(network != 0);
    EXPECT_EQ(srcAddr, FirstNetIpAddress(network));
}

HWTEST(AddressUtilsTest, NextIpAddressTest, TestSize.Level1)
{
    uint8_t srcData[] = {192, 168, 100, 100};
    uint32_t srcAddr = ParseIp(srcData);
    EXPECT_TRUE(srcAddr != 0);
    uint32_t testIp1 = ParseIpAddr("192.168.100.101");
    EXPECT_TRUE(testIp1 != 0);
    uint32_t testIp2 = ParseIpAddr("192.168.100.102");
    EXPECT_TRUE(testIp2 != 0);
    uint32_t testNetmask = ParseIp(netmask24);
    EXPECT_TRUE(testNetmask != 0);
    EXPECT_EQ(testIp1, NextIpAddress(srcAddr, testNetmask, 0));
    EXPECT_EQ(testIp2, NextIpAddress(srcAddr, testNetmask, 1));
}

HWTEST(AddressUtilsTest, IpInNetworkTest, TestSize.Level1)
{
    uint8_t srcData[] = {192, 168, 100, 0};
    uint32_t srcAddr = ParseIp(srcData);
    EXPECT_TRUE(srcAddr != 0);
    uint32_t testNetmask = ParseIp(netmask25);
    EXPECT_TRUE(testNetmask != 0);
    uint32_t testIp1 = ParseIpAddr("192.168.100.120");
    EXPECT_TRUE(testIp1 != 0);
    uint32_t testIp2= ParseIpAddr("192.168.100.150");
    EXPECT_TRUE(testIp2 != 0);
    EXPECT_TRUE(IpInNetwork(testIp1, srcAddr, testNetmask));
    EXPECT_FALSE(IpInNetwork(testIp2, srcAddr, testNetmask));
}

HWTEST(AddressUtilsTest, IpInRangeTest, TestSize.Level1)
{
    uint32_t testNetmask = ParseIp(netmask26);
    ASSERT_TRUE(testNetmask != 0);
    uint32_t beginIp = ParseIpAddr("192.168.100.100");
    ASSERT_TRUE(beginIp != 0);
    uint32_t endIp = LastIpAddress(beginIp, testNetmask);
    ASSERT_TRUE(endIp != 0);

    uint32_t testIp1 = ParseIpAddr("192.168.100.90");
    EXPECT_TRUE(testIp1 != 0);
    uint32_t testIp2= ParseIpAddr("192.168.100.130");
    EXPECT_TRUE(testIp2 != 0);
    uint32_t testIp3= ParseIpAddr("192.168.100.120");
    EXPECT_TRUE(testIp3 != 0);

    EXPECT_FALSE(IpInRange(testIp1, beginIp, endIp, testNetmask));
    EXPECT_FALSE(IpInRange(testIp2, beginIp, endIp, testNetmask));
    EXPECT_TRUE(IpInRange(testIp3, beginIp, endIp, testNetmask));
}

HWTEST(AddressUtilsTest, BroadCastAddressTest, TestSize.Level1)
{
    uint8_t srcData[] = {192, 168, 100, 255};
    uint32_t srcAddr = ParseIp(srcData);
    ASSERT_TRUE(srcAddr != 0);
    uint32_t testNetmask = ParseIp(netmask24);
    ASSERT_TRUE(testNetmask != 0);
    uint32_t testIp1 = ParseIpAddr("192.168.100.120");
    EXPECT_TRUE(testIp1 != 0);
    EXPECT_EQ(srcAddr, BroadCastAddress(testIp1, testNetmask));
}

HWTEST(AddressUtilsTest, IsEmptyHWAddrTest, TestSize.Level1)
{
    uint8_t testMac1[DHCP_HWADDR_LENGTH] = {0};
    uint8_t testMac2[DHCP_HWADDR_LENGTH] = {0, 0, 0, 0, 0, 0, 0, 0x01};
    uint8_t testMac3[DHCP_HWADDR_LENGTH] = {0, 0xae, 0xdc, 0xcc, 0x9f, 0x43, 0};

    EXPECT_TRUE(IsEmptyHWAddr(testMac1));
    EXPECT_TRUE(IsEmptyHWAddr(testMac2));
    EXPECT_FALSE(IsEmptyHWAddr(testMac3));
}

HWTEST(AddressUtilsTest, ParseStrMacTest, TestSize.Level1)
{
    uint8_t testMac[DHCP_HWADDR_LENGTH] = {0, 0xae, 0xdc, 0xcc, 0x9f, 0x43, 0};
    EXPECT_STREQ("00:ae:dc:cc:9f:43", ParseStrMac(testMac, MAC_ADDR_LENGTH));
    uint8_t* testMac1 = nullptr;
    char* result = ParseStrMac(testMac1, MAC_ADDR_LENGTH);
    ASSERT_TRUE(result == 0);
}

HWTEST(AddressUtilsTest, HostToNetworkTest, TestSize.Level1)
{
    uint8_t srcData[] = {150, 100, 168, 192};
    uint32_t srcAddr = ParseIp(srcData);
    ASSERT_TRUE(srcAddr != 0);
    uint32_t testIp = ParseIpAddr("192.168.100.150");
    ASSERT_TRUE(testIp != 0);
    EXPECT_EQ(srcAddr, HostToNetwork(testIp));
}

HWTEST(AddressUtilsTest, NetworkToHostTest, TestSize.Level1)
{
    uint8_t srcData[] = {192, 168, 100, 150};
    uint32_t srcAddr = ParseIp(srcData);
    ASSERT_TRUE(srcAddr != 0);
    uint8_t testData[] = {150, 100, 168, 192};
    uint32_t testAddr = ParseIp(testData);
    ASSERT_TRUE(testAddr != 0);
    EXPECT_EQ(srcAddr, NetworkToHost(testAddr));
}

HWTEST(AddressUtilsTest, ParseLogMacTest, TestSize.Level1)
{
    uint8_t testMac[DHCP_HWADDR_LENGTH] = {0, 0xae, 0xdc, 0xcc, 0x9f, 0x43, 0};
    EXPECT_STREQ("??:ae:??:??:9f:43", ParseLogMac(testMac));
    uint8_t* testMac1 = nullptr;
    char* result = ParseLogMac(testMac1);
    ASSERT_TRUE(result == 0);
}

HWTEST(AddressUtilsTest, AddrEquelsTest, TestSize.Level1)
{
    uint8_t testMac1[DHCP_HWADDR_LENGTH] = {0, 0xae, 0xdc, 0xcc, 0x9f, 0x43, 0};
    uint8_t testMac2[DHCP_HWADDR_LENGTH] = {0, 0xae, 0xdc, 0xcc, 0x9f, 0x43, 0};
    uint8_t testMac3[DHCP_HWADDR_LENGTH] = {0, 0xae, 0xdc, 0xcc, 0x9f, 0x45, 0};

    EXPECT_EQ(1, AddrEquels(testMac1, testMac2, MAC_ADDR_LENGTH));
    EXPECT_EQ(0, AddrEquels(testMac1, testMac3, MAC_ADDR_LENGTH));
    EXPECT_EQ(0, AddrEquels(testMac2, testMac3, MAC_ADDR_LENGTH));
}

HWTEST(AddressUtilsTest, ParseMacAddressTest, TestSize.Level1)
{
    uint8_t macAddr[DHCP_HWADDR_LENGTH] = {0};
    const char *strMac = "12:34:56:78:90:ab:cd";
    int result = ParseMacAddress(strMac, macAddr);
    EXPECT_EQ(result, DHCP_FALSE);
    result = ParseMacAddress(nullptr, macAddr);
    EXPECT_EQ(result, DHCP_FALSE);

    strMac = "12:34:56:78:90:ab";
    result = ParseMacAddress(strMac, macAddr);
    EXPECT_EQ(result, DHCP_TRUE);
}

HWTEST(AddressUtilsTest, ParseHostNameTest, TestSize.Level1)
{
    char hostName[DHCP_BOOT_FILE_LENGTH];
    const char *strHostName = "test.com";
    int result = ParseHostName(nullptr, nullptr);
    EXPECT_EQ(result, DHCP_FALSE);

    result = ParseHostName(strHostName, nullptr);
    EXPECT_EQ(result, DHCP_FALSE);

    result = ParseHostName(nullptr, hostName);
    EXPECT_EQ(result, DHCP_FALSE);

    result = ParseHostName(strHostName, hostName);
    EXPECT_EQ(result, DHCP_TRUE);
}
}
}