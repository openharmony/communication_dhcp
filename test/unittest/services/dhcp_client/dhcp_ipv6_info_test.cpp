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
#include <gtest/gtest.h>

#include "dhcp_logger.h"
#include "dhcp_ipv6_info.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpIpv6InfoTest");

using namespace testing::ext;
using namespace OHOS::DHCP;

namespace OHOS {
class DhcpIpv6InfoTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {}
    virtual void TearDown()
    {}
};

HWTEST_F(DhcpIpv6InfoTest, AddRoute_SUCCESS, TestSize.Level1)
{
    DhcpIpv6Info dhcpIpv6Info;
    std::string route = "2001:db8::1";
    EXPECT_TRUE(DhcpIpv6InfoManager::AddRoute(dhcpIpv6Info, route));
    EXPECT_EQ(dhcpIpv6Info.defaultRouteAddr.size(), 1);
    EXPECT_STREQ(dhcpIpv6Info.defaultRouteAddr[0].c_str(), route.c_str());
}

HWTEST_F(DhcpIpv6InfoTest, AddRoute_DUPLICATE, TestSize.Level1)
{
    DhcpIpv6Info dhcpIpv6Info;
    std::string route = "2001:db8::1";
    EXPECT_TRUE(DhcpIpv6InfoManager::AddRoute(dhcpIpv6Info, route));
    EXPECT_FALSE(DhcpIpv6InfoManager::AddRoute(dhcpIpv6Info, route)); // Duplicate
    EXPECT_EQ(dhcpIpv6Info.defaultRouteAddr.size(), 1);
}

HWTEST_F(DhcpIpv6InfoTest, RemoveRoute_SUCCESS, TestSize.Level1)
{
    DhcpIpv6Info dhcpIpv6Info;
    std::string route = "2001:db8::1";
    DhcpIpv6InfoManager::AddRoute(dhcpIpv6Info, route);
    EXPECT_TRUE(DhcpIpv6InfoManager::RemoveRoute(dhcpIpv6Info, route));
    EXPECT_EQ(dhcpIpv6Info.defaultRouteAddr.size(), 0);
}

HWTEST_F(DhcpIpv6InfoTest, RemoveRoute_NOT_FOUND, TestSize.Level1)
{
    DhcpIpv6Info dhcpIpv6Info;
    std::string route = "2001:db8::1";
    EXPECT_FALSE(DhcpIpv6InfoManager::RemoveRoute(dhcpIpv6Info, route)); // Not found
}

HWTEST_F(DhcpIpv6InfoTest, UpdateAddr_SUCCESS, TestSize.Level1)
{
    DhcpIpv6Info dhcpIpv6Info;
    std::string addr = "2001:db8::1";
    AddrType type = AddrType::GLOBAL;
    EXPECT_TRUE(DhcpIpv6InfoManager::UpdateAddr(dhcpIpv6Info, addr, type));
    EXPECT_EQ(dhcpIpv6Info.IpAddrMap.size(), 1);
    EXPECT_EQ(dhcpIpv6Info.IpAddrMap[addr], static_cast<int>(type));
    EXPECT_STREQ(dhcpIpv6Info.globalIpv6Addr, addr.c_str());
}

HWTEST_F(DhcpIpv6InfoTest, UpdateAddr_SAME_ADDR_DIFFERENT_TYPE, TestSize.Level1)
{
    DhcpIpv6Info dhcpIpv6Info;
    std::string addr = "2001:db8::1";
    AddrType type1 = AddrType::GLOBAL;
    AddrType type2 = AddrType::RAND;
    EXPECT_TRUE(DhcpIpv6InfoManager::UpdateAddr(dhcpIpv6Info, addr, type1));
    EXPECT_TRUE(DhcpIpv6InfoManager::UpdateAddr(dhcpIpv6Info, addr, type2)); // Change type
    EXPECT_EQ(dhcpIpv6Info.IpAddrMap.size(), 1);
    EXPECT_EQ(dhcpIpv6Info.IpAddrMap[addr], static_cast<int>(type2));
    EXPECT_STREQ(dhcpIpv6Info.randIpv6Addr, addr.c_str());
}

HWTEST_F(DhcpIpv6InfoTest, UpdateAddr_INVALID_ADDR, TestSize.Level1)
{
    DhcpIpv6Info dhcpIpv6Info;
    std::string addr = "";
    AddrType type = AddrType::GLOBAL;
    EXPECT_FALSE(DhcpIpv6InfoManager::UpdateAddr(dhcpIpv6Info, addr, type));
}

HWTEST_F(DhcpIpv6InfoTest, RemoveAddr_SUCCESS, TestSize.Level1)
{
    DhcpIpv6Info dhcpIpv6Info;
    std::string addr = "2001:db8::1";
    AddrType type = AddrType::GLOBAL;
    DhcpIpv6InfoManager::UpdateAddr(dhcpIpv6Info, addr, type);
    EXPECT_TRUE(DhcpIpv6InfoManager::RemoveAddr(dhcpIpv6Info, addr));
    EXPECT_EQ(dhcpIpv6Info.IpAddrMap.size(), 0);
    EXPECT_STREQ(dhcpIpv6Info.globalIpv6Addr, ""); // Cleared
}

HWTEST_F(DhcpIpv6InfoTest, RemoveAddr_NOT_FOUND, TestSize.Level1)
{
    DhcpIpv6Info dhcpIpv6Info;
    std::string addr = "2001:db8::1";
    EXPECT_FALSE(DhcpIpv6InfoManager::RemoveAddr(dhcpIpv6Info, addr));
}

HWTEST_F(DhcpIpv6InfoTest, RemoveAddr_FALLBACK, TestSize.Level1)
{
    DhcpIpv6Info dhcpIpv6Info;
    std::string addr1 = "2001:db8::1";
    std::string addr2 = "2001:db8::2";
    AddrType type = AddrType::GLOBAL;
    DhcpIpv6InfoManager::UpdateAddr(dhcpIpv6Info, addr1, type);
    DhcpIpv6InfoManager::UpdateAddr(dhcpIpv6Info, addr2, type); // addr2 becomes latest
    EXPECT_TRUE(DhcpIpv6InfoManager::RemoveAddr(dhcpIpv6Info, addr2)); // Remove latest
    EXPECT_EQ(dhcpIpv6Info.IpAddrMap.size(), 1);
    EXPECT_EQ(dhcpIpv6Info.IpAddrMap.begin()->first, addr1);
    EXPECT_STREQ(dhcpIpv6Info.globalIpv6Addr, addr1.c_str()); // Fallback to addr1
}
}  // namespace OHOS