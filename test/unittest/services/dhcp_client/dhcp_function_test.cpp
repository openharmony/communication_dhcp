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

#include "dhcp_logger.h"
#include "dhcp_function.h"
#include "dhcp_client_def.h"
#include "mock_system_func.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpFunctionTest");

using namespace testing::ext;
using namespace OHOS::DHCP;

namespace OHOS {
class DhcpFunctionTest : public testing::Test {
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

HWTEST_F(DhcpFunctionTest, Ip4StrConToInt_SUCCESS, TestSize.Level1)
{
    DHCP_LOGE("enter Ip4StrConToInt_SUCCESS");
    char serIp[INET_ADDRSTRLEN] = "192.77.1.231";
    uint32_t uSerIp = 0;
    EXPECT_EQ(true, Ip4StrConToInt(serIp, &uSerIp, true));
}

HWTEST_F(DhcpFunctionTest, Ip4StrConToInt_FAILED, TestSize.Level1)
{
    char serIp[INET_ADDRSTRLEN] = {0};
    uint32_t uSerIp = 0;
    EXPECT_EQ(false, Ip4StrConToInt(serIp, &uSerIp, true));

    char serIp1[INET_ADDRSTRLEN] = "192.77.231";
    uint32_t uSerIp1 = 0;
    EXPECT_EQ(false, Ip4StrConToInt(serIp1, &uSerIp1, true));
}

HWTEST_F(DhcpFunctionTest, Ip6StrConToChar_SUCCESS, TestSize.Level1)
{
    char serIp[INET6_ADDRSTRLEN] = "2001:db8:0:1::231";
    uint8_t	addr6[sizeof(struct in6_addr)] = {0};
    EXPECT_EQ(true, Ip6StrConToChar(serIp, addr6, sizeof(addr6)));
}

HWTEST_F(DhcpFunctionTest, Ip6StrConToChar_FAILED, TestSize.Level1)
{
    char serIp[INET6_ADDRSTRLEN] = {0};
    uint8_t	addr6[sizeof(struct in6_addr)] = {0};
    EXPECT_EQ(false, Ip6StrConToChar(serIp, addr6, sizeof(addr6)));

    char serIp1[INET6_ADDRSTRLEN] = "231";
    uint8_t	addr61[sizeof(struct in6_addr)] = {0};
    EXPECT_EQ(false, Ip6StrConToChar(serIp1, addr61, sizeof(addr61)));
}

HWTEST_F(DhcpFunctionTest, MacChConToMacStr_SUCCESS, TestSize.Level1)
{
    EXPECT_EQ(false, MacChConToMacStr(NULL, 0, NULL, 0));

    char interface[INFNAME_SIZE] = "wlan0";
    int  ifindex;
    unsigned char hwaddr[MAC_ADDR_LEN];
    ASSERT_EQ(GetLocalInterface(interface, &ifindex, hwaddr, NULL), DHCP_OPT_SUCCESS);
    EXPECT_EQ(false, MacChConToMacStr(hwaddr, MAC_ADDR_LEN, NULL, 0));

    char buf[MAC_ADDR_LEN * MAC_ADDR_CHAR_NUM] = {0};
    EXPECT_NE(false, MacChConToMacStr(hwaddr, MAC_ADDR_LEN, buf, sizeof(buf)));
}

HWTEST_F(DhcpFunctionTest, GetLocalInterface_SUCCESS, TestSize.Level1)
{
    EXPECT_EQ(GetLocalInterface(NULL, NULL, NULL, NULL), DHCP_OPT_FAILED);

    MockSystemFunc::SetMockFlag(true);

    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _)).WillOnce(Return(-1)).WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), ioctl(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_)).WillRepeatedly(Return(0));

    char interface[INFNAME_SIZE] = "wlan0";
    EXPECT_EQ(GetLocalInterface(interface, NULL, NULL, NULL), DHCP_OPT_FAILED);
    int ifindex = 0;
    EXPECT_EQ(GetLocalInterface(interface, &ifindex, NULL, NULL), DHCP_OPT_FAILED);
    unsigned char hwaddr[MAC_ADDR_LEN];
    EXPECT_EQ(GetLocalInterface(interface, &ifindex, hwaddr, NULL), DHCP_OPT_FAILED);
    uint32_t ifaddr4;
    EXPECT_EQ(GetLocalInterface(interface, &ifindex, hwaddr, &ifaddr4), DHCP_OPT_SUCCESS);
    EXPECT_EQ(GetLocalInterface(interface, &ifindex, hwaddr, &ifaddr4), DHCP_OPT_SUCCESS);

    MockSystemFunc::SetMockFlag(false);
}

HWTEST_F(DhcpFunctionTest, GetLocalIp_SUCCESS, TestSize.Level1)
{
    char interface[INFNAME_SIZE] = "wlan0";
    uint32_t ipaddr4;
    EXPECT_EQ(DHCP_OPT_SUCCESS, GetLocalIp(interface, &ipaddr4));
}

HWTEST_F(DhcpFunctionTest, GetLocalIp_FAILED, TestSize.Level1)
{
    char interface[INFNAME_SIZE] = {0};
    uint32_t ipaddr4;
    EXPECT_EQ(DHCP_OPT_FAILED, GetLocalIp(interface, &ipaddr4));
}

HWTEST_F(DhcpFunctionTest, SetLocalInterface_SUCCESS, TestSize.Level1)
{
    char interface[INFNAME_SIZE] = "wlan0";
    uint32_t ipaddr4 = 2981805322;
    uint32_t netMask = 16318463;
    EXPECT_EQ(DHCP_OPT_SUCCESS, SetLocalInterface(interface, ipaddr4, netMask));
}

HWTEST_F(DhcpFunctionTest, SetLocalInterface_FAILED, TestSize.Level1)
{
    char interface[INFNAME_SIZE] = {0};
    uint32_t ipaddr4 = 0;
    uint32_t netMask = 0;
    EXPECT_EQ(DHCP_OPT_FAILED, SetLocalInterface(interface, ipaddr4, netMask));
    EXPECT_EQ(DHCP_OPT_FAILED, SetLocalInterface("wlan", ipaddr4, netMask));
}

HWTEST_F(DhcpFunctionTest, CreateDirs_SUCCESS, TestSize.Level1)
{
    EXPECT_EQ(DHCP_OPT_FAILED, CreateDirs(NULL, 0));

    const char *path = "test";
    EXPECT_EQ(DHCP_OPT_SUCCESS, CreateDirs(path, S_IRWXU));
    rmdir(path);
}
}  // namespace OHOS