/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstddef>
#include <cstdint>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "securec.h"
#include "dhcp_logger.h"
#include "dhcp_function.h"
#include "dhcp_ipv6_client.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpIpv6ClientTest");

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Ref;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace DHCP {
const int KERNEL_SOCKET_IFA_FAMILY = 10;
constexpr unsigned int IPV6_SCOPE_NODELOCAL = 0x01;
constexpr unsigned int IPV6_SCOPE_LINKLOCAL = 0x02;
constexpr unsigned int IPV6_SCOPE_SITELOCAL = 0x05;
constexpr unsigned int IPV6_SCOPE_OTHER = 0x08;
constexpr unsigned int PRE_FIX_LEN = 12;
constexpr unsigned int PRE_FIX_ADDRSTRLEN = 128;
constexpr int IPV6_RETURN_ZERO = 0x00000;
constexpr int IPV6_RETURN_65552 = 0x10010;
constexpr int IPV6_RETURN_131101 = 0x20020;
constexpr int IPV6_RETURN_1327744 = 0x50040;
constexpr int IPV6_RETURN_524288 = 0x80000;
constexpr int IPV6_RETURN_32 = 0x0020U;
constexpr int IPV6_OPT_FAILED = -1;
constexpr int IPV6_LEN_134 = 134;
constexpr int IPV6_LEN_24 = 24;
constexpr int IPV6_LEN_16 = 16;
constexpr int IPV6_LEN_10 = 10;
constexpr int BUF_LEN = 1024;
constexpr int BUF_LEN_2 = 2;
constexpr int DATA_SIZE = 8;
class DhcpIpv6ClientTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
    }
    static void TearDownTestCase()
    {
    }
    virtual void SetUp()
    {
        std::string ifname = "wlan0";
        ipv6Client = std::make_unique<OHOS::DHCP::DhcpIpv6Client>(ifname);
    }
    virtual void TearDown()
    {
        if (ipv6Client != nullptr) {
            ipv6Client.reset(nullptr);
        }
    }
public:
    std::unique_ptr<OHOS::DHCP::DhcpIpv6Client> ipv6Client;
};

HWTEST_F(DhcpIpv6ClientTest, IsRunningTest, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("IsRunningTest enter!");
    ipv6Client->IsRunning();
}

HWTEST_F(DhcpIpv6ClientTest, DhcpIPV6StopTest, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("DhcpIPV6StopTest enter!");
    ipv6Client->DhcpIPV6Stop();
}

HWTEST_F(DhcpIpv6ClientTest, ResetTest, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("ResetTest enter!");
    ipv6Client->Reset();
}

HWTEST_F(DhcpIpv6ClientTest, ipv6AddrScope2TypeTest, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("ipv6AddrScope2TypeTest enter!");
    EXPECT_EQ(IPV6_RETURN_65552, ipv6Client->ipv6AddrScope2Type(IPV6_SCOPE_NODELOCAL));
    EXPECT_EQ(IPV6_RETURN_131101, ipv6Client->ipv6AddrScope2Type(IPV6_SCOPE_LINKLOCAL));
    EXPECT_EQ(IPV6_RETURN_1327744, ipv6Client->ipv6AddrScope2Type(IPV6_SCOPE_SITELOCAL));
    EXPECT_EQ(IPV6_RETURN_524288, ipv6Client->ipv6AddrScope2Type(IPV6_SCOPE_OTHER));
}

HWTEST_F(DhcpIpv6ClientTest, getAddrTypeTest, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("getAddrTypeTest enter!");
    struct in6_addr addr;
    EXPECT_EQ(IPV6_RETURN_32, ipv6Client->getAddrType(nullptr));
    EXPECT_EQ(IPV6_RETURN_ZERO, ipv6Client->getAddrType(&addr));
}

HWTEST_F(DhcpIpv6ClientTest, getAddrTypeTest1, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("getAddrTypeTest1 enter!");
    struct in6_addr addr;
    ipv6Client->getAddrType(&addr);

    inet_pton(AF_INET6, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", &addr);
    ipv6Client->getAddrType(&addr);

    inet_pton(AF_INET6, "ff02:0000:0000:0000:0000:0000:0000:0001", &addr);
    ipv6Client->getAddrType(&addr);

    inet_pton(AF_INET6, "fe80::", &addr);
    ipv6Client->getAddrType(&addr);

    inet_pton(AF_INET6, "fec0::", &addr);
    ipv6Client->getAddrType(&addr);

    inet_pton(AF_INET6, "::", &addr);
    ipv6Client->getAddrType(&addr);

    inet_pton(AF_INET6, "::1", &addr);
    ipv6Client->getAddrType(&addr);

    inet_pton(AF_INET6, "::ffff:192.0.2.128", &addr);
    ipv6Client->getAddrType(&addr);

    inet_pton(AF_INET6, "::ffff:192.0.2.128", &addr);
    ipv6Client->getAddrType(&addr);
}

HWTEST_F(DhcpIpv6ClientTest, getAddrScopeTest, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("getAddrScopeTest enter!");
    struct in6_addr addr;
    EXPECT_EQ(IPV6_RETURN_32, ipv6Client->getAddrScope(nullptr));
    EXPECT_EQ(IPV6_RETURN_ZERO, ipv6Client->getAddrScope(&addr));
}

HWTEST_F(DhcpIpv6ClientTest, createKernelSocketTest, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("createKernelSocketTest enter!");
    ipv6Client->createKernelSocket();
}

HWTEST_F(DhcpIpv6ClientTest, GetIpv6PrefixTest, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("GetIpv6PrefixTest enter!");
    char ipv6Addr[] = "192.168.1.10";
    char ipv6PrefixBuf[] = "192.168.1.12";
    ipv6Client->GetIpv6Prefix(nullptr, ipv6PrefixBuf, PRE_FIX_LEN);
    ipv6Client->GetIpv6Prefix(ipv6Addr, nullptr, PRE_FIX_LEN);
    ipv6Client->GetIpv6Prefix(ipv6Addr, ipv6PrefixBuf, PRE_FIX_ADDRSTRLEN);
    ipv6Client->GetIpv6Prefix(ipv6Addr, ipv6PrefixBuf, PRE_FIX_LEN);
}

HWTEST_F(DhcpIpv6ClientTest, GetIpFromS6AddressTest, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("GetIpFromS6AddressTest enter!");
    char addr[] = "192.168.1.12";
    char buf[BUF_LEN] = {0};
    EXPECT_EQ(ipv6Client->GetIpFromS6Address(addr, 1, buf, BUF_LEN), IPV6_OPT_FAILED);
    EXPECT_EQ(ipv6Client->GetIpFromS6Address(addr, 1, buf, BUF_LEN_2), IPV6_OPT_FAILED);
}

HWTEST_F(DhcpIpv6ClientTest, onIpv6AddressAddEventTest, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("onIpv6AddressAddEventTest enter!");
    char data[] = "192.168.1.12";
    ipv6Client->onIpv6AddressAddEvent(static_cast<void *>(data), PRE_FIX_LEN, 1);
    ipv6Client->onIpv6AddressAddEvent(nullptr, PRE_FIX_LEN, 0);
    ipv6Client->onIpv6AddressAddEvent(nullptr, PRE_FIX_LEN, 41);
}

HWTEST_F(DhcpIpv6ClientTest, onIpv6DnsAddEventTest, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("onIpv6DnsAddEventTest enter!");
    char data[] = "192.168.1.12";
    ipv6Client->onIpv6DnsAddEvent(static_cast<void *>(data), PRE_FIX_LEN, 1);
    ipv6Client->onIpv6DnsAddEvent(nullptr, PRE_FIX_LEN, 0);
    ipv6Client->onIpv6DnsAddEvent(nullptr, PRE_FIX_LEN, 41);
    ipv6Client->onIpv6DnsAddEvent(static_cast<void *>(data), PRE_FIX_LEN, 41);
}

HWTEST_F(DhcpIpv6ClientTest, onIpv6RouteAddEventTest, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("onIpv6RouteAddEventTest enter!");
    char gateway[] = "192.168.1.1";
    char dst[] = "192.168.1.2";
    ipv6Client->onIpv6RouteAddEvent(gateway, dst, 1);
    ipv6Client->onIpv6RouteAddEvent(nullptr, dst, 41);
    ipv6Client->onIpv6RouteAddEvent(gateway, nullptr, 41);
    ipv6Client->onIpv6RouteAddEvent(gateway, dst, 41);
}

HWTEST_F(DhcpIpv6ClientTest, getIpv6RouteAddrTest, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("getIpv6RouteAddrTest enter!");
    ipv6Client->getIpv6RouteAddr();
}

HWTEST_F(DhcpIpv6ClientTest, setSocketFilterTest, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("setSocketFilterTest enter!");
    char addr[] = "192.168.1.2";
    ipv6Client->setSocketFilter(nullptr);
    ipv6Client->setSocketFilter(static_cast<void *>(addr));
}

HWTEST_F(DhcpIpv6ClientTest, parseNdUserOptMessageTest, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("parseNdUserOptMessageTest enter!");
    struct nduseroptmsg data;
    data.nduseropt_opts_len = IPV6_LEN_16;
    data.nduseropt_family = IPV6_LEN_10;
    data.nduseropt_icmp_type = IPV6_LEN_134;
    data.nduseropt_icmp_code = IPV6_RETURN_ZERO;
    ipv6Client->parseNdUserOptMessage(nullptr, IPV6_LEN_24);
    ipv6Client->parseNdUserOptMessage(static_cast<void *>(&data), IPV6_LEN_24);

    data.nduseropt_opts_len = IPV6_LEN_24;
    ipv6Client->parseNdUserOptMessage(static_cast<void *>(&data), IPV6_LEN_16);

    data.nduseropt_opts_len = IPV6_LEN_16;
    data.nduseropt_family = IPV6_LEN_16;
    ipv6Client->parseNdUserOptMessage(static_cast<void *>(&data), IPV6_LEN_24);

    data.nduseropt_opts_len = IPV6_LEN_16;
    data.nduseropt_family = IPV6_LEN_10;
    data.nduseropt_icmp_type = IPV6_LEN_16;
    data.nduseropt_icmp_code = IPV6_LEN_16;
    ipv6Client->parseNdUserOptMessage(static_cast<void *>(&data), IPV6_LEN_24);

    data.nduseropt_opts_len = IPV6_LEN_16;
    data.nduseropt_family = IPV6_LEN_10;
    data.nduseropt_icmp_type = IPV6_LEN_134;
    data.nduseropt_icmp_code = IPV6_LEN_16;
    ipv6Client->parseNdUserOptMessage(static_cast<void *>(&data), IPV6_LEN_24);
}

HWTEST_F(DhcpIpv6ClientTest, parseNDRouteMessageTest, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("parseNDRouteMessageTest enter!");
    struct nlmsghdr msg;
    ipv6Client->parseNDRouteMessage(nullptr);
    ipv6Client->parseNDRouteMessage(static_cast<void *>(&msg));
}

HWTEST_F(DhcpIpv6ClientTest, ParseNDRouteMessage_TEST1, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("ParseNDRouteMessage_TEST1 enter!");
    nlmsghdr hdrMsg;
    rtmsg rtMsg;
    hdrMsg.nlmsg_len = sizeof(rtmsg);
    rtMsg.rtm_protocol = RTPROT_BOOT;
    rtMsg.rtm_scope = RT_SCOPE_SITE;
    rtMsg.rtm_type = RTN_MULTICAST;
    rtMsg.rtm_src_len = 1;
    rtMsg.rtm_flags = RTM_F_PREFIX;
    ipv6Client->parseNDRouteMessage(&hdrMsg);
}

HWTEST_F(DhcpIpv6ClientTest, ParseNDRouteMessage_TEST2, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("ParseNDRouteMessage_TEST2 enter!");
    nlmsghdr hdrMsg;
    rtmsg rtMsg;
    hdrMsg.nlmsg_len = sizeof(rtmsg);
    rtMsg.rtm_protocol = RTPROT_KERNEL;
    rtMsg.rtm_scope = RT_SCOPE_UNIVERSE;
    rtMsg.rtm_type = RTN_UNICAST;
    rtMsg.rtm_src_len = 0;
    rtMsg.rtm_flags = 0;
    ipv6Client->parseNDRouteMessage(&hdrMsg);
}

HWTEST_F(DhcpIpv6ClientTest, parseNewneighMessageTest, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("parseNewneighMessageTest enter!");
    struct nlmsghdr msg;
    ipv6Client->parseNewneighMessage(nullptr);
    ipv6Client->parseNewneighMessage(static_cast<void *>(&msg));
}

HWTEST_F(DhcpIpv6ClientTest, ParseNewneighMessage_Test, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("ParseNewneighMessage_Test enter!");
    void* msg = new char[sizeof(nlmsghdr) + sizeof(ndmsg) + sizeof(rtattr) + sizeof(in6_addr)];
    nlmsghdr* nlh = reinterpret_cast<nlmsghdr*>(msg);
    ndmsg* ndm = reinterpret_cast<ndmsg*>((char*)msg + sizeof(nlmsghdr));
    rtattr* rta = reinterpret_cast<rtattr*>((char*)msg + sizeof(nlmsghdr) + sizeof(ndmsg));
    in6_addr* addr = reinterpret_cast<in6_addr*>((char*)msg + sizeof(nlmsghdr) + sizeof(ndmsg) + sizeof(rtattr));
    nlh->nlmsg_type = RTM_NEWNEIGH;
    ndm->ndm_family = KERNEL_SOCKET_IFA_FAMILY;
    ndm->ndm_state = NUD_REACHABLE;
    rta->rta_type = NDA_DST;
    rta->rta_len = sizeof(rtattr) + sizeof(in6_addr);
    ipv6Client->parseNewneighMessage(msg);
}

HWTEST_F(DhcpIpv6ClientTest, fillRouteDataTest, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("fillRouteDataTest enter!");
    int len = 0;
    char buf[BUF_LEN] = {0};
    ipv6Client->fillRouteData(nullptr, len);
    ipv6Client->fillRouteData(buf, len);
}

HWTEST_F(DhcpIpv6ClientTest, handleKernelEventTest, TestSize.Level1)
{
    ASSERT_TRUE(ipv6Client != nullptr);
    DHCP_LOGE("handleKernelEventTest enter!");
    uint8_t data[] = "testcode";
    ipv6Client->handleKernelEvent(nullptr, 0);
    ipv6Client->handleKernelEvent(data, 1);
    ipv6Client->handleKernelEvent(data, DATA_SIZE);
}

HWTEST_F(DhcpIpv6ClientTest, AddIpv6AddressTest, TestSize.Level1)
{
    DHCP_LOGI("AddIpv6Address enter!");
    ipv6Client->AddIpv6Address(nullptr, 0);
}

HWTEST_F(DhcpIpv6ClientTest, AddIpv6AddressTest1, TestSize.Level1)
{
    DHCP_LOGI("AddIpv6Address1 enter!");
    char ipv6Addr[128] = "1001:0db8:85a3:0000:0000:8a2e:0370:7334";
    int len = DHCP_INET6_ADDRSTRLEN - 1;
    ipv6Client->AddIpv6Address(nullptr, len);
}

HWTEST_F(DhcpIpv6ClientTest, IsEui64ModeIpv6AddressTest, TestSize.Level1)
{
    DHCP_LOGI("IsEui64ModeIpv6AddressTest enter!");
    char data[] = "2408:8471:a02:8fc0:200:52ff:fe5d:003b";
    EXPECT_EQ(ipv6Client->IsEui64ModeIpv6Address(nullptr, 0), false);
    EXPECT_EQ(ipv6Client->IsEui64ModeIpv6Address(data, PRE_FIX_ADDRSTRLEN), false);
}
}
}
