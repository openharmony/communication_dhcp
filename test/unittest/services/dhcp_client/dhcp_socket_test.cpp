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

#include <gtest/gtest.h>

#include "dhcp_logger.h"
#include "dhcp_socket.h"
#include "dhcp_function.h"
#include "securec.h"
#include "mock_system_func.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpSocketTest");

using namespace testing::ext;
using namespace OHOS::DHCP;

namespace OHOS {
class DhcpSocketTest : public testing::Test {
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

HWTEST_F(DhcpSocketTest, CreateRawSocket_SUCCESS, TestSize.Level1)
{
    DHCP_LOGE("enter CreateRawSocket_SUCCESS");
    MockSystemFunc::SetMockFlag(true);

    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _)).WillOnce(Return(-1)).WillRepeatedly(Return(1));
    int fd = -1;
    EXPECT_EQ(CreateRawSocket(&fd), SOCKET_OPT_FAILED);
    EXPECT_EQ(CreateRawSocket(&fd), SOCKET_OPT_SUCCESS);

    MockSystemFunc::SetMockFlag(false);
}

HWTEST_F(DhcpSocketTest, CreateKernelSocket_SUCCESS, TestSize.Level1)
{
    MockSystemFunc::SetMockFlag(true);

    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _)).WillOnce(Return(-1)).WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_)).WillRepeatedly(Return(0));
    int fd = -1;
    EXPECT_EQ(CreateKernelSocket(nullptr), SOCKET_OPT_FAILED);
    EXPECT_EQ(CreateKernelSocket(&fd), SOCKET_OPT_FAILED);
    EXPECT_EQ(CreateKernelSocket(&fd), SOCKET_OPT_SUCCESS);

    MockSystemFunc::SetMockFlag(false);
}

HWTEST_F(DhcpSocketTest, BindRawSocket_SUCCESS, TestSize.Level1)
{
    int fd = -1;
    int ifaceIndex = 1;
    EXPECT_EQ(BindRawSocket(fd, ifaceIndex, NULL), SOCKET_OPT_FAILED);

    MockSystemFunc::SetMockFlag(true);

    fd = 1;
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(_, _, _)).WillOnce(Return(-1)).WillRepeatedly(Return(0));
    EXPECT_EQ(BindRawSocket(fd, ifaceIndex, (uint8_t *)MAC_BCAST_ADDR), SOCKET_OPT_FAILED);
    EXPECT_EQ(BindRawSocket(fd, ifaceIndex, (uint8_t *)MAC_BCAST_ADDR), SOCKET_OPT_SUCCESS);

    MockSystemFunc::SetMockFlag(false);
}

HWTEST_F(DhcpSocketTest, BindKernelSocket_SUCCESS, TestSize.Level1)
{
    int fd = -1;
    EXPECT_EQ(BindKernelSocket(fd, NULL, 0, 0, false), SOCKET_OPT_FAILED);

    MockSystemFunc::SetMockFlag(true);

    fd = 1;
    const char *ifname = "wlan0";
    EXPECT_CALL(MockSystemFunc::GetInstance(), setsockopt(_, _, _, _, _))
        .WillOnce(Return(-1))
        .WillOnce(Return(-1))
        .WillOnce(Return(-1)).WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(_, _, _)).WillOnce(Return(-1)).WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_)).WillRepeatedly(Return(0));

    EXPECT_EQ(BindKernelSocket(fd, ifname, 0, 0, false), SOCKET_OPT_FAILED);
    EXPECT_EQ(BindKernelSocket(fd, NULL, 0, 0, true), SOCKET_OPT_FAILED);
    EXPECT_EQ(BindKernelSocket(fd, NULL, 0, 0, false), SOCKET_OPT_FAILED);
    EXPECT_EQ(BindKernelSocket(fd, NULL, INADDR_ANY, BOOTP_CLIENT, false), SOCKET_OPT_FAILED);
    EXPECT_EQ(BindKernelSocket(fd, ifname, INADDR_ANY, BOOTP_CLIENT, true), SOCKET_OPT_SUCCESS);

    MockSystemFunc::SetMockFlag(false);
}

HWTEST_F(DhcpSocketTest, SendToDhcpPacket_SUCCESS, TestSize.Level1)
{
    uint32_t srcIp = 3226272232;
    uint32_t destIp = 3226272232;
    int destIndex = 1;
    uint8_t destHwaddr[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

    struct DhcpPacket packet;
    ASSERT_TRUE(memset_s(&packet, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket)) == EOK);

    int endIndex = 0;
    uint8_t *pOption = packet.options;
    pOption[endIndex + DHCP_OPT_CODE_INDEX] = PAD_OPTION;
    endIndex += DHCP_OPT_CODE_BYTES;

    pOption[endIndex + DHCP_OPT_CODE_INDEX] = SUBNET_MASK_OPTION;
    pOption[endIndex + DHCP_OPT_LEN_INDEX] = DHCP_UINT32_BYTES;
    uint32_t u32Data = 3226272231;
    ASSERT_TRUE(
        memcpy_s(pOption + endIndex + DHCP_OPT_DATA_INDEX, DHCP_UINT32_BYTES, &u32Data, DHCP_UINT32_BYTES) == EOK);
    endIndex += DHCP_OPT_CODE_BYTES + DHCP_OPT_LEN_BYTES + pOption[endIndex + DHCP_OPT_LEN_INDEX];

    pOption[endIndex + DHCP_OPT_CODE_INDEX] = END_OPTION;

    int result = SendToDhcpPacket(&packet, srcIp, destIp, destIndex, destHwaddr);
    EXPECT_EQ(result, 0);
}

HWTEST_F(DhcpSocketTest, SendDhcpPacket_SUCCESS, TestSize.Level1)
{
    MockSystemFunc::SetMockFlag(true);

    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _)).WillOnce(Return(-1)).WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(_, _, _)).WillOnce(Return(-1)).WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), connect(_, _, _)).WillOnce(Return(-1)).WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), write(_, _, _)).WillOnce(Return(-1)).WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_)).WillRepeatedly(Return(0));
    struct DhcpPacket packet;
    packet.options[0] = END_OPTION;
    EXPECT_EQ(SendDhcpPacket(&packet, 0, 0), SOCKET_OPT_FAILED);
    EXPECT_EQ(SendDhcpPacket(&packet, INADDR_ANY, 0), SOCKET_OPT_FAILED);
    EXPECT_EQ(SendDhcpPacket(&packet, INADDR_ANY, INADDR_BROADCAST), SOCKET_OPT_FAILED);
    packet.xid = 123456;
    EXPECT_NE(SendDhcpPacket(&packet, INADDR_ANY, INADDR_BROADCAST), SOCKET_OPT_ERROR);
    MockSystemFunc::SetMockFlag(false);
}

HWTEST_F(DhcpSocketTest, CheckReadBytes_SUCCESS, TestSize.Level1)
{
    int count = -1;
    int total = 0;
    EXPECT_EQ(CheckReadBytes(-1, 0), SOCKET_OPT_ERROR);

    count = sizeof(struct iphdr) + sizeof(struct udphdr) - 1;
    EXPECT_EQ(CheckReadBytes(count, 0), SOCKET_OPT_FAILED);

    count = sizeof(struct iphdr) + sizeof(struct udphdr);
    total = count + 1;
    EXPECT_EQ(CheckReadBytes(count, total), SOCKET_OPT_FAILED);

    total = count;
    EXPECT_EQ(CheckReadBytes(count, total), SOCKET_OPT_SUCCESS);
}

HWTEST_F(DhcpSocketTest, CheckUdpPacket_SUCCESS, TestSize.Level1)
{
    EXPECT_EQ(CheckUdpPacket(NULL, 0), SOCKET_OPT_FAILED);

    struct UdpDhcpPacket packet;
    int total = (int)sizeof(struct UdpDhcpPacket) + 1;
    EXPECT_EQ(CheckUdpPacket(&packet, total), SOCKET_OPT_FAILED);

    total = (int)sizeof(struct UdpDhcpPacket);
    packet.ip.protocol = 0;
    packet.ip.version = 0;
    EXPECT_EQ(CheckUdpPacket(&packet, total), SOCKET_OPT_FAILED);

    packet.ip.protocol = IPPROTO_UDP;
    packet.ip.version = IPVERSION;
    packet.ip.ihl = 0;
    EXPECT_EQ(CheckUdpPacket(&packet, total), SOCKET_OPT_FAILED);

    packet.ip.ihl = (uint32_t)(sizeof(packet.ip) >> DHCP_UINT16_BYTES);
    packet.udp.dest = 0;
    EXPECT_EQ(CheckUdpPacket(&packet, total), SOCKET_OPT_FAILED);

    packet.udp.dest = htons(BOOTP_CLIENT);
    packet.udp.len = 0;
    EXPECT_EQ(CheckUdpPacket(&packet, total), SOCKET_OPT_FAILED);

    uint16_t uLen = (uint16_t)(total - (int)sizeof(packet.ip));
    packet.udp.len = htons(uLen);
    EXPECT_EQ(CheckUdpPacket(&packet, total), SOCKET_OPT_SUCCESS);
}

HWTEST_F(DhcpSocketTest, CheckPacketIpSum_FAILED, TestSize.Level1)
{
    EXPECT_EQ(CheckPacketIpSum(NULL, 0), SOCKET_OPT_FAILED);

    struct UdpDhcpPacket packet;
    int total = (int)sizeof(struct UdpDhcpPacket) + 1;
    EXPECT_EQ(CheckPacketIpSum(&packet, total), SOCKET_OPT_FAILED);

    total = (int)sizeof(struct UdpDhcpPacket);
    packet.ip.protocol = IPPROTO_UDP;
    packet.ip.version = IPVERSION;
    packet.ip.ihl = (uint32_t)(sizeof(packet.ip) >> DHCP_UINT16_BYTES);
    packet.udp.dest = htons(BOOTP_CLIENT);
    uint16_t uLen = (uint16_t)(total - (int)sizeof(packet.ip));
    packet.udp.len = htons(uLen);
    packet.ip.check = 0;
    EXPECT_EQ(CheckPacketIpSum(&packet, total), SOCKET_OPT_ERROR);
}

HWTEST_F(DhcpSocketTest, CheckPacketUdpSum_SUCCESS, TestSize.Level1)
{
    EXPECT_EQ(CheckPacketUdpSum(NULL, 0), SOCKET_OPT_FAILED);

    struct UdpDhcpPacket packet;
    packet.udp.check = 1;
    EXPECT_EQ(CheckPacketUdpSum(&packet, 0), SOCKET_OPT_FAILED);
    packet.udp.check = 0;
    EXPECT_EQ(CheckPacketUdpSum(&packet, 1), SOCKET_OPT_SUCCESS);
}

HWTEST_F(DhcpSocketTest, GetDhcpKernelPacket_SUCCESS, TestSize.Level1)
{
    EXPECT_EQ(GetDhcpKernelPacket(NULL, 0), SOCKET_OPT_FAILED);

    MockSystemFunc::SetMockFlag(true);

    EXPECT_CALL(MockSystemFunc::GetInstance(), read(_, _, _)).WillOnce(Return(-1)).WillRepeatedly(Return(1));

    struct DhcpPacket packet;
    EXPECT_EQ(GetDhcpKernelPacket(&packet, 1), SOCKET_OPT_ERROR);

    MockSystemFunc::SetMockFlag(false);
}

HWTEST_F(DhcpSocketTest, GetDhcpRawPacket_FAILED, TestSize.Level1)
{
    EXPECT_EQ(GetDhcpRawPacket(NULL, 1), SOCKET_OPT_FAILED);

    struct DhcpPacket packet;
    EXPECT_EQ(GetDhcpRawPacket(&packet, 1), SOCKET_OPT_ERROR);
}
}  // namespace OHOS