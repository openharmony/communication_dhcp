/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include <vector>
#include <string>
#include <cstring>
#include <netinet/in.h>

#include "dhcp_v6_socket.h"
#include "dhcp_logger.h"
#include "mock_system_func.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpV6SocketTest");

using namespace testing::ext;
using namespace OHOS::DHCP;

namespace OHOS {
class DhcpV6SocketTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        MockSystemFunc::SetMockFlag(true);
    }
    virtual void TearDown()
    {
        MockSystemFunc::SetMockFlag(false);
    }
};

HWTEST_F(DhcpV6SocketTest, Constructor_SUCCESS, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE({
        DhcpV6Socket socket("wlan0");
    });
}

HWTEST_F(DhcpV6SocketTest, DhcpV6Init_SUCCESS, TestSize.Level1)
{
    DhcpV6Socket socket("wlan0");

    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), setsockopt(_, _, _, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), if_nametoindex(_))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_))
        .WillRepeatedly(Return(0));

    EXPECT_EQ(socket.DhcpV6Init(), 0);
}

HWTEST_F(DhcpV6SocketTest, DhcpV6Init_SocketFailed_FAILED, TestSize.Level1)
{
    DhcpV6Socket socket("wlan0");

    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _))
        .WillRepeatedly(Return(-1));

    EXPECT_EQ(socket.DhcpV6Init(), -1);
}

HWTEST_F(DhcpV6SocketTest, DhcpV6Receive_Timeout, TestSize.Level1)
{
    DhcpV6Socket socket("wlan0");

    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), setsockopt(_, _, _, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), if_nametoindex(_))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_))
        .WillRepeatedly(Return(0));

    (void)socket.DhcpV6Init();

    std::vector<uint8_t> data;
    socket.Close();  // Close socket to make socketFd_ = -1
    EXPECT_EQ(socket.DhcpV6Receive(data, 100), -1);  // Should return ERR_GENERIC
}

HWTEST_F(DhcpV6SocketTest, Close_SUCCESS, TestSize.Level1)
{
    DhcpV6Socket socket("wlan0");

    EXPECT_CALL(MockSystemFunc::GetInstance(), socket(_, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(MockSystemFunc::GetInstance(), setsockopt(_, _, _, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), bind(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(MockSystemFunc::GetInstance(), close(_))
        .WillRepeatedly(Return(0));

    (void)socket.DhcpV6Init();
    EXPECT_NO_FATAL_FAILURE(socket.Close());
}
}  // namespace OHOS
