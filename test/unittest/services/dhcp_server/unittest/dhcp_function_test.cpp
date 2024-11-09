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

#include "dhcp_function.h"
#include "system_func_mock.h"
#include "securec.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::DHCP;
namespace OHOS {
namespace DHCP {
constexpr int DHCP_FAILED_CODE = -1;
class DhcpFunctionTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
    }
    virtual void TearDown()
    {
    }
};

HWTEST_F(DhcpFunctionTest, Ip4StrConToInt_SUCCESS, TestSize.Level1)
{
    std::string strIp = "192.77.1.232";
    uint32_t uSerIp = 0;
    EXPECT_EQ(true, DhcpFunction::Ip4StrConToInt(strIp, uSerIp));
    printf("DhcpFunctionTest Ip4StrConToInt_SUCCESS strIp:%s -> uSerIp:%u.\n", strIp.c_str(), uSerIp);
}

HWTEST_F(DhcpFunctionTest, Ip4StrConToInt_FAILED, TestSize.Level1)
{
    std::string strIp = "test4";
    uint32_t uSerIp = 0;
    EXPECT_EQ(false, DhcpFunction::Ip4StrConToInt(strIp, uSerIp));

    strIp.clear();
    uSerIp = 0;
    EXPECT_EQ(false, DhcpFunction::Ip4StrConToInt(strIp, uSerIp));
}

HWTEST_F(DhcpFunctionTest, Ip6StrConToChar_SUCCESS, TestSize.Level1)
{
    std::string strIp = "fe80::20c:29ff:fed7:fac8";
    uint8_t	addr6[sizeof(struct in6_addr)] = {0};
    EXPECT_EQ(true, DhcpFunction::Ip6StrConToChar(strIp, addr6, sizeof(struct in6_addr)));
}

HWTEST_F(DhcpFunctionTest, Ip6StrConToChar_FAILED, TestSize.Level1)
{
    std::string strIp = "test6";
    uint8_t	addr6[sizeof(struct in6_addr)] = {0};
    EXPECT_EQ(false, DhcpFunction::Ip6StrConToChar(strIp, addr6, sizeof(struct in6_addr)));

    strIp.clear();
    EXPECT_EQ(false, DhcpFunction::Ip6StrConToChar(strIp, addr6, sizeof(struct in6_addr)));
}

HWTEST_F(DhcpFunctionTest, Ip6CharConToStr_SUCCESS, TestSize.Level1)
{
    uint8_t	addr6[sizeof(struct in6_addr)] = {0};
    EXPECT_STREQ(DhcpFunction::Ip6CharConToStr(addr6, sizeof(struct in6_addr)).c_str(), "");
}

HWTEST_F(DhcpFunctionTest, Ip6CharConToStr_FAILED, TestSize.Level1)
{
    uint8_t	addr6[sizeof(struct in6_addr)] = {0};
    EXPECT_STREQ(DhcpFunction::Ip6CharConToStr(addr6, 0).c_str(), "");
}

HWTEST_F(DhcpFunctionTest, CheckIpStr_SUCCESS, TestSize.Level1)
{
    std::string strIp4 = "192.77.1.232";
    EXPECT_EQ(true, DhcpFunction::CheckIpStr(strIp4));

    std::string strIp6 = "fe80::20c:29ff:fed7:fac8";
    EXPECT_EQ(true, DhcpFunction::CheckIpStr(strIp6));
}

HWTEST_F(DhcpFunctionTest, CheckIpStr_FAILED, TestSize.Level1)
{
    std::string strIp1 = "192.77.232";
    EXPECT_EQ(false, DhcpFunction::CheckIpStr(strIp1));
    strIp1.clear();
    EXPECT_EQ(false, DhcpFunction::CheckIpStr(strIp1));

    std::string strIp2 = "fe80:fac8";
    EXPECT_EQ(false, DhcpFunction::CheckIpStr(strIp2));

    std::string strIp3 = "192.77.232:fe80:fac8";
    EXPECT_EQ(false, DhcpFunction::CheckIpStr(strIp3));
}

HWTEST_F(DhcpFunctionTest, GetLocalIp_TEST, TestSize.Level1)
{
    std::string ifname, ip, netmask;
    EXPECT_EQ(DHCP_OPT_ERROR, DhcpFunction::GetLocalIp(ifname, ip, netmask));

    SystemFuncMock::SetMockFlag(true);

    EXPECT_CALL(SystemFuncMock::GetInstance(), socket(_, _, _)).WillRepeatedly(Return(1));
    EXPECT_CALL(SystemFuncMock::GetInstance(), ioctl(_, _, _))
        .WillOnce(Return(-1))
        .WillOnce(Return(0)).WillOnce(Return(-1))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(SystemFuncMock::GetInstance(), close(_)).WillRepeatedly(Return(0));

    ifname = "wlan";
    EXPECT_EQ(DHCP_OPT_FAILED, DhcpFunction::GetLocalIp(ifname, ip, netmask));
    EXPECT_EQ(DHCP_OPT_FAILED, DhcpFunction::GetLocalIp(ifname, ip, netmask));

    SystemFuncMock::SetMockFlag(false);
}

HWTEST_F(DhcpFunctionTest, GetLocalMac_TEST, TestSize.Level1)
{
    SystemFuncMock::SetMockFlag(true);

    EXPECT_CALL(SystemFuncMock::GetInstance(), socket(_, _, _)).WillOnce(Return(-1)).WillRepeatedly(Return(1));
    EXPECT_CALL(SystemFuncMock::GetInstance(), ioctl(_, _, _))
        .WillOnce(Return(-1)).WillRepeatedly(Return(0));
    EXPECT_CALL(SystemFuncMock::GetInstance(), close(_)).WillRepeatedly(Return(0));

    std::string ifname = "wlan";
    std::string mac;
    EXPECT_EQ(-1, DhcpFunction::GetLocalMac(ifname, mac));
    EXPECT_EQ(-1, DhcpFunction::GetLocalMac(ifname, mac));

    SystemFuncMock::SetMockFlag(false);
}

HWTEST_F(DhcpFunctionTest, CheckRangeNetwork_TEST, TestSize.Level1)
{
    std::string ifname, begin, end;
    EXPECT_EQ(DHCP_OPT_ERROR, DhcpFunction::CheckRangeNetwork(ifname, begin, end));
}

HWTEST_F(DhcpFunctionTest, CheckRangeNetwork_TEST01, TestSize.Level1)
{
    std::string ifname, begin, end;
    EXPECT_EQ(DHCP_OPT_ERROR, DhcpFunction::CheckRangeNetwork(nullptr, begin, end));
    EXPECT_EQ(DHCP_OPT_ERROR, DhcpFunction::CheckRangeNetwork(ifname, nullptr, end));
    EXPECT_EQ(DHCP_OPT_ERROR, DhcpFunction::CheckRangeNetwork(ifname, begin, nullptr));

    EXPECT_EQ(DHCP_OPT_ERROR, DhcpFunction::CheckRangeNetwork(nullptr, nullptr, end));
    EXPECT_EQ(DHCP_OPT_ERROR, DhcpFunction::CheckRangeNetwork(nullptr, begin, nullptr));
    EXPECT_EQ(DHCP_OPT_ERROR, DhcpFunction::CheckRangeNetwork(ifname, nullptr, nullptr));

    EXPECT_EQ(DHCP_OPT_ERROR, DhcpFunction::CheckRangeNetwork(nullptr, nullptr, nullptr));
}

HWTEST_F(DhcpFunctionTest, FileManage_SUCCESS, TestSize.Level1)
{
    std::string strFile = "./wlan0.result";
    bool bExist = DhcpFunction::IsExistFile(strFile);
    if (bExist) {
        EXPECT_EQ(true, DhcpFunction::RemoveFile(strFile));
        usleep(200);
    } else {
        EXPECT_EQ(false, DhcpFunction::RemoveFile(strFile));
    }

    std::string strData = "IP4 1624421132 192.168.1.207 192.168.1.2 255.255.255.0 192.168.1.2 * 192.168.1.2 * * 43200";
    EXPECT_EQ(true, DhcpFunction::CreateFile(strFile, strData));

    std::string strAdd = "test add str";
    EXPECT_EQ(true, DhcpFunction::AddFileLineData(strFile, strData, strAdd));
    std::string strModify = "test modify str";
    EXPECT_EQ(true, DhcpFunction::ModifyFileLineData(strFile, strAdd, strModify));
    EXPECT_EQ(true, DhcpFunction::DelFileLineData(strFile, strModify));

    EXPECT_EQ(true, DhcpFunction::RemoveFile(strFile));
}

HWTEST_F(DhcpFunctionTest, FileManage_FAILED, TestSize.Level1)
{
    std::string strFile = "./test/wlan0.result";
    EXPECT_EQ(false, DhcpFunction::RemoveFile(strFile));
}

HWTEST_F(DhcpFunctionTest, FormatString_SUCCESS, TestSize.Level1)
{
    struct DhcpPacketResult result;
    ASSERT_TRUE(memset_s(&result, sizeof(result), 0, sizeof(result)) == EOK);
    ASSERT_TRUE(strncpy_s(result.strYiaddr, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) == EOK);
    ASSERT_TRUE(strncpy_s(result.strOptServerId, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) == EOK);
    ASSERT_TRUE(strncpy_s(result.strOptSubnet, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) == EOK);
    ASSERT_TRUE(strncpy_s(result.strOptDns1, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) == EOK);
    ASSERT_TRUE(strncpy_s(result.strOptDns2, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) == EOK);
    ASSERT_TRUE(strncpy_s(result.strOptRouter1, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) == EOK);
    ASSERT_TRUE(strncpy_s(result.strOptRouter2, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) == EOK);
    ASSERT_TRUE(strncpy_s(result.strOptVendor, DHCP_FILE_MAX_BYTES, "*", DHCP_FILE_MAX_BYTES - 1) == EOK);
    EXPECT_EQ(0, DhcpFunction::FormatString(result));
}

HWTEST_F(DhcpFunctionTest, FormatString_FAIL, TestSize.Level1)
{
    struct DhcpPacketResult result;
    ASSERT_TRUE(memset_s(&result, sizeof(result), 0, sizeof(result)) == EOK);
    ASSERT_TRUE(strncpy_s(result.strYiaddr, INET_ADDRSTRLEN, "1", INET_ADDRSTRLEN - 1) == EOK);
    ASSERT_TRUE(strncpy_s(result.strOptServerId, INET_ADDRSTRLEN, "1", INET_ADDRSTRLEN - 1) == EOK);
    ASSERT_TRUE(strncpy_s(result.strOptSubnet, INET_ADDRSTRLEN, "1", INET_ADDRSTRLEN - 1) == EOK);
    ASSERT_TRUE(strncpy_s(result.strOptDns1, INET_ADDRSTRLEN, "1", INET_ADDRSTRLEN - 1) == EOK);
    ASSERT_TRUE(strncpy_s(result.strOptDns2, INET_ADDRSTRLEN, "1", INET_ADDRSTRLEN - 1) == EOK);
    ASSERT_TRUE(strncpy_s(result.strOptRouter1, INET_ADDRSTRLEN, "1", INET_ADDRSTRLEN - 1) == EOK);
    ASSERT_TRUE(strncpy_s(result.strOptRouter2, INET_ADDRSTRLEN, "1", INET_ADDRSTRLEN - 1) == EOK);
    ASSERT_TRUE(strncpy_s(result.strOptVendor, DHCP_FILE_MAX_BYTES, "1", DHCP_FILE_MAX_BYTES - 1) == EOK);
    EXPECT_EQ(0, DhcpFunction::FormatString(result));
}

HWTEST_F(DhcpFunctionTest, InitPidfile_TEST, TestSize.Level1)
{
    std::string pidDir, pidFile;
    EXPECT_EQ(DHCP_OPT_FAILED, DhcpFunction::InitPidfile(pidDir, pidFile));

    SystemFuncMock::SetMockFlag(true);

    EXPECT_CALL(SystemFuncMock::GetInstance(), open(_, _)).WillOnce(Return(-1)).WillRepeatedly(Return(1));
    EXPECT_CALL(SystemFuncMock::GetInstance(), close(_)).WillRepeatedly(Return(0));

    pidDir = "./";
    pidFile = "./wlan.pid";
    EXPECT_EQ(DHCP_OPT_FAILED, DhcpFunction::InitPidfile(pidDir, pidFile));

    SystemFuncMock::SetMockFlag(false);
}

HWTEST_F(DhcpFunctionTest, GetPID_TEST, TestSize.Level1)
{
    std::string pidDir = "./";
    std::string pidFile = "./wlan.pid";
    EXPECT_EQ(DHCP_OPT_SUCCESS, DhcpFunction::InitPidfile(pidDir, pidFile));
    EXPECT_GT(DhcpFunction::GetPID(pidFile), 0);
    unlink(pidFile.c_str());
    EXPECT_EQ(DhcpFunction::GetPID(pidFile), -1);
}

HWTEST_F(DhcpFunctionTest, CreateDirs_TEST, TestSize.Level1)
{
    std::string strDir;
    EXPECT_EQ(DhcpFunction::CreateDirs(strDir), DHCP_OPT_FAILED);
}

HWTEST_F(DhcpFunctionTest, CheckProRunningTest, TestSize.Level1)
{
    std::string proName;
    pid_t proPid = 0;
    EXPECT_EQ(DhcpFunction::CheckProRunning(proPid, proName), DHCP_FAILED_CODE);
    proPid = 1234;
    EXPECT_EQ(DhcpFunction::CheckProRunning(proPid, proName), DHCP_FAILED_CODE);
    proName = "testcode";
    EXPECT_EQ(DhcpFunction::CheckProRunning(proPid, proName), DHCP_OPT_SUCCESS);
}

HWTEST_F(DhcpFunctionTest, SplitStringTest, TestSize.Level1)
{
    std::string src, delim;
    int count = 0;
    std::vector<std::string> splits {};
    EXPECT_EQ(DhcpFunction::SplitString(src, delim, count, splits), false);

    src = "testcode";
    delim = "test";
    count = -1;
    EXPECT_EQ(DhcpFunction::SplitString(src, delim, count, splits), false);
}

HWTEST_F(DhcpFunctionTest, WaitProcessExit01, TestSize.Level1)
{
    pid_t serverPid = 1235;
    EXPECT_EQ(DhcpFunction::WaitProcessExit(serverPid), -1);
}
}
}
