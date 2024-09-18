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
1
#include <gtest/gtest.h>
#include "dhcp_common_utils.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpCommonUtilsTest");

using namespace testing::ext;
using namespace OHOS::DHCP;
namespace OHOS {
constexpr int32_t MAC_LENTH = 6;

class DhcpCommonUtilsTest : public testing::Test {
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

/**
* @tc.name: Ipv4AnonymizeTest_SUCCESS
* @tc.desc: Ipv4AnonymizeTest.
* @tc.type: FUNC
* @tc.require: AR00000000
*/
HWTEST_F(DhcpCommonUtilsTest, Ipv4AnonymizeTest_SUCCESS, TestSize.Level1)
{
    DHCP_LOGI("enter Ipv4AnonymizeTest_SUCCESS");
    std::string ipAddr = "1.2.3.4";
    std::string ret = Ipv4Anonymize(ipAddr);
    EXPECT_TRUE(!ret.empty());
    DHCP_LOGI("ret is %{public}s", ret.c_str());
}

HWTEST_F(DhcpCommonUtilsTest, UintIp4ToStrTest, TestSize.Level1)
{
    DHCP_LOGI("enter UintIp4ToStrTest");
    uint32_t ip = 4294967295;
    char *pIp = UintIp4ToStr(ip, false);
    if (pIp != nullptr) {
        DHCP_LOGI("pIp:%{public}s", pIp);
        free(pIp);
        pIp = nullptr;
    }
    char *pIp2 = UintIp4ToStr(ip, true);
    if (pIp2 != nullptr) {
        DHCP_LOGI("pIp2:%{public}s", pIp2);
        free(pIp2);
        pIp2 = nullptr;
    }
}

HWTEST_F(DhcpCommonUtilsTest, IntIpv4ToAnonymizeStrTest, TestSize.Level1)
{
    DHCP_LOGI("enter IntIpv4ToAnonymizeStrTest");
    uint32_t ip = 4294967295;
    std::string ret = IntIpv4ToAnonymizeStr(ip);
    EXPECT_TRUE(!ret.empty());
    DHCP_LOGI("ret is %{public}s", ret.c_str());
}

HWTEST_F(DhcpCommonUtilsTest, MacArray2StrTest, TestSize.Level1)
{
    DHCP_LOGI("enter MacArray2StrTest");
    uint8_t *macArray = nullptr;
    int32_t len = 0;
    EXPECT_TRUE(MacArray2Str(macArray, len).empty());
    uint8_t mac[MAC_LENTH] = {12, 12, 33, 54, 56, 78};
    EXPECT_TRUE(MacArray2Str(mac, len).empty());
    len = MAC_LENTH;
    EXPECT_TRUE(!MacArray2Str(mac, len).empty());
}

HWTEST_F(DhcpCommonUtilsTest, ValidHexadecimalNumberTest, TestSize.Level1)
{
    DHCP_LOGI("enter ValidHexadecimalNumberTest");
    std::string data = "123456";
    int result = CheckDataLegal(data);
    EXPECT_EQ(result, 123456);
}

HWTEST_F(DhcpCommonUtilsTest, InvalidHexadecimalNumberTest, TestSize.Level1)
{
    DHCP_LOGI("enter InvalidHexadecimalNumberTest");
    std::string data = "abcdef";
    int result = CheckDataLegal(data);
    EXPECT_EQ(result, 0);
}

HWTEST_F(DhcpCommonUtilsTest, EmptyStringTest, TestSize.Level1)
{
    DHCP_LOGI("enter EmptyStringTest");
    std::string data = "";
    int result = CheckDataLegal(data);
    EXPECT_EQ(result, 0);
}
}