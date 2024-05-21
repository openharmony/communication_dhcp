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
#include "dhcp_common_utils.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpCommonUtilsTest");

using namespace testing::ext;
using namespace OHOS::DHCP;

namespace OHOS {
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
}