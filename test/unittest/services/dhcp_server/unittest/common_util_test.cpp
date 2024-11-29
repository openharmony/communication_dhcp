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
#include "dhcp_s_define.h"
#include "common_util.h"
#include "dhcp_logger.h"

using namespace testing::ext;
namespace OHOS {
namespace DHCP {

HWTEST(CommonUtilTest, TrimStringTest, TestSize.Level1)
{
    char src1[] = "aabbccdd ";
    char src2[] = " aabbccdd";
    char src3[] = " aabbccdd  ";
    TrimString(src1);
    TrimString(src2);
    TrimString(src3);
    EXPECT_STREQ("aabbccdd", src1);
    EXPECT_STREQ("aabbccdd", src2);
    EXPECT_STREQ("aabbccdd", src3);
}

HWTEST(CommonUtilTest, GetFilePathTest, TestSize.Level1)
{
    const char *testPath = "/etc/dhcp/dhcp_server.conf";
    EXPECT_TRUE(GetFilePath(NULL) == NULL);
    EXPECT_TRUE(GetFilePath("") == NULL);
    EXPECT_STREQ("/etc/dhcp", GetFilePath(testPath));
}

HWTEST(CommonUtilTest, CreatePathTest, TestSize.Level1)
{
    const char *testPath = "./test/data/testpath";
    ASSERT_EQ(RET_FAILED, CreatePath(NULL));
    ASSERT_EQ(RET_FAILED, CreatePath(""));
    ASSERT_EQ(RET_SUCCESS, CreatePath(testPath));
    EXPECT_EQ(0, remove(testPath));
}

HWTEST(CommonUtilTest, RemoveSpaceCharactersTest, TestSize.Level1)
{
    char buf[] = "0";
    size_t bufSize = 0;
    int result = RemoveSpaceCharacters(buf, bufSize);
    EXPECT_EQ(0, result);
}
}
}