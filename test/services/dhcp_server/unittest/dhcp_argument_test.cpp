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
#include <string>
#include <securec.h>
#include <cstdlib>
#include <cstdio>
#include "dhcp_argument.h"
#include "dhcp_s_define.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpArgumentTest");

using namespace testing::ext;

namespace OHOS {
namespace Wifi {
HWTEST(DhcpArgumentTest, InitArgumentsTest, TestSize.Level1)
{
    EXPECT_TRUE(InitArguments() == RET_SUCCESS);
}

HWTEST(DhcpArgumentTest, PutArgumentTest, TestSize.Level1)
{
    EXPECT_TRUE(PutArgument(NULL, NULL) == RET_FAILED);
    const char *argu = "lease";
    const char *val = "4000";
    EXPECT_TRUE(PutArgument(NULL, val) == RET_FAILED);
    EXPECT_TRUE(PutArgument(argu, NULL) == RET_FAILED);
    EXPECT_TRUE(PutArgument(argu, val) == RET_SUCCESS);
    argu = "xxxx";
    val = "nothing";
    EXPECT_TRUE(PutArgument(argu, val) == RET_SUCCESS);
    EXPECT_TRUE(PutArgument(argu, val) == RET_FAILED);
    argu = "longlongvalue";
    val = "verylongvalueverylongvalueverylongvalueverylongvalueverylongvalueverylongvalueverylongvalueverylongvaluevery"
    "longvalueverylongvalueverylongvalueverylongvalueverylongvalueverylongvalueverylongvalueverylongvalueverylongvaluev"
    "erylongvalueverylongvalueverylongvalueverylongvalue";
    EXPECT_TRUE(PutArgument(argu, val) == RET_ERROR);
}

HWTEST(DhcpArgumentTest, GetArgumentTest, TestSize.Level1)
{
    DHCP_LOGE("enter GetArgumentTest");
    ArgumentInfo *arg = GetArgument("lease");
    EXPECT_TRUE(arg);
    EXPECT_EQ(0, strncmp(arg->name, "lease", strlen("lease")));
    EXPECT_EQ(0, strncmp(arg->value, "4000", strlen("4000")));

    arg = GetArgument("xxxx");
    EXPECT_TRUE(arg);
    EXPECT_EQ(0, strncmp(arg->name, "xxxx", strlen("xxxx")));
    EXPECT_EQ(0, strncmp(arg->value, "nothing", strlen("nothing")));
}

HWTEST(DhcpArgumentTest, HasArgumentTest, TestSize.Level1)
{
    const char *name = "xxx";
    EXPECT_TRUE(HasArgument(name) == 0);
    name = "lease";
    EXPECT_TRUE(HasArgument(name) == 1);
    name = nullptr;
    EXPECT_TRUE(HasArgument(name) == 0);
    FreeArguments();
}
}
}