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

#include "dhcp_argument.h"
#include <map>
#include <getopt.h>
#include <securec.h>
#include <stddef.h>
#include <stdint.h>
#include <cstdio>
#include <string.h>
#include "address_utils.h"
#include "dhcp_s_define.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpArgument");

static std::map<std::string, ArgumentInfo> g_argumentsTable;

static int PutIpArgument(const char *argument, const char *val)
{
    if (!ParseIpAddr(val)) {
        DHCP_LOGE("%s format error.", argument);
        return RET_FAILED;
    }
    return PutArgument(argument, val);
}

static int PutPoolArgument(const char *argument, const char *val)
{
    if (!val) {
        return 0;
    }
    if (strchr(val, ',') == nullptr) {
        DHCP_LOGE("too few pool option arguments.");
        return RET_FAILED;
    }
    return PutArgument(argument, val);
}

int HasArgument(const char *argument)
{
    char name[ARGUMENT_NAME_SIZE] = {'\0'};
    if (!argument) {
        return 0;
    }
    size_t ssize = strlen(argument);
    if (ssize > ARGUMENT_NAME_SIZE) {
        ssize = ARGUMENT_NAME_SIZE;
    }
    if (memcpy_s(name, ARGUMENT_NAME_SIZE, argument, ssize) != EOK) {
        DHCP_LOGE("failed to set argument name.");
        return 0;
    }
    if (g_argumentsTable.empty()) {
        return 0;
    }
    if (g_argumentsTable.count(name) > 0) {
        return 1;
    }
    return 0;
}

int InitArguments(void)
{
    DHCP_LOGI("start InitArguments.");
    g_argumentsTable.clear();
    DHCP_LOGI("end InitArguments.");
    return RET_SUCCESS;
}

ArgumentInfo *GetArgument(const char *name)
{
    char argName[ARGUMENT_NAME_SIZE] = {'\0'};
    size_t ssize = strlen(name);
    if (ssize > ARGUMENT_NAME_SIZE) {
        ssize = ARGUMENT_NAME_SIZE;
    }
    if (memcpy_s(argName, ARGUMENT_NAME_SIZE, name, ssize) != EOK) {
        DHCP_LOGE("failed to set argument name.");
        return nullptr;
    }
    if (g_argumentsTable.count(argName) > 0) {
        return &g_argumentsTable[argName];
    }
    return nullptr;
}

int PutArgument(const char *argument, const char *val)
{
    DHCP_LOGI("start PutArgument.");
    if (!argument) {
        return RET_FAILED;
    }
    if (!val) {
        return RET_FAILED;
    }

    if (HasArgument(argument)) {
        return RET_FAILED;
    }

    ArgumentInfo arg;
    size_t ssize = strlen(argument);
    if (ssize >= ARGUMENT_NAME_SIZE) {
        ssize = ARGUMENT_NAME_SIZE -1;
    }
    size_t vlen = strlen(val);
    if (memset_s(arg.name, ARGUMENT_NAME_SIZE, '\0', ARGUMENT_NAME_SIZE) != EOK) {
        DHCP_LOGE("failed to reset argument name.");
        return RET_ERROR;
    }
    if (memcpy_s(arg.name, ARGUMENT_NAME_SIZE, argument, ssize) != EOK) {
        DHCP_LOGE("failed to set argument name.");
        return RET_ERROR;
    }
    if (vlen >= ARGUMENT_VALUE_SIZE) {
        DHCP_LOGE("value string too long.");
        return RET_ERROR;
    }
    if (memset_s(arg.value, ARGUMENT_VALUE_SIZE, '\0', ARGUMENT_NAME_SIZE) != EOK) {
        DHCP_LOGE("failed to reset argument value.");
        return RET_ERROR;
    }
    if (memcpy_s(arg.value, ARGUMENT_VALUE_SIZE, val, vlen) != EOK) {
        DHCP_LOGE("failed to set argument value.");
        return RET_ERROR;
    }
    g_argumentsTable[std::string(arg.name)] = arg;
    return RET_SUCCESS;
}

int ParseArguments(const std::string& ifName, const std::string& netMask, const std::string& ipRange,
    const std::string& localIp)
{
    DHCP_LOGI("start ParseArguments.");
    PutArgument("ifname", ifName.c_str());
    PutIpArgument("server", localIp.c_str());
    PutIpArgument("netmask", netMask.c_str());
    PutPoolArgument("pool", ipRange.c_str());
    return 0;
}

void FreeArguments(void)
{
    g_argumentsTable.clear();
}
