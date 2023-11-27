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
#include <getopt.h>
#include <securec.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "address_utils.h"
#include "dhcp_s_define.h"
#include "dhcp_logger.h"
#include "hash_table.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpArgument");

static HashTable g_argumentsTable;

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

static int ShowVersion(const char *argument, const char *val)
{
    DHCP_LOGI("version:%s\n", DHCPD_VERSION);
    return RET_SUCCESS;
}

static int DefaultArgument(const char *argument, const char *val)
{
    DHCP_LOGI("Input argument is: [%s], value is [%s]", (argument == nullptr) ? "" : argument,
        (val == nullptr) ? "" : val);
    return RET_SUCCESS;
}

const char *g_optionString = "i:c:d:g:s:n:P:S:Bp:o:lb:rvhD";

static struct option g_longOptions[] = {
    {"ifname", REQUIRED_ARG, 0, 'i'},
    {"conf", REQUIRED_ARG, 0, 'c'},
    {"dns", REQUIRED_ARG, 0, 'd'},
    {"gateway", REQUIRED_ARG, 0, 'g'},
    {"server", REQUIRED_ARG, 0, 's'},
    {"netmask", REQUIRED_ARG, 0, 'n'},
    {"pool", REQUIRED_ARG, 0, 'P'},
    {"lease", REQUIRED_ARG, 0, 0},
    {"renewal", REQUIRED_ARG, 0, 0},
    {"rebinding", REQUIRED_ARG, 0, 0},
    {"version", NO_ARG, 0, 'v'},
    {"help", NO_ARG, 0, 'h'},
    {0, 0, 0, 0},
};

static DhcpUsage usages[] = {
    {&g_longOptions[NUM_ZERO], "<interface>", "network interface name.", "--ifname eth0", 1, PutArgument},
    {&g_longOptions[NUM_ONE], "<file>", "configure file name.", "--conf /etc/conf/dhcp_server.conf", 0, PutArgument},
    {&g_longOptions[NUM_TWO], "<dns1>[,dns2][,dns3][...]", "domain name server IP address list.", "", 0, PutArgument},
    {&g_longOptions[NUM_THREE], "<gateway>", "gateway option.", "", 0, PutIpArgument},
    {&g_longOptions[NUM_FOUR], "<server>", "server identifier.", "", 1, PutIpArgument},
    {&g_longOptions[NUM_FIVE], "<netmask>", "default subnet mask.", "", 1, PutIpArgument},
    {&g_longOptions[NUM_SIX], "<beginip>,<endip>", "pool address range.", "", 0,
        PutPoolArgument},
    {&g_longOptions[NUM_SEVEN], "<leaseTime>", "set lease time value, the value is in units of seconds.", "", 0,
        PutArgument},
    {&g_longOptions[NUM_EIGHT], "<renewalTime>", "set renewal time value, the value is in units of seconds.", "", 0,
        PutArgument},
    {&g_longOptions[NUM_NINE], "<rebindingTime>", "set rebinding time value, the value is in units of seconds.", "", 0,
        PutArgument},
    {&g_longOptions[NUM_TEN], "", "show version information.", "", 0, ShowVersion},
    {&g_longOptions[NUM_ELEVEN], "", "show help information.", "", 0, DefaultArgument},
    {0, "", "", ""},
};

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
    if (ContainsKey(&g_argumentsTable, (uintptr_t)name)) {
        return 1;
    }
    return 0;
}

static void ShowUsage(const DhcpUsage *usage)
{
    if (!usage || !usage->opt) {
        return;
    }
    if (usage->opt->val) {
        DHCP_LOGI("-%{public}c,--%{public}s ", (char)usage->opt->val, usage->opt->name);
    } else {
        DHCP_LOGI("   --%{public}s ", usage->opt->name);
    }
    if (usage->params[0] == '\0') {
        DHCP_LOGI("\t\t%{public}s\n", usage->desc);
    } else {
        int plen = strlen(usage->params) + strlen(usage->params);
        if (plen < USAGE_DESC_MAX_LENGTH) {
            DHCP_LOGI("\t\t%{public}s\t\t%{public}s\n", usage->params, usage->desc);
        } else {
            DHCP_LOGI("\t\t%{public}s\n", usage->params);
            DHCP_LOGI("\t\t\t%{public}s\n\n", usage->desc);
        }
    }
}

void PrintRequiredArguments(void)
{
    size_t argc = sizeof(usages) / sizeof(DhcpUsage);
    DHCP_LOGI("required parameters:");
    int idx = 0;
    for (size_t i = 0; i < argc; i++) {
        DhcpUsage usage = usages[i];
        if (!usage.opt) {
            break;
        }
        if (usage.required) {
            if (idx == 0) {
                DHCP_LOGI("\"%{public}s\"", usage.opt->name);
            } else {
                DHCP_LOGI(", \"%{public}s\"", usage.opt->name);
            }
            idx++;
        }
    }
    DHCP_LOGI(".\n\n");
    DHCP_LOGI("Usage: dhcp_server [options] \n");
    DHCP_LOGI("e.g: dhcp_server -i eth0 -c /data/service/el1/public/dhcp/dhcp_server.conf \n");
    DHCP_LOGI("     dhcp_server --help \n\n");
}

static void PrintUsage(void)
{
    DHCP_LOGI("Usage: dhcp_server [options] \n\n");

    size_t argc = sizeof(usages) / sizeof(DhcpUsage);
    for (size_t i = 0; i < argc; i++) {
        DhcpUsage usage = usages[i];
        if (!usage.opt) {
            break;
        }
        ShowUsage(&usage);
    }
    DHCP_LOGI("\n");
}

void ShowHelp(int argc)
{
    if (argc == NUM_TWO) {
        PrintUsage();
        return;
    }
}

int InitArguments(void)
{DHCP_LOGI("start InitArguments.");
    if (CreateHashTable(&g_argumentsTable, ARGUMENT_NAME_SIZE, sizeof(ArgumentInfo), INIT_ARGS_SIZE) != HASH_SUCCESS) {
        return RET_FAILED;
    }
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
    if (ContainsKey(&g_argumentsTable, (uintptr_t)argName)) {
        ArgumentInfo *arg = (ArgumentInfo *)At(&g_argumentsTable, (uintptr_t)argName);
        return arg;
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
    int ret = Insert(&g_argumentsTable, (uintptr_t)arg.name, (uintptr_t)&arg);
    if (ret == HASH_INSERTED) {
        return RET_SUCCESS;
    }
    return RET_FAILED;
}

int FindIndex(int c)
{
    int size = sizeof(g_longOptions) / sizeof(g_longOptions[0]);
    for (int i = 0; i < size; ++i) {
        if (g_longOptions[i].val == c) {
            return i;
        }
    }
    return -1;
}

int ParseArguments(const std::string& ifName, const std::string& netMask, const std::string& ipRange)
{
    DHCP_LOGI("start ParseArguments.");
    PutArgument("ifname", ifName.c_str());
    PutIpArgument("server", IP_V4_DEFAULT.c_str());
    PutIpArgument("netmask", netMask.c_str());
    PutPoolArgument("pool", ipRange.c_str());
    return 0;
}

void FreeArguments(void)
{
    if (!Initialized(&g_argumentsTable)) {
        return;
    }
    DestroyHashTable(&g_argumentsTable);
}
