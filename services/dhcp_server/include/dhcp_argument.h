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

#include <string>

#ifndef OHOS_DHCP_ARGUMENT_H
#define OHOS_DHCP_ARGUMENT_H

#define ARGUMENT_NAME_SIZE 32
#define ARGUMENT_VALUE_SIZE 256
#define INIT_ARGS_SIZE 4

#define NO_ARG 0
#define REQUIRED_ARG 1
#define OPTIONAL_ARG 2

#define USAGE_DESC_MAX_LENGTH 32

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DhcpUsage DhcpUsage;
struct DhcpUsage {
    struct option *opt;
    const char *params;
    const char *desc;
    const char *example;
    int required;
    int (*dealOption)(const char *, const char *);
};


typedef struct ArgumentInfo ArgumentInfo;
struct ArgumentInfo {
    char name[ARGUMENT_NAME_SIZE];
    char value[ARGUMENT_VALUE_SIZE];
};

int InitArguments(void);
int HasArgument(const char *argument);
ArgumentInfo *GetArgument(const char *name);
int PutArgument(const char *argument, const char *val);

int ParseArguments(const std::string& ifName, const std::string& netMask, const std::string& ipRange,
    const std::string& localIp);

void FreeArguments(void);

#ifdef __cplusplus
}
#endif

#endif // OHOS_DHCP_ARGUMENT_H
