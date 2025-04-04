/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "common_util.h"
#include <ctype.h>
#include <securec.h>
#include <stdint.h>
#include <cstdio>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include "dhcp_s_define.h"
#include "dhcp_logger.h"

#define NEW_FILEPATH_MODE 0755
#define TIME_BASE_YEAR 1900
#define TIME_SEC_TO_USEC (1000 * 1000)

DEFINE_DHCPLOG_DHCP_LABEL("DhcpServerCommon");

typedef struct tm *ptm;

uint64_t Tmspusec(void)
{
    struct timeval t;
    gettimeofday(&t, 0);
    return (uint64_t)((long long)t.tv_sec * TIME_SEC_TO_USEC + t.tv_usec);
}

uint64_t Tmspsec(void)
{
    struct timeval t;
    gettimeofday(&t, 0);
    return (uint64_t)((long long)t.tv_sec);
}

static void LeftTrim(char *buf)
{
    if (buf == nullptr || (buf[0] != ' ' && buf[0] != '\t')) {
        return;
    }
    int i = 0;
    while (buf[i] == ' ' || buf[i] == '\t') {
        ++i;
    }
    int j = 0;
    while (buf[i] != '\0') {
        buf[j++] = buf[i++];
    }
    buf[j] = '\0';
    return;
}

static void RightTrim(char *buf)
{
    if (buf == nullptr || buf[0] == '\0') {
        return;
    }
    int i = strlen(buf) - 1;
    while (i >= 0 && (buf[i] == ' ' || buf[i] == '\t')) {
        buf[i] = '\0';
        --i;
    }
    return;
}

void TrimString(char *buf)
{
    RightTrim(buf);
    LeftTrim(buf);
    return;
}

const char *GetFilePath(const char *fileName)
{
    static char currFilePath[DHCP_MAX_PATH_LENGTH];
    if (!fileName) {
        return 0;
    }
    int flen = strlen(fileName);
    if (flen == 0) {
        return 0;
    }
    char currName[DHCP_MAX_PATH_LENGTH] = {'\0'};
    if (memcpy_s(currName, sizeof(currName), fileName, strlen(fileName)) != EOK) {
        return 0;
    }
    char *last = strrchr(currName, '/');
    if (last) {
        *last = '\0';
    }
    if (memset_s(currFilePath, sizeof(currFilePath), '\0', sizeof(currFilePath)) != EOK) {
        return 0;
    }
    if (memcpy_s(currFilePath, sizeof(currFilePath), currName, strlen(currName)) != EOK) {
        return 0;
    }
    return currFilePath;
}

int CreatePath(const char *fileName)
{
    if (!fileName) {
        return RET_FAILED;
    }
    int len = strlen(fileName);
    if (!len) {
        return RET_FAILED;
    }
    char filePath[DHCP_MAX_PATH_LENGTH] = {'\0'};
    if (strncpy_s(filePath, sizeof(filePath), fileName, len) != EOK) {
        return RET_FAILED;
    }
    for (int i = 0; i < len; i++) {
        if (filePath[i] == '/') {
            filePath[i] = '\0';
            if (access(filePath, 0) != 0) {
                mkdir(filePath, NEW_FILEPATH_MODE);
            }
            filePath[i] = '/';
        }
    }
    if (len > 0 && access(filePath, 0) != 0) {
        mkdir(filePath, NEW_FILEPATH_MODE);
    }
    return RET_SUCCESS;
}

int RemoveSpaceCharacters(char *buf, size_t bufSize)
{
    if ((buf == nullptr) || (strlen(buf) == 0) || (bufSize == 0)) {
        DHCP_LOGE("RemoveSpaceCharacters() buf == nullptr or len == 0!");
        return DHCP_FALSE;
    }

    /* Handle rightmost spaces. */
    int nEnd = strlen(buf) - 1;
    while ((nEnd >= 0) && isspace(buf[nEnd])) {
        buf[nEnd--] = '\0';
    }

    /* Handle leftmost spaces. */
    int i = 0;
    while (isspace(buf[i])) {
        buf[i++] = '\0';
    }

    int j = 0;
    while (buf[i] != '\0') {
        buf[j++] = buf[i++];
    }
    buf[j] = '\0';

    return DHCP_TRUE;
}
