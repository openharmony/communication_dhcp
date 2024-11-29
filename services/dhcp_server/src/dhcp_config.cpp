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

#include "dhcp_config.h"
#include <cerrno>
#include <securec.h>
#include <cstdio>
#include <cstdlib>
#include <string.h>
#include <sys/time.h>
#include "address_utils.h"
#include "common_util.h"
#include "dhcp_define.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpServerConfig");

#define FILE_LINE_LEN_MAX       1024
#define FILE_LINE_DELIMITER     "="

static int SetEnableConfigInfo(DhcpConfig *dhcpConfig, const char *pKey, const char *pValue)
{
    if ((dhcpConfig == nullptr) || (pKey == nullptr) || (pValue == nullptr)) {
        DHCP_LOGE("SetEnableConfigInfo param dhcpConfig or pKey or pValue is nullptr!");
        return RET_FAILED;
    }

    uint32_t uValue = (uint32_t)atoi(pValue);
    if ((uValue != 0) && (uValue != 1)) {
        DHCP_LOGE("enable:%s error", pValue);
        return RET_FAILED;
    }

    if (strcmp(pKey, "distribution") == 0) {
        dhcpConfig->distribution = uValue;
    } else if (strcmp(pKey, "broadcast") == 0) {
        dhcpConfig->broadcast = uValue;
    }
    return RET_SUCCESS;
}

static int SetTimeConfigInfo(DhcpConfig *dhcpConfig, const char *pKey, const char *pValue)
{
    if ((dhcpConfig == nullptr) || (pKey == nullptr) || (pValue == nullptr)) {
        DHCP_LOGE("SetTimeConfigInfo param dhcpConfig or pKey or pValue is nullptr!");
        return RET_FAILED;
    }

    uint32_t uValue = 0;
    if ((uValue = (uint32_t)atoi(pValue)) == 0) {
        DHCP_LOGE("atoi failed, time:%s", pValue);
        return RET_FAILED;
    }

    if (strcmp(pKey, "leaseTime") == 0) {
        dhcpConfig->leaseTime = uValue;
    } else if (strcmp(pKey, "renewalTime") == 0) {
        dhcpConfig->renewalTime = uValue;
    } else if (strcmp(pKey, "rebindingTime") == 0) {
        dhcpConfig->rebindingTime = uValue;
    }
    return RET_SUCCESS;
}

static int SetNetConfigInfo(DhcpConfig *dhcpConfig, const char *pKey, const char *pValue, int common)
{
    if ((dhcpConfig == nullptr) || (pKey == nullptr) || (pValue == nullptr)) {
        DHCP_LOGE("SetNetConfigInfo param dhcpConfig or pKey or pValue is nullptr!");
        return RET_FAILED;
    }

    uint32_t uValue = 0;
    if ((uValue = ParseIpAddr(pValue)) == 0) {
        DHCP_LOGE("ParseIpAddr failed, ip:%s", pValue);
        return RET_FAILED;
    }

    if (((strcmp(pKey, "serverId") == 0) && common) || ((strcmp(pKey, "server") == 0) && !common)) {
        dhcpConfig->serverId = uValue;
    } else if (strcmp(pKey, "gateway") == 0) {
        dhcpConfig->gateway = uValue;
    } else if (strcmp(pKey, "netmask") == 0) {
        dhcpConfig->netmask = uValue;
    }
    return RET_SUCCESS;
}

static int SetIpAddressPool(DhcpConfig *dhcpConfig, const char *pValue)
{
    if ((dhcpConfig == nullptr) || (pValue == nullptr)) {
        DHCP_LOGE("SetIpAddressPool param dhcpConfig or pValue is nullptr!");
        return RET_FAILED;
    }

    char *pSrc = (char *)pValue;
    char *pSave = nullptr;
    char *pTok = strtok_r(pSrc, ",", &pSave);
    if (((pTok == nullptr) || (strlen(pTok) == 0)) || ((pSave == nullptr) || (strlen(pSave) == 0))) {
        DHCP_LOGE("strtok_r pTok or pSave nullptr or len is 0!");
        return RET_FAILED;
    }

    uint32_t begin;
    if ((begin = ParseIpAddr(pTok)) == 0) {
        DHCP_LOGE("ParseIpAddr begin:%s failed!", pTok);
        return RET_FAILED;
    }
    dhcpConfig->pool.beginAddress = begin;
    uint32_t end;
    if ((end = ParseIpAddr(pSave)) == 0) {
        DHCP_LOGE("ParseIpAddr end:%s failed!", pSave);
        return RET_FAILED;
    }
    dhcpConfig->pool.endAddress = end;
    return RET_SUCCESS;
}

static int SetDnsInfo(DhcpConfig *dhcpConfig, const char *pValue)
{
    if ((dhcpConfig == nullptr) || (pValue == nullptr)) {
        DHCP_LOGE("SetDnsInfo param dhcpConfig or pValue is nullptr!");
        return RET_FAILED;
    }

    char *pSrc = (char *)pValue;
    char *pSave = nullptr;
    char *pTok = strtok_r(pSrc, ",", &pSave);
    if ((pTok == nullptr) || (strlen(pTok) == 0)) {
        DHCP_LOGE("strtok_r pTok nullptr or len is 0!");
        return RET_FAILED;
    }

    DhcpOption optDns = {DOMAIN_NAME_SERVER_OPTION, 0, {0}};
    if (GetOption(&dhcpConfig->options, optDns.code) != nullptr) {
        RemoveOption(&dhcpConfig->options, optDns.code);
    }

    uint32_t dnsAddress;
    while (pTok != nullptr) {
        if ((dnsAddress = ParseIpAddr(pTok)) == 0) {
            DHCP_LOGE("ParseIpAddr %s failed, code:%d", pTok, optDns.code);
            return RET_FAILED;
        }
        if (AppendAddressOption(&optDns, dnsAddress) != RET_SUCCESS) {
            DHCP_LOGW("failed append dns option.");
        }
        pTok = strtok_r(nullptr, ",", &pSave);
    }
    PushBackOption(&dhcpConfig->options, &optDns);
    return RET_SUCCESS;
}

static int SetIfnameInfo(DhcpConfig *dhcpConfig, const char *pValue)
{
    if ((dhcpConfig == nullptr) || (pValue == nullptr)) {
        DHCP_LOGE("SetIfnameInfo dhcpConfig or pValue is nullptr!");
        return RET_FAILED;
    }
    if (strlen(pValue) >= IFACE_NAME_SIZE) {
        DHCP_LOGE("ifname:%s too long!", pValue);
        return RET_FAILED;
    }
    if (memset_s(dhcpConfig->ifname, IFACE_NAME_SIZE, '\0', IFACE_NAME_SIZE) != EOK ||
        strncpy_s(dhcpConfig->ifname, IFACE_NAME_SIZE, pValue, strlen(pValue)) != EOK) {
        return RET_FAILED;
    }
    return RET_SUCCESS;
}

static int SetDhcpConfig(DhcpConfig *dhcpConfig, const char *strLine, int common)
{
    if ((strLine == nullptr) || (strlen(strLine) == 0)) {
        DHCP_LOGE("SetDhcpConfig param strLine is nullptr or len = 0!");
        return RET_FAILED;
    }

    char *pSrc = (char *)strLine;
    char *pSave = nullptr;
    char *pTok = strtok_r(pSrc, FILE_LINE_DELIMITER, &pSave);
    if (pTok == nullptr) {
        DHCP_LOGE("strtok_r pTok nullptr!");
        return RET_FAILED;
    }
    if (strcmp(pTok, "interface") == 0) {
        return SetIfnameInfo(dhcpConfig, pSave);
    } else if (strcmp(pTok, "dns") == 0) {
        return SetDnsInfo(dhcpConfig, pSave);
    } else if (strcmp(pTok, "pool") == 0) {
        return SetIpAddressPool(dhcpConfig, pSave);
    } else if ((((strcmp(pTok, "serverId") == 0) && common) || ((strcmp(pTok, "server") == 0) && !common)) ||
        (strcmp(pTok, "gateway") == 0) || (strcmp(pTok, "netmask") == 0)) {
        return SetNetConfigInfo(dhcpConfig, pTok, pSave, common);
    } else if ((strcmp(pTok, "leaseTime") == 0) || (strcmp(pTok, "renewalTime") == 0) ||
               (strcmp(pTok, "rebindingTime") == 0)) {
        return SetTimeConfigInfo(dhcpConfig, pTok, pSave);
    } else if ((strcmp(pTok, "distribution") == 0) || (strcmp(pTok, "broadcast") == 0)) {
        return SetEnableConfigInfo(dhcpConfig, pTok, pSave);
    } else {
        DHCP_LOGD("invalid key:%s", pTok);
        return RET_SUCCESS;
    }
}

static int ParseConfigFile(const char *configFile, const char *ifname, DhcpConfig *dhcpConfig)
{
    if ((configFile == nullptr) || (strlen(configFile) == 0) || (dhcpConfig == nullptr)) {
        DHCP_LOGE("ParseConfigFile param configFile or dhcpConfig is nullptr or len = 0!");
        return RET_FAILED;
    }

    FILE *fp = fopen(configFile, "r");
    if (fp == nullptr) {
        DHCP_LOGE("fopen %{public}s failed, err:%{public}d", configFile, errno);
        return RET_FAILED;
    }

    int bComm = 1;
    int bValid = 1;
    char strLine[FILE_LINE_LEN_MAX] = {0};
    while (fgets(strLine, FILE_LINE_LEN_MAX, fp) != nullptr) {
        DHCP_LOGI("fgets strLine = %{public}s", strLine);
        if ((strchr(strLine, '#') != nullptr) || (strchr(strLine, '=') == nullptr) ||
            !RemoveSpaceCharacters(strLine, FILE_LINE_LEN_MAX)) {
            if (memset_s(strLine, FILE_LINE_LEN_MAX, 0, FILE_LINE_LEN_MAX) != EOK) {
                break;
            }
            continue;
        }
        if (memcmp(strLine, "interface", strlen("interface")) == 0) {
            bComm = 0;
            bValid = 0;
            if ((ifname == nullptr) || (strlen(ifname) == 0) || (strstr(strLine, ifname) != nullptr)) {
                DHCP_LOGI("%s %s find ifname:%s", configFile, strLine, ((ifname == nullptr) ? "" : ifname));
                bValid = 1;
            } else {
                DHCP_LOGI("%s %s no find ifname:%s", configFile, strLine, ifname);
            }
        }
        if (bValid && SetDhcpConfig(dhcpConfig, strLine, bComm) != RET_SUCCESS) {
            DHCP_LOGE("set dhcp config %s %s failed", configFile, strLine);
            (void)fclose(fp);
            return RET_FAILED;
        }
        if (memset_s(strLine, FILE_LINE_LEN_MAX, 0, FILE_LINE_LEN_MAX) != EOK) {
            break;
        }
    }
    if (fclose(fp) != 0) {
        DHCP_LOGE("ParseConfigFile fclose fp failed!");
    }
    return RET_SUCCESS;
}

static int CheckDhcpConfig(DhcpConfig *config)
{
    if (config == nullptr) {
        DHCP_LOGE("CheckDhcpConfig param config is null");
        return DHCP_FALSE;
    }
    if ((strlen(config->ifname) > 0) && ((config->serverId == 0))) {
        DHCP_LOGE("failed to config serverId or netmask");
        return DHCP_FALSE;
    }

    if (config->renewalTime == 0) {
        config->renewalTime = config->leaseTime * DHCP_RENEWAL_MULTIPLE;
    }
    if (config->rebindingTime == 0) {
        config->rebindingTime = config->leaseTime * DHCP_REBIND_MULTIPLE;
    }
    return DHCP_TRUE;
}

int LoadConfig(const char *configFile, const char *ifname, DhcpConfig *config)
{
    if ((configFile == nullptr) || (strlen(configFile) == 0) || (ifname == nullptr) || (strlen(ifname) == 0) ||
        (config == nullptr)) {
        DHCP_LOGE("LoadConfig param configFile or ifname or config is nullptr or len = 0!");
        return RET_FAILED;
    }

    /* Default config. */
    config->leaseTime = DHCP_LEASE_TIME;
    config->distribution = 1;
    config->broadcast = 1;

    /* Set file config. */
    if (ParseConfigFile(configFile, ifname, config) != RET_SUCCESS) {
        DHCP_LOGE("parse config file %{public}s error!", configFile);
        return RET_FAILED;
    }
    DHCP_LOGI("parse config file %{public}s success", configFile);

    if (!CheckDhcpConfig(config)) {
        DHCP_LOGE("check dhcp config failed");
        return RET_FAILED;
    }

    if ((strlen(config->ifname) == 0) && SetIfnameInfo(config, ifname) != RET_SUCCESS) {
        DHCP_LOGE("set ifname %s error!", ifname);
        return RET_FAILED;
    }
    return RET_SUCCESS;
}
