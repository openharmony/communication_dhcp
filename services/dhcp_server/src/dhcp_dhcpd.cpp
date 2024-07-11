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

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "dhcp_dhcpd.h"
#include "securec.h"
#include "address_utils.h"
#include "dhcp_address_pool.h"
#include "dhcp_argument.h"
#include "dhcp_config.h"
#include "dhcp_s_define.h"
#include "dhcp_server_ipv4.h"
#include "dhcp_logger.h"
#include "dhcp_option.h"
#include "dhcp_s_server.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpServerMain");

#define DEFAUTL_NET_MASK "255.255.255.0"

static DhcpConfig g_dhcpConfig;

static PDhcpServerContext g_dhcpServer = 0;

static LeasesChangeFunc leasesChangeFunc;
enum SignalEvent {
    EXIT = 0,
    RELOAD,
    RESTART,
};

void LoadLocalConfig(DhcpAddressPool *pool)
{
    DHCP_LOGD("loading local configure ...");
}

void ReloadLocalConfig(DhcpAddressPool *pool)
{
    DHCP_LOGD("reloading local configure ...");
}

static int InitNetworkAbout(DhcpConfig *config)
{
    ArgumentInfo *arg = GetArgument("netmask");
    if (arg) {
        DHCP_LOGI("subnet mask:%s", arg->value);
        uint32_t argNetmask = ParseIpAddr(arg->value);
        if (argNetmask) {
            config->netmask = argNetmask;
        } else {
            DHCP_LOGW("error netmask argument.");
            return RET_FAILED;
        }
    } else {
        if (!config->netmask) {
            config->netmask = ParseIpAddr(DEFAUTL_NET_MASK);
        }
    }
    arg = GetArgument("gateway");
    if (arg) {
        DHCP_LOGI("gateway:%s", arg->value);
        uint32_t argGateway = ParseIpAddr(arg->value);
        if (argGateway) {
            config->gateway = argGateway;
        } else {
            DHCP_LOGE("error gateway argument.");
            return RET_FAILED;
        }
    } else {
        config->gateway = config->serverId;
        DHCP_LOGW("InitNetworkAbout, set gateway to serverId as default.");
    }
    return RET_SUCCESS;
}

static int PareseAddreesRange(DhcpConfig *config)
{
    ArgumentInfo *arg = GetArgument("pool");
    if (arg) {
        DHCP_LOGD("pool info:%s", arg->value);
        int index = 0;
        char *src = arg->value;
        constexpr const char *delim = ",";
        char *pSave = nullptr;
        char *poolPartArg;
        poolPartArg = strtok_r(src, delim, &pSave);
        while (poolPartArg) {
            if (index == 0) {
                config->pool.beginAddress = ParseIpAddr(poolPartArg);
                DHCP_LOGD("address range begin of: %s", poolPartArg);
            } else if (index == 1) {
                config->pool.endAddress = ParseIpAddr(poolPartArg);
                DHCP_LOGD("address range end of: %s", poolPartArg);
            }
            index++;
            poolPartArg = strtok_r(nullptr, delim, &pSave);
        }
        if (!config->pool.beginAddress || !config->pool.endAddress) {
            DHCP_LOGE("'pool' argument format error.");
            return RET_FAILED;
        }
        return RET_SUCCESS;
    }
    DHCP_LOGW("failed to get 'pool' argument.");
    return RET_FAILED;
}

static int InitAddressRange(DhcpConfig *config)
{
    if (HasArgument("pool")) {
        if (PareseAddreesRange(config) != RET_SUCCESS) {
            DHCP_LOGW("dhcp range config error.");
            return RET_FAILED;
        }
    } else {
        if (!config->pool.beginAddress || !config->pool.endAddress) {
            config->pool.beginAddress = FirstIpAddress(config->serverId, config->netmask);
            config->pool.endAddress = LastIpAddress(config->serverId, config->netmask);
        }
    }
    return RET_SUCCESS;
}

static int InitDomainNameServer(DhcpConfig *config)
{
    DhcpOption argOpt = {DOMAIN_NAME_SERVER_OPTION, 0, {0}};
    ArgumentInfo *arg = GetArgument("dns");
    uint32_t dnsAddress = 0;
    if (arg) {
        char *pSave = nullptr;
        char *pTok = strtok_r(arg->value, ",", &pSave);
        if ((pTok == nullptr) || (strlen(pTok) == 0)) {
            DHCP_LOGE("strtok_r pTok nullptr or len is 0!");
            return RET_FAILED;
        }
        while (pTok != nullptr) {
            if ((dnsAddress = ParseIpAddr(pTok)) == 0) {
                DHCP_LOGE("ParseIpAddr %s failed, code:%d", pTok, argOpt.code);
                return RET_FAILED;
            }
            if (AppendAddressOption(&argOpt, dnsAddress) != RET_SUCCESS) {
                DHCP_LOGW("failed to append dns option.");
            }
            pTok = strtok_r(nullptr, ",", &pSave);
        }
    } else {
        DHCP_LOGW("%{public}s, set dns to serverId as default.", __func__);
        dnsAddress = config->serverId;
        if (AppendAddressOption(&argOpt, dnsAddress) != RET_SUCCESS) {
            DHCP_LOGW("failed to append dns option.");
        }
    }

    if (GetOption(&config->options, argOpt.code) != nullptr) {
        RemoveOption(&config->options, DOMAIN_NAME_SERVER_OPTION);
    }
    PushBackOption(&config->options, &argOpt);
    return RET_SUCCESS;
}

static int InitServerId(DhcpConfig *config)
{
    ArgumentInfo *arg = GetArgument("server");
    if (arg) {
        DHCP_LOGI("server id:%s", arg->value);
        uint32_t argServerId = ParseIpAddr(arg->value);
        if (argServerId) {
            config->serverId = argServerId;
        } else {
            DHCP_LOGE("error server argument.");
            return RET_FAILED;
        }
    } else {
        if (!config->serverId) {
            DHCP_LOGE("failed to get 'server' argument or config item.");
            return RET_FAILED;
        }
    }
    return RET_SUCCESS;
}

static int InitLeaseTime(DhcpConfig *config)
{
    ArgumentInfo *arg = GetArgument("lease");
    if (arg) {
        config->leaseTime = static_cast<uint32_t>(atoi(arg->value));
    } else {
        if (!config->leaseTime) {
            config->leaseTime = DHCP_LEASE_TIME;
        }
    }
    return RET_SUCCESS;
}

static int InitRenewalTime(DhcpConfig *config)
{
    ArgumentInfo *arg = GetArgument("renewal");
    if (arg) {
        config->renewalTime = static_cast<uint32_t>(atoi(arg->value));
    } else {
        if (!config->rebindingTime) {
            config->rebindingTime = DHCP_RENEWAL_TIME;
        }
        config->renewalTime = DHCP_RENEWAL_TIME;
    }
    return RET_SUCCESS;
}

static int InitRebindingTime(DhcpConfig *config)
{
    ArgumentInfo *arg = GetArgument("rebinding");
    if (arg) {
        config->rebindingTime = static_cast<uint32_t>(atoi(arg->value));
    } else {
        if (!config->rebindingTime) {
            config->rebindingTime =  DHCP_REBINDING_TIME;
        }
    }
    return RET_SUCCESS;
}
static int InitConfigByArguments(DhcpConfig *config)
{
    if (!config) {
        DHCP_LOGE("dhcp configure pointer is null.");
        return RET_FAILED;
    }
    if (InitServerId(config) != RET_SUCCESS) {
        return RET_FAILED;
    }
    if (InitNetworkAbout(config) != RET_SUCCESS) {
        return RET_FAILED;
    }
    if (InitAddressRange(config) != RET_SUCCESS) {
        return RET_FAILED;
    }
    if (InitLeaseTime(config) != RET_SUCCESS) {
        return RET_FAILED;
    }
    if (InitRenewalTime(config) != RET_SUCCESS) {
        return RET_FAILED;
    }
    if (InitRebindingTime(config) != RET_SUCCESS) {
        return RET_FAILED;
    }
    if (InitDomainNameServer(config) != RET_SUCCESS) {
        return RET_FAILED;
    }
    return RET_SUCCESS;
}

int ServerActionCallback(int state, int code, const char *ifname)
{
    int ret = 0;
    switch (state) {
        case ST_STARTING: {
            if (code == 0) {
                DHCP_LOGD(" callback[%s] ==> server starting ...", ifname);
            } else if (code == 1) {
                DHCP_LOGD(" callback[%s] ==> server started.", ifname);
            } else if (code == NUM_TWO) {
                DHCP_LOGD(" callback[%s] ==> server start failed.", ifname);
            }
            break;
        }
        case ST_RELOADNG: {
            DHCP_LOGD(" callback[%s] ==> reloading ...", ifname);
            break;
        }
        case ST_STOPED: {
            DHCP_LOGD(" callback[%s] ==> server stopped.", ifname);
            break;
        }
        default:
            break;
    }
    return ret;
}

static int InitializeDhcpConfig(const char *ifname, DhcpConfig *config)
{
    if (!config) {
        DHCP_LOGE("dhcp configure pointer is null.");
        return RET_FAILED;
    }
    if (InitOptionList(&config->options) != RET_SUCCESS) {
        DHCP_LOGE("failed to initialize options.");
        return RET_FAILED;
    }
    char configFile[ARGUMENT_VALUE_SIZE] = DHCPD_CONFIG_FILE;
    if (HasArgument("conf")) {
        ArgumentInfo *configArg = GetArgument("conf");
        if (configArg) {
            if (memcpy_s(configFile, ARGUMENT_VALUE_SIZE, configArg->value, strlen(configArg->value)) != EOK) {
                DHCP_LOGE("conf memcpy_s failed.");
                return RET_FAILED;
            }
        } else {
            DHCP_LOGE("failed to get config file name.");
            return RET_FAILED;
        }
    }
    DHCP_LOGI("load local dhcp config file:%{public}s", configFile);
    if (LoadConfig(configFile, ifname, config) != RET_SUCCESS) {
        DHCP_LOGE("failed to load configure file.");
        return RET_FAILED;
    }
    DHCP_LOGI("init config by argument.");
    if (InitConfigByArguments(config) != RET_SUCCESS) {
        DHCP_LOGE("failed to parse arguments.");
        return RET_FAILED;
    }

    return RET_SUCCESS;
}

static void FreeLocalConfig(void)
{
    FreeOptionList(&g_dhcpConfig.options);
}

void FreeSeverResources(void)
{
    DHCP_LOGI("FreeSeverResources enter");
    FreeArguments();
    FreeLocalConfig();
    if (FreeServerContext(&g_dhcpServer) != RET_SUCCESS) {
        DHCP_LOGE("Free server context failed!");
        return;
    }
}

int StartDhcpServerMain(const std::string& ifName, const std::string& netMask, const std::string& ipRange,
    const std::string& localIp)
{
    DHCP_LOGI("StartDhcpServerMain.");

    if (InitArguments() != RET_SUCCESS) {
        DHCP_LOGE("failed to init arguments table.");
        return 1;
    }
    int ret = ParseArguments(ifName, netMask, ipRange, localIp);
    if (ret != RET_SUCCESS) {DHCP_LOGE("error ParseArguments.");
        FreeArguments();
        return 1;
    }
    ArgumentInfo *ifaceName = GetArgument("ifname");
    if (!ifaceName || strlen(ifaceName->value) == 0) {
        printf("missing required parameters:\"ifname\"\n");
        FreeArguments();
        return 1;
    }
    if (InitializeDhcpConfig(ifaceName->value, &g_dhcpConfig) != RET_SUCCESS) {
        DHCP_LOGW("failed to initialize config.");
    }
    if (strcpy_s(g_dhcpConfig.ifname, IFACE_NAME_SIZE, ifaceName->value) != EOK) {
        DHCP_LOGE("cpy ifname failed!");
        return 1;
    }
    g_dhcpServer = InitializeServer(&g_dhcpConfig);
    if (g_dhcpServer == nullptr) {
        DHCP_LOGE("failed to initialize dhcp server.");
        FreeSeverResources();
        return 1;
    }

    RegisterDhcpCallback(g_dhcpServer, ServerActionCallback);
    RegisterLeasesChangedCallback(g_dhcpServer, leasesChangeFunc);
    if (StartDhcpServer(g_dhcpServer) != RET_SUCCESS) {
        FreeSeverResources();
        return 1;
    }
    return 0;
}

int StopDhcpServerMain()
{
    DHCP_LOGI("StopDhcpServerMain.");
    if (StopDhcpServer(g_dhcpServer) != RET_SUCCESS) {
        FreeSeverResources();
        return 1;
    }
    FreeSeverResources();
    return 0;
}

int RegisterLeaseInfoCbks(DhcpLeasesChangeFunc func)
{
    leasesChangeFunc = func;
    return 0;
}