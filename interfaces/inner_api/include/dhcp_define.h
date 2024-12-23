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

#ifndef OHOS_DHCP_DEFINE_H
#define OHOS_DHCP_DEFINE_H

#include <string>
#include <cstdint>
#include <netinet/ip.h>
#include <sys/stat.h>

namespace OHOS {
namespace DHCP {
const int ETH_MAC_ADDR_INDEX_0  = 0;
const int ETH_MAC_ADDR_INDEX_1  = 1;
const int ETH_MAC_ADDR_INDEX_2  = 2;
const int ETH_MAC_ADDR_INDEX_3  = 3;
const int ETH_MAC_ADDR_INDEX_4  = 4;
const int ETH_MAC_ADDR_INDEX_5  = 5;
const int ETH_MAC_ADDR_LEN      = 6;
const int ETH_MAC_ADDR_CHAR_NUM = 3;
const int IP_SIZE               = 18;
const int LEASETIME_DEFAULT     = 6;
const int ONE_HOURS_SEC         = 3600;
const int RECEIVER_TIMEOUT      = 6;
const int EVENT_DATA_NUM        = 11;
const int IPV6_EVENT_DATA_NUM   = 9;
const int DHCP_NUM_ZERO         = 0;
const int DHCP_NUM_ONE          = 1;
const int DHCP_NUM_TWO          = 2;
const int DHCP_NUM_THREE        = 3;
const int DHCP_NUM_FOUR         = 4;
const int DHCP_NUM_FIVE         = 5;
const int DHCP_NUM_SIX          = 6;
const int DHCP_NUM_SEVEN        = 7;
const int DHCP_NUM_EIGHT        = 8;
const int DHCP_NUM_NINE         = 9;
const int DHCP_NUM_TEN          = 10;
const int DHCP_FILE_MAX_BYTES   = 128;
const int FILE_LINE_MAX_SIZE    = 1024;
const int DHCP_SER_ARGSNUM      = 6;
const int DHCP_CLI_ARGSNUM      = 5;
const int SLEEP_TIME_200_MS     = 200 * 1000;
const int SLEEP_TIME_500_MS     = 500 * 1000;
const int PID_MAX_LEN           = 16;
const int PARAM_MAX_SIZE        = 40;
const int DEFAULT_UMASK         = 027;
const int DIR_MAX_LEN           = 256;
const int DIR_DEFAULT_MODE      = S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH;
const int DHCP_IPV4_GETTED  = 1;
const int DHCP_IPV6_GETTED  = 2;
const int DHCP_IPALL_GETED  = DHCP_IPV4_GETTED | DHCP_IPV6_GETTED;
const std::string IP4_SEPARATOR(".");
const std::string IP6_SEPARATOR(":");
const std::string INVALID_STRING("*");
const std::string EVENT_DATA_DELIMITER(",");
const std::string EVENT_DATA_IPV4("ipv4");
const std::string EVENT_DATA_IPV6("ipv6");

#define DHCP_CLIENT_ABILITY_ID  1126
#define DHCP_SERVER_ABILITY_ID  1127

#ifdef OHOS_EUPDATER
const std::string DHCP_WORK_DIR("/tmp/service/el1/public/dhcp/");
#else
const std::string DHCP_WORK_DIR("/data/service/el1/public/dhcp/");
#endif // OHOS_EUPDATER

const std::string DHCP_CLIENT_PID_FILETYPE(".pid");
const std::string DHCP_RESULT_FILETYPE(".result");
#ifdef OHOS_ARCH_LITE
const std::string DHCP_CLIENT_FILE("/bin/dhcp_client_service");
const std::string DHCP_SERVER_FILE("/bin/dhcp_server");
#else
const std::string DHCP_CLIENT_FILE("/system/bin/dhcp_client_service");
const std::string DHCP_SERVER_FILE("/system/bin/dhcp_server");
#endif
const std::string DHCP_SERVER_CONFIG_FILE(DHCP_WORK_DIR + "etc/dhcpd.conf");
const std::string DHCP_SERVER_CONFIG_DIR(DHCP_WORK_DIR + "etc/");
const std::string DHCP_SERVER_LEASES_FILE(DHCP_WORK_DIR + "dhcpd_lease.lease");
const std::string DHCP_SERVER_CFG_IPV4("#ipv4");
const std::string DHCP_SERVER_CFG_IPV6("#ipv6");
const std::string COMMON_EVENT_DHCP_GET_IPV4 = "usual.event.wifi.dhcp.GET_IPV4";
const std::string IP_V4_MASK("255.255.255.0");
const std::string IP_V4_DEFAULT("192.168.62.1");

typedef enum EnumErrCode {
    /* success */
    DHCP_OPT_SUCCESS = 0,
    /* failed */
    DHCP_OPT_FAILED,
    /* null pointer */
    DHCP_OPT_NULL,
    /* get ip timeout */
    DHCP_OPT_TIMEOUT,
    /* renew failed */
    DHCP_OPT_RENEW_FAILED,
    /* renew timeout */
    DHCP_OPT_RENEW_TIMEOUT,
    /* lease expired */
    DHCP_OPT_LEASE_EXPIRED,
    /* dhcp offer */
    DHCP_OPT_OFFER_REPORT,
    /* error */
    DHCP_OPT_ERROR,
} DhcpErrCode;

enum DhcpServerState {
    DHCP_SERVER_OFF = 0,
    DHCP_SERVER_ON,
};

typedef enum EnumServiceStatus {
    SERVICE_STATUS_INVALID  = 0,
    SERVICE_STATUS_START    = 1,
    SERVICE_STATUS_STOP     = 2
} DhcpServiceStatus;

struct DhcpResult {
    bool isOptSuc;          /* get result */
    int iptype;             /* 0-ipv4,1-ipv6 */
    std::string strYourCli; /* your (client) IP */
    std::string strServer;  /* dhcp server IP */
    std::string strSubnet;  /* your (client) subnet mask */
    std::string strDns1;    /* your (client) DNS server1 */
    std::string strDns2;    /* your (client) DNS server2 */
    std::string strRouter1; /* your (client) router1 */
    std::string strRouter2; /* your (client) router2 */
    std::string strVendor;  /* your (client) vendor */
    std::string strLinkIpv6Addr;  /* your (client) link ipv6 addr */
    std::string strRandIpv6Addr;  /* your (client) rand ipv6 addr */
    std::string strLocalAddr1;  /* your (client) unique local ipv6 addr */
    std::string strLocalAddr2;  /* your (client) unique local ipv6 addr */
    uint32_t uLeaseTime;    /* your (client) IP lease time (s) */
    uint32_t uAddTime;      /* dhcp result add time */
    uint32_t uGetTime;      /* dhcp result get time */
    std::vector<std::string> vectorDnsAddr; /* your (client) multi dns server */

    DhcpResult()
    {
        iptype      = -1;
        isOptSuc    = false;
        strYourCli  = "";
        strServer   = "";
        strSubnet   = "";
        strDns1     = "";
        strDns2     = "";
        strRouter1  = "";
        strRouter2  = "";
        strVendor   = "";
        strLinkIpv6Addr = "";
        strRandIpv6Addr = "";
        strLocalAddr1   = "";
        strLocalAddr2   = "";
        uLeaseTime  = 0;
        uAddTime    = 0;
        uGetTime    = 0;
        vectorDnsAddr.clear();
    }
};

struct DhcpPacketResult {
    char strYiaddr[INET_ADDRSTRLEN];        /* your (client) IP */
    char strOptServerId[INET_ADDRSTRLEN];   /* dhcp option DHO_SERVERID */
    char strOptSubnet[INET_ADDRSTRLEN];     /* dhcp option DHO_SUBNETMASK */
    char strOptDns1[INET_ADDRSTRLEN];       /* dhcp option DHO_DNSSERVER */
    char strOptDns2[INET_ADDRSTRLEN];       /* dhcp option DHO_DNSSERVER */
    char strOptRouter1[INET_ADDRSTRLEN];    /* dhcp option DHO_ROUTER */
    char strOptRouter2[INET_ADDRSTRLEN];    /* dhcp option DHO_ROUTER */
    char strOptVendor[DHCP_FILE_MAX_BYTES]; /* dhcp option DHO_VENDOR */
    uint32_t uOptLeasetime;                 /* dhcp option DHO_LEASETIME */
    uint32_t uAddTime;                      /* dhcp result add time */
};

struct DhcpServiceInfo {
    bool enableIPv6;        /* true:ipv4 and ipv6,false:ipv4 */
    int clientRunStatus;    /* dhcp client service status */
    pid_t clientProPid;     /* dhcp client process pid */
    std::string serverIp;   /* dhcp server IP */

    DhcpServiceInfo()
    {
        enableIPv6 = true;
        clientRunStatus = -1;
        clientProPid = 0;
        serverIp = "";
    }
};

struct DhcpServerInfo {
    pid_t proPid;           /* dhcp server process id */
    bool normalExit;        /* dhcp server process normal exit */
    bool exitSig;           /* dhcp server process exit signal */

    DhcpServerInfo()
    {
        proPid = 0;
        normalExit = false;
        exitSig = false;
    }
};

struct DhcpRange {
    int iptype;             /* 0-ipv4,1-ipv6 */
    int leaseHours;         /* lease hours */
    std::string strTagName; /* dhcp-range tag name */
    std::string strStartip; /* dhcp-range start ip */
    std::string strEndip;   /* dhcp-range end ip */
    std::string strSubnet;  /* dhcp-range subnet */

    DhcpRange()
    {
        iptype = -1;
        leaseHours = LEASETIME_DEFAULT;
        strTagName = "";
        strStartip = "";
        strEndip = "";
        strSubnet = "";
    }
};

struct RouterConfig {
    std::string ifname;
    std::string bssid;
    bool prohibitUseCacheIp;
    bool bIpv6;
    bool bSpecificNetwork;

    RouterConfig()
    {
        prohibitUseCacheIp = false;
        bIpv6 = true;
        bSpecificNetwork = false;
    }
};
}  // namespace DHCP
}  // namespace OHOS
#endif /* OHOS_DHCP_DEFINE_H */
