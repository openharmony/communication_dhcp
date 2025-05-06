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
#ifndef OHOS_DHCP_CLIENT_DEF_H
#define OHOS_DHCP_CLIENT_DEF_H

#include <stdbool.h>
#include <stdint.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <string>
#include "dhcp_define.h"
#define DHCP_GET_TIMEOUT        15
#define MAXRETRYTIMEOUT         10
#define USECOND_CONVERT         1000
#define MAX_READ_EVENT_SIZE     512
#define NUMBER_ONE              1
#define NUMBER_TWO              2
#define NUMBER_THREE            3
#define NUMBER_FOUR             4
#define NUMBER_FIVE             5
#define NUMBER_FIFTY_FOUR       54
#define FIRST_TIMEOUT_SEC       1
#define MAX_TIMEOUT_SEC         6
#define DOUBLE_TIME             2
#define RENEWAL_SEC_MULTIPLE    0.5
#define REBIND_SEC_MULTIPLE     0.875
#define TIME_INTERVAL_MAX       1
#define TIMEOUT_TIMES_MAX       15
#define MAX_WAIT_TIMES          5
#define TIMEOUT_WAIT_SEC        1
#define TIMEOUT_MORE_WAIT_SEC   60
#define LEASETIME_DEFAULT       1
#define DHCP_FAILE_TIMEOUT_THR  6
#define MAX_CONFLICTS_COUNT     2
#define RENEWAL_SEC_MULTIPLE_SPECIFIC_NETWORK 0.9
#define SELECT_TIMEOUT_US       100000

#define MAC_ADDR_LEN            6
#define MAC_ADDR_CHAR_NUM       3
#define ETHERNET_TYPE           0x01
#define ETHERNET_LEN            6
#define VENDOR_MAX_LEN          64
#define MAGIC_COOKIE            0x63825363
#define BROADCAST_FLAG          0x8000
inline constexpr char MAC_BCAST_ADDR[] = "\xff\xff\xff\xff\xff\xff";
#define SIGNED_INTEGER_MAX      0x7FFFFFFF
#define INFNAME_SIZE            16    /* Length of interface name */
#define RWMODE                  0600
#define MAX_MSG_SIZE            1500
#define STRING_MAX_LEN          1024
inline constexpr char  EVENT_GET_IPV4[] = "usual.event.wifi.dhcp.GET_IPV4";

/* UDP port numbers for BOOTP */
#define BOOTP_SERVER            67
#define BOOTP_CLIENT            68

/* BOOTP message type */
#define BOOT_REQUEST            1
#define BOOT_REPLY              2

/* DHCP packet type */
#define DHCP_DISCOVER           1
#define DHCP_OFFER              2
#define DHCP_REQUEST            3
#define DHCP_DECLINE            4
#define DHCP_ACK                5
#define DHCP_NAK                6
#define DHCP_RELEASE            7
#define DHCP_INFORM             8
#define DHCP_FORCERENEW         9

/* Sizes for DhcpPacket Fields */
#define DHCP_HWADDR_LENGTH          16
#define DHCP_HOST_NAME_LENGTH       64
#define DHCP_BOOT_FILE_LENGTH       128
#define DHCP_OPT_SIZE               1780
#define DHCP_OPT_CODE_INDEX         0
#define DHCP_OPT_LEN_INDEX          1
#define DHCP_OPT_DATA_INDEX         2
#define DHCP_OPT_CODE_BYTES         1
#define DHCP_OPT_LEN_BYTES          1
#define DHCP_UINT8_BYTES            1
#define DHCP_UINT16_BYTES           2
#define DHCP_UINT32_BYTES           4
#define DHCP_UINT32_DOUBLE_BYTES    8
#define DHCP_UINT16_BITS            16
#define DHCP_REQ_CODE_NUM           12
#define OPTION_FIELD                0
#define FILE_FIELD                  1
#define SNAME_FIELD                 2
#define DHCP_DNS_FIRST              1
#define DHCP_DNS_SECOND             2
#define DHCP_APPEND_LEN             2
#define WIFI_DHCP_CACHE_ADD 1
#define WIFI_DHCP_CACHE_REMOVE 2
#ifdef OHOS_EUPDATER
inline constexpr char  WORKDIR[] = "/tmp/service/el1/public/dhcp/";
#else
inline constexpr char  WORKDIR[] = "/data/service/el1/public/dhcp/";
#endif // OHOS_EUPDATER
       
inline constexpr char  DHCPC_NAME[] = "dhcp_client_service";
inline constexpr char  DHCPC_CONF[] = "dhcp_client_service.conf";
inline constexpr char  DHCPC_PID[] = "dhcp_client_service.pid";
inline constexpr char  DHCPC_VERSION[] = "1.0";
inline constexpr char  DHCPC_LEASE[] = "dhcp_client_service-%s.lease";
#ifdef OHOS_EUPDATER
inline constexpr char  DHCP_CACHE_FILE[] = "/tmp/service/el1/public/dhcp/dhcp_cache.conf";
#else
inline constexpr char  DHCP_CACHE_FILE[] = "/data/service/el1/public/dhcp/dhcp_cache.conf";
#endif // OHOS_EUPDATER
/* netmanager ipv6 */
constexpr int DHCP_IPV6_ENABLE = 1;
constexpr int DHCP_IPV6_DISENABLE = 0;

/* dhcp action mode */
enum ActionMode {
    ACTION_START_NEW = 0,
    ACTION_START_OLD,
    ACTION_RENEW_T1,
    ACTION_RENEW_T2,
    ACTION_RENEW_T3,
    ACTION_INVALID  
};

/* dhcp signal mode */
enum SigMode {
    SIG_START = 0,
    SIG_STOP,
    SIG_RENEW,
    SIG_INVALID  
};

/* dhcp state code */
enum EnumDhcpStateCode {
    DHCP_STATE_INIT = 0,
    DHCP_STATE_SELECTING,
    DHCP_STATE_REQUESTING,
    DHCP_STATE_BOUND,
    DHCP_STATE_RENEWING,
    DHCP_STATE_REBINDING,
    DHCP_STATE_INITREBOOT,
    DHCP_STATE_RELEASED,
    DHCP_STATE_RENEWED,
    DHCP_STATE_FAST_ARP,
    DHCP_STATE_SLOW_ARP,
    DHCP_STATE_DECLINE,
};

/* socket return code */
enum EnumSocketErrCode {
    SOCKET_OPT_SUCCESS = 0,
    SOCKET_OPT_FAILED = -1,
    SOCKET_OPT_ERROR = -2
};

/* socket mode */
enum EnumSocketMode {
    SOCKET_MODE_INVALID        = 0,
    SOCKET_MODE_RAW            = 1,
    SOCKET_MODE_KERNEL         = 2
};

enum DHCP_OPTION_DATA_TYPE {
    DHCP_OPTION_DATA_INVALID = 0,
    DHCP_OPTION_DATA_U8,
    DHCP_OPTION_DATA_U16,
    DHCP_OPTION_DATA_S16,
    DHCP_OPTION_DATA_U32,
    DHCP_OPTION_DATA_S32,
    DHCP_OPTION_DATA_IP,
    DHCP_OPTION_DATA_IP_PAIR,
    DHCP_OPTION_DATA_IP_LIST,
    DHCP_OPTION_DATA_IP_STRING
};


/* publish event code */
typedef enum EnumPublishEventCode {
    /* success */
    PUBLISH_CODE_SUCCESS = 0,
    /* failed */
    PUBLISH_CODE_FAILED = -1,
    /* timeout */
    PUBLISH_CODE_TIMEOUT = -2,
    /* lease expired */
    PUBLISH_CODE_EXPIRED = -3,
    /* dhcp offer report*/
    PUBLISH_DHCP_OFFER_REPORT = -4
} DhcpEventCode;

/* DhcpPacket Fields */
struct DhcpPacket {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[DHCP_HWADDR_LENGTH];
    uint8_t sname[DHCP_HOST_NAME_LENGTH];
    uint8_t file[DHCP_BOOT_FILE_LENGTH];
    int32_t cookie;
    uint8_t options[DHCP_OPT_SIZE];
};

struct UdpDhcpPacket {
    struct iphdr ip;
    struct udphdr udp;
    struct DhcpPacket data;
};

struct DhcpIpResult{
    int32_t code;                          /* get result code */
    std::string ifname;                     /* ifname */
    uint32_t uAddTime;                      /* addTime */
    uint32_t uOptLeasetime;                 /* dhcp option IP_ADDRESS_LEASE_TIME_OPTION */
    char strYiaddr[INET_ADDRSTRLEN];        /* your (client) IP */
    char strOptServerId[INET_ADDRSTRLEN];   /* dhcp option SERVER_IDENTIFIER_OPTION */
    char strOptSubnet[INET_ADDRSTRLEN];     /* dhcp option SUBNET_MASK_OPTION */
    char strOptDns1[INET_ADDRSTRLEN];       /* dhcp option DOMAIN_NAME_SERVER_OPTION */
    char strOptDns2[INET_ADDRSTRLEN];       /* dhcp option DOMAIN_NAME_SERVER_OPTION */
    char strOptRouter1[INET_ADDRSTRLEN];    /* dhcp option ROUTER_OPTION */
    char strOptRouter2[INET_ADDRSTRLEN];    /* dhcp option ROUTER_OPTION */
    char strOptVendor[DHCP_FILE_MAX_BYTES]; /* dhcp option VENDOR_SPECIFIC_INFO_OPTION */
    std::vector<std::string> dnsAddr;       /* dhcp option MULTI DOMAIN_NAME_SERVER_OPTION */
};

enum DHCP_IP_TYPE {
    DHCP_IP_TYPE_NONE =  0,
    DHCP_IP_TYPE_ALL  =  1,
    DHCP_IP_TYPE_V4   =  2,
    DHCP_IP_TYPE_V6   =  3
};

typedef struct{
    int  ifaceIndex;                        /* Index of the network interface used by the current process. */
    bool isIpv6;                            /* IPv6 address of the network interface used to get. */
    unsigned int ifaceIpv4;                 /* IPv4 of the network interface used by the current process. */
    unsigned int getMode;                   /* Current process obtaining IPv4 address mode. */
    unsigned char ifaceMac[MAC_ADDR_LEN];   /* Mac addr of the network interface used by the current process. */
    char ifaceName[INFNAME_SIZE];           /* Name of the network interface used by the current process. */
    char workDir[DIR_MAX_LEN];              /* Current process working directory. */
    char confFile[DIR_MAX_LEN];             /* Current process Configuration Directory. */
    char leaseFile[DIR_MAX_LEN];
    char resultFile[DIR_MAX_LEN];           /* Save the obtained IPv4 result. */
    char result6File[DIR_MAX_LEN];
}DhcpClientCfg;

struct IpInfoCached {
    std::string bssid;
    std::string ssid;
    int64_t absoluteLeasetime;
    struct DhcpIpResult ipResult;
};

/* timer type */
enum TimerType {
    TIMER_GET_IP = 0,
    TIMER_RENEW_DELAY,
    TIMER_REBIND_DELAY,
    TIMER_REMAINING_DELAY,
    TIMER_SLOW_ARP,
};
#endif