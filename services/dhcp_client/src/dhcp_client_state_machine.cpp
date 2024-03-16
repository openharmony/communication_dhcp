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
#include "dhcp_client_state_machine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <string>

#include "securec.h"
#include "dhcp_result.h"
#include "dhcp_options.h"
#include "dhcp_socket.h"
#include "dhcp_function.h" 
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpIpv4");

namespace OHOS {
namespace DHCP {
DhcpClientStateMachine::DhcpClientStateMachine(std::string ifname) :
    m_dhcp4State(DHCP_STATE_INIT),
    m_sockFd(-1),
    m_resendTimer(0),
    m_sentPacketNum(0),
    m_timeoutTimestamp(0),
    m_renewalTimestamp(0),
    m_leaseTime(0),
    m_renewalSec(0),
    m_rebindSec(0),
    m_requestedIp4(0),
    m_serverIp4(0),
    m_socketMode(SOCKET_MODE_INVALID),
    m_transID(0),
    m_ifName(ifname),
    m_renewThreadIsRun(false),
    m_pthread(nullptr)
{
#ifndef OHOS_ARCH_LITE
    getIpTimerId = 0;
#endif
    m_cltCnf.ifaceIndex = 0;
    m_cltCnf.timeoutExit = false;
    m_cltCnf.ifaceIpv4 = 0;
    m_cltCnf.getMode = DHCP_IP_TYPE_NONE;
    m_cltCnf.pOptClientId = NULL;
    DHCP_LOGI("DhcpClientStateMachine()");

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, m_sigSockFds) != 0) {
        DHCP_LOGE("DhcpClientStateMachine() socketpair m_sigSockFds failed, error:%{public}d", errno);
    }
}

DhcpClientStateMachine::~DhcpClientStateMachine()
{
    DHCP_LOGI("~DhcpClientStateMachine()");
    if (m_pthread != nullptr) {
        m_pthread->join();
        delete m_pthread;
        m_pthread = nullptr;
        DHCP_LOGI("~DhcpClientStateMachine() delete m_pthread!");
    }
}

void DhcpClientStateMachine::RunGetIPThreadFunc()
{
    DHCP_LOGI("RunGetIPThreadFunc begin.");
    if ((m_cltCnf.getMode == DHCP_IP_TYPE_ALL) || (m_cltCnf.getMode == DHCP_IP_TYPE_V4)) {
        StartIpv4();  // Handle dhcp v4.
    }
    return;
}

int DhcpClientStateMachine::InitConfig(const std::string &ifname, bool isIpv6)
{
    if (InitSpecifiedClientCfg(ifname, isIpv6) != DHCP_OPT_SUCCESS) {
        DHCP_LOGE("InitConfig InitSpecifiedClientCfg failed!");
        return DHCP_OPT_FAILED;
    }
    if (GetClientNetworkInfo() != DHCP_OPT_SUCCESS) {
        DHCP_LOGE("InitConfig GetClientNetworkInfo failed!");
        return DHCP_OPT_FAILED;
    }
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::StartIpv4Type(const std::string &ifname, bool isIpv6, ActionMode action)
{
    DHCP_LOGI("StartIpv4 ifname:%{public}s isIpv6:%{public}d isExit:%{public}d threadRun:%{public}d action:%{public}d",
        ifname.c_str(), isIpv6, m_cltCnf.timeoutExit, m_renewThreadIsRun, action);
    m_ifName = ifname;
    m_action = action;
    if (InitConfig(ifname, isIpv6) != DHCP_OPT_SUCCESS) {
        return DHCP_OPT_FAILED;
    }
#ifndef OHOS_ARCH_LITE
    StartGetIpTimer(); // statr get ip timer
#endif
    if(m_action == ACTION_START_NEW && !m_cltCnf.timeoutExit) {  // first, thread is exit
        DHCP_LOGI("StartIpv4 start new InitStartIpv4Thread");
        InitStartIpv4Thread(ifname, isIpv6);
    } else if(m_action == ACTION_START_OLD) {
        if (!m_cltCnf.timeoutExit && m_renewThreadIsRun) {  // thread is running
            int signum = SIG_START;
            m_renewThreadIsRun = false;
            if (send(m_sigSockFds[1], &signum, sizeof(signum), MSG_DONTWAIT) < 0) {  // SIG_START SignalReceiver
                DHCP_LOGE("StartIpv4 start old sig send failed.");
                return DHCP_OPT_FAILED;
            }
            while (!m_renewThreadIsRun) {
                usleep(50000); // 50ms, waiting for socket select run SignalReceiver 
                DHCP_LOGI("StartIpv4 waiting for socket select run, usleep 500ms"); 
            }
            DHCP_LOGI("StartIpv4 start old active Ipv4Thread, signum:%{public}d", signum);
        } else {  // thread not exit
            DHCP_LOGI("StartIpv4 start old InitStartIpv4Thread");
            InitStartIpv4Thread(ifname, isIpv6);
        }
    } else { // renew  m_action == ACTION_RENEW
        if (m_cltCnf.timeoutExit) { // thread not exit
            DHCP_LOGI("StartIpv4 renew InitStartIpv4Thread");
            m_renewThreadIsRun = false;
            InitStartIpv4Thread(ifname, isIpv6);
        }
        int signum = SIG_RENEW;
        if (send(m_sigSockFds[1], &signum, sizeof(signum), MSG_DONTWAIT) < 0) { // SIG_RENEW SignalReceiver
            DHCP_LOGE("StartIpv4 renew sig send failed.");
            return DHCP_OPT_FAILED;
        }
        while (!m_renewThreadIsRun) {
            usleep(50000); // 50ms, waiting for socket select running...
            DHCP_LOGI("StartIpv4 renew waiting for socket select run, usleep 50ms");
        }
        DHCP_LOGI("StartIpv4 renew active Ipv4Thread, signum:%{public}d", signum);
    }
    return DHCP_OPT_SUCCESS;
}


int DhcpClientStateMachine::InitStartIpv4Thread(const std::string &ifname, bool isIpv6)
{
    DHCP_LOGI("InitStartIpv4Thread, ifname:%{public}s, isIpv6:%{public}d", ifname.c_str(), isIpv6);
    if (m_pthread == nullptr) {
        m_pthread = new std::thread(&DhcpClientStateMachine::RunGetIPThreadFunc, this);
        if (m_pthread == nullptr) {
            DHCP_LOGE("InitStartIpv4Thread thread RunGetIPThreadFunc failed!");
            return DHCP_OPT_FAILED;
        }
        m_pthread->detach();
        DHCP_LOGI("InitStartIpv4Thread create thread ok");
    }
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::InitSpecifiedClientCfg(const std::string &ifname, bool isIpv6)
{
    if ((strncpy_s(m_cltCnf.workDir, sizeof(m_cltCnf.workDir), WORKDIR, DIR_MAX_LEN - 1) != EOK) ||
        (strncpy_s(m_cltCnf.ifaceName, sizeof(m_cltCnf.ifaceName), ifname.c_str(), ifname.size()) != EOK)) {
        return DHCP_OPT_FAILED;
    }

    if (strlen(m_cltCnf.workDir) == 0) {
        DHCP_LOGE("InitSpecifiedClientCfg() m_cltCnf.workDir:%{public}s error!", m_cltCnf.workDir);
        return DHCP_OPT_FAILED;
    }

    if (CreateDirs(m_cltCnf.workDir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != DHCP_OPT_SUCCESS) {
        DHCP_LOGE("InitSpecifiedClientCfg() CreateDirs %{public}s failed!", m_cltCnf.workDir);
        return DHCP_OPT_FAILED;
    }

    if (snprintf_s(m_cltCnf.confFile, DIR_MAX_LEN, DIR_MAX_LEN - 1, "%s%s", m_cltCnf.workDir, DHCPC_CONF) < 0) {
        return DHCP_OPT_FAILED;
    }

    if (snprintf_s(m_cltCnf.resultFile, DIR_MAX_LEN, DIR_MAX_LEN - 1, "%s%s.result",
        m_cltCnf.workDir, m_cltCnf.ifaceName) < 0) {
        return DHCP_OPT_FAILED;
    }

    if (snprintf_s(m_cltCnf.leaseFile, DIR_MAX_LEN, DIR_MAX_LEN - 1, "%sdhcp_client_service-%s.lease",
        m_cltCnf.workDir, m_cltCnf.ifaceName) < 0) {
        return DHCP_OPT_FAILED;
    }

    if (snprintf_s(m_cltCnf.result6File, DIR_MAX_LEN, DIR_MAX_LEN - 1, "%sdhcp_client_service-6-%s.lease",
        m_cltCnf.workDir, m_cltCnf.ifaceName) < 0) {
        return DHCP_OPT_FAILED;
    }
    m_cltCnf.getMode = DHCP_IP_TYPE_ALL;
    isIpv6 ? m_cltCnf.getMode = DHCP_IP_TYPE_ALL : m_cltCnf.getMode = DHCP_IP_TYPE_V4;

    DHCP_LOGD("InitSpecifiedClientCfg: ifaceName:%{public}s, workDir:%{public}s, confFile:%{public}s,"
        "leaseFile:%{public}s,resultFile:%{public}s,result6File:%{public}s,getMode:%{public}d", m_cltCnf.ifaceName,
        m_cltCnf.workDir, m_cltCnf.confFile, m_cltCnf.leaseFile,m_cltCnf.resultFile, m_cltCnf.result6File,
        m_cltCnf.getMode);
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::GetClientNetworkInfo(void)
{
    if (GetLocalInterface(m_cltCnf.ifaceName, &m_cltCnf.ifaceIndex, m_cltCnf.ifaceMac, NULL) != DHCP_OPT_SUCCESS) {
        DHCP_LOGE("GetClientNetworkInfo() GetLocalInterface failed, ifaceName:%{public}s.", m_cltCnf.ifaceName);
        return DHCP_OPT_FAILED;
    }

    char macAddr[MAC_ADDR_LEN * MAC_ADDR_CHAR_NUM];
    if (memset_s(macAddr, sizeof(macAddr), 0, sizeof(macAddr)) != EOK) {
        DHCP_LOGE("GetClientNetworkInfo() memset_s failed!");
        return DHCP_OPT_FAILED;
    }
    MacChConToMacStr(m_cltCnf.ifaceMac, MAC_ADDR_LEN, macAddr, sizeof(macAddr));
    DHCP_LOGI("GetClientNetworkInfo() m_cltCnf.ifaceName:%{public}s -> ifaceIndex:%{public}d,ifaceMac:%{private}s.",
        m_cltCnf.ifaceName, m_cltCnf.ifaceIndex, macAddr);

    if (GetLocalIp(m_cltCnf.ifaceName, &m_cltCnf.ifaceIpv4) != DHCP_OPT_SUCCESS) {
        DHCP_LOGE("GetClientNetworkInfo() failed, m_cltCnf.ifaceName:%{public}s.", m_cltCnf.ifaceName);
        return DHCP_OPT_FAILED;
    }
    char *cIp = Ip4IntConToStr(m_cltCnf.ifaceIpv4, true);
    if (cIp == NULL) {
        DHCP_LOGE("GetClientNetworkInfo() Ip4IntConToStr m_cltCnf.ifaceIpv4 failed!");
        return DHCP_OPT_FAILED;
    }
    DHCP_LOGI("GetClientNetworkInfo() GetLocalIp ifaceName:%{public}s -> ifaceIpv4:%{private}u - %{private}s.",
        m_cltCnf.ifaceName, m_cltCnf.ifaceIpv4, cIp);
    free(cIp);
    cIp = NULL;

    /* Generate clientid for the specified client process interface. */
    if (m_cltCnf.pOptClientId == NULL) {
        m_cltCnf.pOptClientId = (unsigned char *)malloc(DHCP_OPT_CODE_BYTES + DHCP_OPT_LEN_BYTES + MAC_ADDR_LEN + 1);
        if (m_cltCnf.pOptClientId == NULL) {
            DHCP_LOGE("GetClientNetworkInfo() m_cltCnf.pOptClientId malloc failed!");
            return DHCP_OPT_FAILED;
        }
        m_cltCnf.pOptClientId[DHCP_OPT_CODE_INDEX] = CLIENT_IDENTIFIER_OPTION;
        m_cltCnf.pOptClientId[DHCP_OPT_LEN_INDEX] = MAC_ADDR_LEN + 1;
        /* Generate format: 1 + ifaceMac. */
        m_cltCnf.pOptClientId[DHCP_OPT_DATA_INDEX] = NUMBER_ONE;
        if (memcpy_s(m_cltCnf.pOptClientId + DHCP_OPT_DATA_INDEX + 1,
            MAC_ADDR_LEN,
            m_cltCnf.ifaceMac,
            MAC_ADDR_LEN) != EOK) {
            DHCP_LOGE("GetClientNetworkInfo() memcpy_s failed!");
            return DHCP_OPT_FAILED;
        }
    }
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::StartIpv4(void)
{
    DHCP_LOGI("StartIpv4  function start");
    int nRet, nMaxFds;
    fd_set exceptfds;
    struct timeval timeout;
    time_t curTimestamp;
 
    if (m_action != ACTION_RENEW) {
         DhcpInit();
    }
    m_cltCnf.timeoutExit = false;
    DHCP_LOGI("StartIpv4 m_dhcp4State:%{public}d m_action:%{public}d", m_dhcp4State, m_action);
    for (; ;) {
        if (m_cltCnf.timeoutExit) {
            DHCP_LOGI("StartIpv4 send packet timed out, now break!");
            break;
        }
        
        FD_ZERO(&exceptfds);
        timeout.tv_sec = m_timeoutTimestamp - time(NULL);
        timeout.tv_usec = (GetRandomId() % USECOND_CONVERT) * USECOND_CONVERT;
        InitSocketFd();

        if (m_sockFd >= 0) {
            FD_SET(m_sockFd, &exceptfds);
            DHCP_LOGI("StartIpv4 m_sockFd>0 m_sockFd:%{public}d", m_sockFd);
        }
        FD_SET(m_sigSockFds[0], &exceptfds);
        DHCP_LOGI("StartIpv4 m_sigSockFds[0]:%{public}d m_sigSockFds[1]:%{public}d m_sentPacketNum:%{public}d",
            m_sigSockFds[0], m_sigSockFds[1], m_sentPacketNum);

        if (timeout.tv_sec <= 0) {
            DHCP_LOGI("StartIpv4 already timed out, need send or resend packet...");
            nRet = 0;
        } else {
            nMaxFds = (m_sigSockFds[0] > m_sockFd) ? m_sigSockFds[0] : m_sockFd;
            m_renewThreadIsRun = true;
            DHCP_LOGI("StartIpv4 waiting on select, m_dhcp4State:%{public}d m_renewThreadIsRun:%{public}d",
                m_dhcp4State, m_renewThreadIsRun);
            nRet = select(nMaxFds + 1, &exceptfds, NULL, NULL, &timeout);
            DHCP_LOGI("StartIpv4 select nMaxFds:%{public}d,m_sigSockFds[0]:%{public}d,m_sigSockFds[1]:%{public}d",
                nMaxFds, m_sigSockFds[0], m_sigSockFds[1]);
        }

        if (nRet < 0) {
            if ((nRet == -1) && (errno == EINTR)) {
                DHCP_LOGI("StartIpv4 select err:%{public}d, a signal was caught!", errno);
            } else {
                DHCP_LOGI("StartIpv4 failed, select maxFds:%{public}d error:%{public}d!", nMaxFds, errno);
            }
            continue;
        }
        curTimestamp = time(NULL);
        DHCP_LOGI("StartIpv4  nRet:%{public}d m_socketMode:%{public}d", nRet, m_socketMode);
        if (nRet == 0) {
            DhcpRequestHandle(curTimestamp);
        } else if ((m_socketMode != SOCKET_MODE_INVALID) && FD_ISSET(m_sockFd, &exceptfds)) {
            DhcpResponseHandle(curTimestamp);
        } else if (FD_ISSET(m_sigSockFds[0], &exceptfds)) {
            SignalReceiver();
        } else {
            DHCP_LOGI("StartIpv4  nRet:%{public}d, m_socketMode:%{public}d, continue select...", nRet, m_socketMode);
        }
    }
    return m_cltCnf.timeoutExit ? ExitIpv4() : DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::ExitIpv4(void)
{
    if (m_pthread != nullptr) {
        delete m_pthread;
        m_pthread = nullptr;
        DHCP_LOGI("StopIpv4 delete m_pthread!");
    }
    DHCP_LOGI("ExitIpv4 timeoutExit:%{public}d threadIsRun:%{public}d", m_cltCnf.timeoutExit, m_renewThreadIsRun);
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::StopIpv4(void)
{
    DHCP_LOGI("StopIpv4 timeoutExit:%{public}d threadIsRun:%{public}d", m_cltCnf.timeoutExit, m_renewThreadIsRun);
    if (!m_cltCnf.timeoutExit) { // thread not exit
        int signum = SIG_STOP;
        if (send(m_sigSockFds[1], &signum, sizeof(signum), MSG_DONTWAIT) < 0) { // SIG_STOP SignalReceiver
            DHCP_LOGE("StopIpv4 send failed.");
            return DHCP_OPT_FAILED;
        }
    }
    return DHCP_OPT_SUCCESS;
}

ActionMode DhcpClientStateMachine::GetAction(void)
{
    return m_action;
}

void DhcpClientStateMachine::DhcpInit(void)
{
    DHCP_LOGI("DhcpInit m_dhcp4State:%{public}d", m_dhcp4State);
    /* Init dhcp ipv4 state. */
    m_dhcp4State = DHCP_STATE_INIT;
    m_resendTimer = 0;
    m_sentPacketNum = 0;
    m_timeoutTimestamp = 0;
    SetSocketMode(SOCKET_MODE_RAW);

    InitSocketFd();

    time_t t = time(NULL);
    if (t == (time_t)-1) {
        return;
    }
    Reboot(t);
}

void DhcpClientStateMachine::DhcpStop(void)
{
    DHCP_LOGI("DhcpStop m_dhcp4State:%{public}d", m_dhcp4State);
    m_cltCnf.timeoutExit = true;
}

void DhcpClientStateMachine::InitSocketFd(void)
{
    DHCP_LOGI("InitSocketFd fd:%{public}d,mode:%{public}d,index:%{public}d,name:%{public}s,timeoutTimestamp:%{public}u",
        m_sockFd, m_socketMode, m_cltCnf.ifaceIndex, m_cltCnf.ifaceName, m_timeoutTimestamp);
    if (m_sockFd < 0) {
        if (m_socketMode == SOCKET_MODE_INVALID) {
            return;
        }

        bool bInitSuccess = true;
        if (m_socketMode == SOCKET_MODE_RAW) {
            if ((CreateRawSocket(&m_sockFd) != SOCKET_OPT_SUCCESS) ||
                (BindRawSocket(m_sockFd, m_cltCnf.ifaceIndex, NULL) != SOCKET_OPT_SUCCESS)) {
                DHCP_LOGE("InitSocketFd fd:%{public}d,index:%{public}d failed!", m_sockFd, m_cltCnf.ifaceIndex);
                bInitSuccess = false;
            }
        } else {
            if ((CreateKernelSocket(&m_sockFd) != SOCKET_OPT_SUCCESS) ||
                (BindKernelSocket(m_sockFd, m_cltCnf.ifaceName, INADDR_ANY, BOOTP_CLIENT, true) !=
                    SOCKET_OPT_SUCCESS)) {
                DHCP_LOGE("InitSocketFd fd:%{public}d,ifname:%{public}s failed!", m_sockFd, m_cltCnf.ifaceName);
                bInitSuccess = false;
            }
        }
        if (!bInitSuccess || (m_sockFd < 0)) {
            DHCP_LOGE("InitSocketFd %{public}d err:%{public}d, couldn't listen on socket!", m_sockFd, errno);
        }
    }
}

int DhcpClientStateMachine::GetPacketReadSockFd(void)
{
    return m_sockFd;
}

int DhcpClientStateMachine::GetSigReadSockFd(void)
{
    return m_sigSockFds[0];
}

uint32_t DhcpClientStateMachine::GetDhcpTransID(void)
{
    return m_transID;
}


void DhcpClientStateMachine::SetSocketMode(uint32_t mode)
{
    DHCP_LOGI("close m_sockFd:%{public}d", m_sockFd);
    close(m_sockFd);
    m_sockFd = -1;
    m_socketMode = mode;
    DHCP_LOGI("SetSocketMode() the socket mode %{public}s.", (mode == SOCKET_MODE_RAW) ? "raw"
        : ((mode == SOCKET_MODE_KERNEL) ? "kernel" : "not valid"));
}

int DhcpClientStateMachine::ExecDhcpRenew(void)
{
    DHCP_LOGI("ExecDhcpRenew m_dhcp4State:%{public}d", m_dhcp4State);
    /* Set socket mode and dhcp ipv4 state, make sure dhcp packets can be sent normally. */
    switch (m_dhcp4State) {
        case DHCP_STATE_INIT:
        case DHCP_STATE_SELECTING:
            DHCP_LOGI("ExecDhcpRenew() dhcp ipv4 old state:%{public}d, no need change state.", m_dhcp4State);
            break;
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RELEASED:
        case DHCP_STATE_RENEWED:
            DHCP_LOGI("ExecDhcpRenew() dhcp ipv4 old state:%{public}d, init state:INIT.", m_dhcp4State);
            /* Init socket mode and dhcp ipv4 state. */
            m_dhcp4State = DHCP_STATE_INIT;
            SetSocketMode(SOCKET_MODE_RAW);
            break;
        case DHCP_STATE_BOUND:
            /* Set socket mode, send unicast packet. */
            SetSocketMode(SOCKET_MODE_KERNEL);
            /* fall through */
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:
            DHCP_LOGI("ExecDhcpRenew() dhcp ipv4 old state:%{public}d, set state:RENEWED.", m_dhcp4State);
            /* Set dhcp ipv4 state, send request packet. */
            m_dhcp4State = DHCP_STATE_RENEWED;
            break;
        default:
            break;
    }

    /* Start record again, go back to init state. */
    m_sentPacketNum = 0;
    m_timeoutTimestamp = 0;
    DHCP_LOGI("ExecDhcpRenew() a dhcp renew is executed...");
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::ExecDhcpRelease(void)
{
    /* Ensure that we've received dhcp ack packet completely. */
    if ((m_dhcp4State == DHCP_STATE_BOUND) || (m_dhcp4State == DHCP_STATE_RENEWING) ||
        (m_dhcp4State == DHCP_STATE_REBINDING)) {
        /* Unicast dhcp release packet. */
        DhcpRelease(m_requestedIp4, m_serverIp4);
    }

    m_dhcp4State = DHCP_STATE_RELEASED;
    SetSocketMode(SOCKET_MODE_INVALID);

    /* Ensure that the function select() is always blocked and don't need to receive ip from dhcp server. */
    m_timeoutTimestamp = SIGNED_INTEGER_MAX;

    DHCP_LOGI("ExecDhcpRelease() enter released state...");
    return DHCP_OPT_SUCCESS;
}

void DhcpClientStateMachine::AddParamaterRequestList(struct DhcpPacket *packet)
{
    int end = GetEndOptionIndex(packet->options);
    int i;
    int len = 0;
    const uint8_t arrReqCode[DHCP_REQ_CODE_NUM] = {SUBNET_MASK_OPTION,
        ROUTER_OPTION,
        DOMAIN_NAME_SERVER_OPTION,
        HOST_NAME_OPTION,
        DOMAIN_NAME_OPTION,
        BROADCAST_ADDRESS_OPTION};

    packet->options[end + DHCP_OPT_CODE_INDEX] = PARAMETER_REQUEST_LIST_OPTION;
    for (i = 0; i < DHCP_REQ_CODE_NUM; i++) {
        if ((arrReqCode[i] > PAD_OPTION) && (arrReqCode[i] < END_OPTION)) {
            packet->options[end + DHCP_OPT_DATA_INDEX + len++] = arrReqCode[i];
        }
    }
    packet->options[end + DHCP_OPT_LEN_INDEX] = len;
    packet->options[end + DHCP_OPT_DATA_INDEX + len] = END_OPTION;
}

uint32_t DhcpClientStateMachine::GetRandomId(void)
{
    static bool bSranded = false;
    if (!bSranded) {
        unsigned int uSeed = 0;
        int nFd = -1;
        if ((nFd = open("/dev/urandom", 0)) == -1) {
            DHCP_LOGE("GetRandomId() open /dev/urandom failed, error:%{public}d!", errno);
            uSeed = time(NULL);
        } else {
            if (read(nFd, &uSeed, sizeof(uSeed)) == -1) {
                DHCP_LOGE("GetRandomId() read /dev/urandom failed, error:%{public}d!", errno);
                uSeed = time(NULL);
            }
            DHCP_LOGI("GetRandomId() read /dev/urandom uSeed:%{public}u.", uSeed);
            close(nFd);
        }
        srandom(uSeed);
        bSranded = true;
    }
    return random();
}

void DhcpClientStateMachine::InitSelecting(time_t timestamp)
{
    if (m_sentPacketNum > TIMEOUT_TIMES_MAX) {
        // Send packet timed out, now exit process.
        DHCP_LOGI("InitSelecting() send packet timed out %{public}u times, now exit process!", m_sentPacketNum);
        m_timeoutTimestamp = timestamp + TIMEOUT_MORE_WAIT_SEC;
        m_sentPacketNum = 0;
        m_cltCnf.timeoutExit = true;
        return;
    }
    
    if (m_sentPacketNum == 0) {
        m_transID = GetRandomId();
    }

    /* Broadcast dhcp discover packet. */
    DhcpDiscover(m_transID, m_requestedIp4);
    m_dhcp4State = DHCP_STATE_SELECTING;

    uint32_t uTimeoutSec = TIMEOUT_WAIT_SEC << m_sentPacketNum;
    if (uTimeoutSec > MAX_WAIT_TIMES) {
        uTimeoutSec = MAX_WAIT_TIMES;
    }
    m_timeoutTimestamp = timestamp + uTimeoutSec;
    DHCP_LOGI("InitSelecting() DhcpDiscover m_sentPacketNum:%{public}u,timeoutSec:%{public}u,timestamp:%{public}u.",
        m_sentPacketNum,
        uTimeoutSec,
        m_timeoutTimestamp);
    m_sentPacketNum++;
}

struct DhcpPacket * DhcpClientStateMachine::ReadLease(void)
{
    if (m_cltCnf.leaseFile[0] == '\0') {
        return NULL;
    }

    int fd;
    struct DhcpPacket *dhcp = NULL;
    ssize_t rBytes;

    fd = open(m_cltCnf.leaseFile, O_RDONLY);
    if (fd < 0) {
        return NULL;
    }

    dhcp = (struct DhcpPacket *)calloc(1, sizeof(struct DhcpPacket));
    if (dhcp == NULL) {
        close(fd);
        return NULL;
    }

    rBytes = read(fd, (uint8_t *)dhcp, sizeof(*dhcp));
    close(fd);
    if (rBytes <= 0 || (size_t)rBytes < offsetof(struct DhcpPacket, options)) {
        free(dhcp);
        dhcp = NULL;
        return NULL;
    }
    return dhcp;
}

ssize_t DhcpClientStateMachine::WriteLease(const struct DhcpPacket *pkt)
{
    if (pkt == NULL) {
        return -1;
    }

    if (m_cltCnf.leaseFile[0] == '\0') {
        return -1;
    }

    int fd;
    ssize_t wBytes;

    fd = open(m_cltCnf.leaseFile, O_WRONLY | O_CREAT | O_TRUNC, RWMODE);
    if (fd < 0) {
        return -1;
    }

    wBytes = write(fd, (uint8_t *)pkt, sizeof(*pkt));
    close(fd);
    return wBytes;
}

void DhcpClientStateMachine::AddParamaterRebootList(struct DhcpPacket *packet)
{
    int end = GetEndOptionIndex(packet->options);
    int i;
    int len = 0;
    const uint8_t arrReqCode[DHCP_REQ_CODE_NUM] = {
        SUBNET_MASK_OPTION,
        STATIC_ROUTE_OPTION,
        ROUTER_OPTION,
        DOMAIN_NAME_SERVER_OPTION,
        BROADCAST_ADDRESS_OPTION,
        IP_ADDRESS_LEASE_TIME_OPTION,
        RENEWAL_TIME_VALUE_OPTION,
        REBINDING_TIME_VALUE_OPTION};

    packet->options[end + DHCP_OPT_CODE_INDEX] = PARAMETER_REQUEST_LIST_OPTION;
    for (i = 0; i < DHCP_REQ_CODE_NUM; i++) {
        if ((arrReqCode[i] > PAD_OPTION) && (arrReqCode[i] < END_OPTION)) {
            packet->options[end + DHCP_OPT_DATA_INDEX + len++] = arrReqCode[i];
        }
    }
    packet->options[end + DHCP_OPT_LEN_INDEX] = len;
    packet->options[end + DHCP_OPT_DATA_INDEX + len] = END_OPTION;
}

int DhcpClientStateMachine::DhcpReboot(uint32_t transid, uint32_t reqip)
{
    DHCP_LOGI("DhcpReboot() enter");
    struct DhcpPacket packet;
    if (memset_s(&packet, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket)) != EOK) {
        DHCP_LOGE("DhcpReboot() memset_s failed!");
        return -1;
    }

    /* Get packet header and common info. */
    if (GetPacketHeaderInfo(&packet, DHCP_REQUEST) != DHCP_OPT_SUCCESS) {
        DHCP_LOGE("DhcpReboot() GetPacketHeaderInfo failed!");
        return -1;
    }

    if (memcpy_s(packet.chaddr, sizeof(packet.chaddr), m_cltCnf.ifaceMac, MAC_ADDR_LEN) != EOK) {
        DHCP_LOGE("DhcpReboot() failed, memcpy_s error!");
        return -1;
    }

    /* Get packet not common info. */
    packet.xid = transid;
    AddOptValueToOpts(packet.options, REQUESTED_IP_ADDRESS_OPTION, reqip);
    AddOptValueToOpts(packet.options, MAXIMUM_DHCP_MESSAGE_SIZE_OPTION, MAX_MSG_SIZE);
    AddOptValueToOpts(packet.options, FORCERENEW_NONCE_OPTION, 1);
    AddParamaterRebootList(&packet);

    /* Begin broadcast dhcp request packet. */
    char *pReqIp = Ip4IntConToStr(reqip, false);
    if (pReqIp != NULL) {
        DHCP_LOGD("DhcpReboot() broadcast req packet, reqip: host %{private}u->%{private}s.", ntohl(reqip), pReqIp);
        free(pReqIp);
        pReqIp = NULL;
    }
    return SendToDhcpPacket(&packet, INADDR_ANY, INADDR_BROADCAST, m_cltCnf.ifaceIndex, (uint8_t *)MAC_BCAST_ADDR);
}

void DhcpClientStateMachine::SendReboot(struct DhcpPacket *p, time_t timestamp)
{
    if (p == NULL) {
        DHCP_LOGE("SendReboot() p is null!");
        return;
    }

    m_requestedIp4 = p->yiaddr;
    free(p);
    p = NULL;
    m_transID = GetRandomId();
    m_dhcp4State = DHCP_STATE_INITREBOOT;
    m_sentPacketNum = 0;

    uint32_t uTimeoutSec = TIMEOUT_WAIT_SEC << m_sentPacketNum;
    m_timeoutTimestamp = timestamp + uTimeoutSec;
    DhcpReboot(m_transID, m_requestedIp4);
}

void DhcpClientStateMachine::Reboot(time_t timestamp)
{
    struct DhcpPacket *pkt = ReadLease();
    if (pkt == NULL) {
        DHCP_LOGE("SendReboot() p is null!");
        return;
    }

    uint32_t leaseTime;
    uint32_t renewalTime;
    uint32_t rebindTime;
    struct stat st;
    if (!GetDhcpOptionUint32(pkt, IP_ADDRESS_LEASE_TIME_OPTION, &leaseTime)) {
        leaseTime = ~0U;
    }

    DHCP_LOGI("Reboot read lease file leaseTime: %{public}u", leaseTime);
    if (leaseTime != ~0U && stat(m_cltCnf.leaseFile, &st) == 0) {
        if (timestamp == (time_t)-1 || timestamp < st.st_mtime || (time_t)leaseTime < timestamp - st.st_mtime) {
            DHCP_LOGI("Reboot read lease file leaseTime expire");
            free(pkt);
            pkt = NULL;
            return;
        } else {
            uint32_t interval = (uint32_t)(timestamp - st.st_mtime);
            leaseTime -= interval;
            renewalTime = leaseTime * RENEWAL_SEC_MULTIPLE;
            rebindTime = leaseTime * REBIND_SEC_MULTIPLE;
            DHCP_LOGI("Reboot read lease file leaseTime:%{public}u, renewalTime:%{public}u, rebindTime:%{public}u",
                leaseTime, renewalTime, rebindTime);
        }
    } else {
        DHCP_LOGI("Reboot read lease file leaseTime option not found");
        free(pkt);
        pkt = NULL;
        return;
    }

    m_leaseTime = leaseTime;
    m_renewalSec = renewalTime;
    m_rebindSec = rebindTime;

    SendReboot(pkt, timestamp);
}

void DhcpClientStateMachine::Requesting(time_t timestamp)
{
    if (m_sentPacketNum > TIMEOUT_TIMES_MAX) {
        /* Send packet timed out, now enter init state. */
        m_dhcp4State = DHCP_STATE_INIT;
        SetSocketMode(SOCKET_MODE_RAW);
        m_sentPacketNum = 0;
        m_timeoutTimestamp = timestamp;
        return;
    }

    if (m_dhcp4State == DHCP_STATE_RENEWED) {
        /* Unicast dhcp request packet in the renew state. */
        DhcpRenew(m_transID, m_requestedIp4, m_serverIp4);
    } else {
        /* Broadcast dhcp request packet in the requesting state. */
        DhcpRequest(m_transID, m_requestedIp4, m_serverIp4);
    }

    uint32_t uTimeoutSec = TIMEOUT_WAIT_SEC << m_sentPacketNum;
    if (uTimeoutSec > MAX_WAIT_TIMES) {
        uTimeoutSec = MAX_WAIT_TIMES;
    }
    m_timeoutTimestamp = timestamp + uTimeoutSec;
    DHCP_LOGI("Requesting() DhcpRequest m_sentPacketNum:%{public}u,timeoutSec:%{public}u,timeoutTimestamp:%{public}u.",
        m_sentPacketNum,
        uTimeoutSec,
        m_timeoutTimestamp);

    m_sentPacketNum++;
}

void DhcpClientStateMachine::Renewing(time_t timestamp)
{
    if ((m_renewalSec + TIME_INTERVAL_MAX) < m_rebindSec) {
        /* Cur time is between renewal and rebind time, unicast dhcp request packet in the renew state. */
        DhcpRenew(m_transID, m_requestedIp4, m_serverIp4);

        /* Set a new renewal time. */
        m_renewalSec += (m_rebindSec - m_renewalSec) / NUMBER_TWO;
        m_timeoutTimestamp = m_renewalTimestamp + m_renewalSec;
        DHCP_LOGI("Renewing() DhcpRenew unicast renewalTime:%{public}u,renewal:%{public}u,timeoutTime:%{public}u, "
                  "rebind:%{public}u.",
            m_renewalTimestamp,
            m_renewalSec,
            m_timeoutTimestamp,
            m_rebindSec);
    } else {
        /* Cur time reaches rebind time, now enter rebinding state. */
        m_dhcp4State = DHCP_STATE_REBINDING;
        DHCP_LOGI("Renewing() cur time reaches rebind time, now enter rebinding state...");
        m_timeoutTimestamp = timestamp + (m_rebindSec - m_renewalSec);
        DHCP_LOGI("Renewing() timestamp:%{public}d,rebind:%{public}u,renewal:%{public}u, timeoutTime:%{public}u.",
            (int)timestamp, m_rebindSec, m_renewalSec, m_timeoutTimestamp);
    }
}

void DhcpClientStateMachine::Rebinding(time_t timestamp)
{
    if ((m_rebindSec + TIME_INTERVAL_MAX) < m_leaseTime) {
        /* Cur time is between rebind and lease time, broadcast dhcp request packet in the rebind state. */
        DhcpRenew(m_transID, m_requestedIp4, 0);

        /* Set a new rebind time. */
        m_rebindSec += (m_leaseTime - m_rebindSec) / NUMBER_TWO;
        m_timeoutTimestamp = m_renewalTimestamp + m_rebindSec;
        DHCP_LOGI("Rebinding() DhcpRenew broadcast renewalTime:%{public}u,rebind:%{public}u,timeoutTime:%{public}u, "
                  "lease:%{public}u.",
            m_renewalTimestamp,
            m_rebindSec,
            m_timeoutTimestamp,
            m_leaseTime);
    } else {
        /* Cur time reaches lease time, send packet timed out, now enter init state. */
        DHCP_LOGI("Rebinding() 555 cur time reaches lease time, now enter init state...");
        m_dhcp4State = DHCP_STATE_INIT;
        SetSocketMode(SOCKET_MODE_RAW);
        m_sentPacketNum = 0;
        m_timeoutTimestamp = timestamp;
        return;
    }
}

void DhcpClientStateMachine::DhcpRequestHandle(time_t timestamp)
{
    DHCP_LOGI("DhcpRequestHandle() m_dhcp4State:%{public}d", m_dhcp4State);
    switch (m_dhcp4State) {
        case DHCP_STATE_INIT:
        case DHCP_STATE_SELECTING:
            DHCP_LOGI("DhcpRequestHandle() DHCP_STATE_INIT-0 DHCP_STATE_SELECTING-1");
            InitSelecting(timestamp);
            break;
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RENEWED:
            DHCP_LOGI("DhcpRequestHandle() DHCP_STATE_REQUESTING-2 DHCP_STATE_RENEWING-8");
            Requesting(timestamp);
            break;
        case DHCP_STATE_BOUND:
            /* Now the renewal time run out, ready to enter renewing state. */
            DHCP_LOGI("DhcpRequestHandle() DHCP_STATE_BOUND-3 the renewal time run out, ready to enter renewing state");
            m_dhcp4State = DHCP_STATE_RENEWING;
            SetSocketMode(SOCKET_MODE_KERNEL);
            /* fall through */
        case DHCP_STATE_RENEWING:
            DHCP_LOGI("DhcpRequestHandle() DHCP_STATE_RENEWING-4");
            Renewing(timestamp);
            break;
        case DHCP_STATE_REBINDING:
            DHCP_LOGI("DhcpRequestHandle() DHCP_STATE_REBINDING-8");
            Rebinding(timestamp);
            break;
        case DHCP_STATE_INITREBOOT:
            DHCP_LOGI("DhcpRequestHandle() DHCP_STATE_INITREBOOT-6 m_dhcp4State:%{public}d", m_dhcp4State);
            m_dhcp4State = DHCP_STATE_INIT;
            break;
        case DHCP_STATE_RELEASED:
            /* Ensure that the function select() is always blocked and don't need to receive ip from dhcp server. */
            DHCP_LOGI("DhcpRequestHandle() DHCP_STATE_RELEASED-7 m_timeoutTimestamp:%{public}d", m_timeoutTimestamp);
            m_timeoutTimestamp = SIGNED_INTEGER_MAX;
            break;
        default:
            break;
    }
}
void DhcpClientStateMachine::DhcpOfferPacketHandle(uint8_t type, const struct DhcpPacket *packet, time_t timestamp)
{
    if (type != DHCP_OFFER) {
        DHCP_LOGE("DhcpOfferPacketHandle() type:%{public}d error!", type);
        return;
    }

    if (packet == NULL) {
        DHCP_LOGE("DhcpOfferPacketHandle() type:%{public}d error, packet == NULL!", type);
        return;
    }

    uint32_t u32Data = 0;
    if (!GetDhcpOptionUint32(packet, SERVER_IDENTIFIER_OPTION, &u32Data)) {
        DHCP_LOGE("DhcpOfferPacketHandle() type:%{public}d GetDhcpOptionUint32 SERVER_IDENTIFIER_OPTION failed!", type);
        return;
    }

    m_transID = packet->xid;
    m_requestedIp4 = packet->yiaddr;
    m_serverIp4 = htonl(u32Data);

    char *pReqIp = Ip4IntConToStr(m_requestedIp4, false);
    if (pReqIp != NULL) {
        DHCP_LOGI(
            "DhcpOfferPacketHandle() receive DHCP_OFFER, xid:%{public}u, requestIp: host %{private}u->%{private}s.",
            m_transID,
            ntohl(m_requestedIp4),
            pReqIp);
        free(pReqIp);
        pReqIp = NULL;
    }
    char *pSerIp = Ip4IntConToStr(m_serverIp4, false);
    if (pSerIp != NULL) {
        DHCP_LOGI("DhcpOfferPacketHandle() receive DHCP_OFFER, serverIp: host %{private}u->%{private}s.",
            ntohl(m_serverIp4),
            pSerIp);
        free(pSerIp);
        pSerIp = NULL;
    }

    /* Receive dhcp offer packet finished, next send dhcp request packet. */
    WriteLease(packet);
    m_dhcp4State = DHCP_STATE_REQUESTING;
    m_sentPacketNum = 0;
    m_timeoutTimestamp = timestamp;
}

void DhcpClientStateMachine::ParseOtherNetworkInfo(const struct DhcpPacket *packet, struct DhcpIpResult *result)
{
    if ((packet == NULL) || (result == NULL)) {
        DHCP_LOGE("ParseOtherNetworkInfo() error, packet == NULL or result == NULL!");
        return;
    }

    uint32_t u32Data = 0;
    uint32_t u32Data2 = 0;
    if (GetDhcpOptionUint32n(packet, DOMAIN_NAME_SERVER_OPTION, &u32Data, &u32Data2)) {
        char *pDnsIp = Ip4IntConToStr(u32Data, true);
        if (pDnsIp != NULL) {
            DHCP_LOGI("ParseOtherNetworkInfo() recv DHCP_ACK 6, dns1: %{private}u->%{private}s.", u32Data, pDnsIp);
            if (strncpy_s(result->strOptDns1, INET_ADDRSTRLEN, pDnsIp, INET_ADDRSTRLEN - 1) != EOK) {
                free(pDnsIp);
                pDnsIp = NULL;
                return;
            }
            free(pDnsIp);
            pDnsIp = NULL;
        }
        if ((u32Data2 > 0) && ((pDnsIp = Ip4IntConToStr(u32Data2, true)) != NULL)) {
            DHCP_LOGI("ParseOtherNetworkInfo() recv DHCP_ACK 6, dns2: %{private}u->%{private}s.", u32Data2, pDnsIp);
            if (strncpy_s(result->strOptDns2, INET_ADDRSTRLEN, pDnsIp, INET_ADDRSTRLEN - 1) != EOK) {
                DHCP_LOGE("ParseOtherNetworkInfo() strncpy_s Failed.");
            }
            free(pDnsIp);
            pDnsIp = NULL;
            return;
        }
    }
    return;
}

void DhcpClientStateMachine::ParseNetworkInfo(const struct DhcpPacket *packet, struct DhcpIpResult *result)
{
    if ((packet == NULL) || (result == NULL)) {
        DHCP_LOGE("ParseNetworkInfo() error, packet == NULL or result == NULL!");
        return;
    }

    char *pReqIp = Ip4IntConToStr(m_requestedIp4, false);
    if (pReqIp != NULL) {
        DHCP_LOGI("ParseNetworkInfo() recv DHCP_ACK yiaddr: %{private}u->%{private}s.", ntohl(m_requestedIp4), pReqIp);
        if (strncpy_s(result->strYiaddr, INET_ADDRSTRLEN, pReqIp, INET_ADDRSTRLEN - 1) != EOK) {
            DHCP_LOGI("ParseNetworkInfo() strncpy_s failed!");
            free(pReqIp);
            pReqIp = NULL;
            return;
        }
        free(pReqIp);
        pReqIp = NULL;
    }

    uint32_t u32Data = 0;
    if (GetDhcpOptionUint32(packet, SUBNET_MASK_OPTION, &u32Data)) {
        char *pSubIp = Ip4IntConToStr(u32Data, true);
        if (pSubIp != NULL) {
            DHCP_LOGI("ParseNetworkInfo() recv DHCP_ACK 1, subnetmask: %{private}u->%{private}s.", u32Data, pSubIp);
            if (strncpy_s(result->strOptSubnet, INET_ADDRSTRLEN, pSubIp, INET_ADDRSTRLEN - 1) != EOK) {
                free(pSubIp);
                pSubIp = NULL;
                return;
            }
            free(pSubIp);
            pSubIp = NULL;
        }
    }

    u32Data = 0;
    uint32_t u32Data2 = 0;
    if (GetDhcpOptionUint32n(packet, ROUTER_OPTION, &u32Data, &u32Data2)) {
        char *pRouterIp = Ip4IntConToStr(u32Data, true);
        if (pRouterIp != NULL) {
            DHCP_LOGI("ParseNetworkInfo() recv DHCP_ACK 3, router1: %{private}u->%{private}s.", u32Data, pRouterIp);
            if (strncpy_s(result->strOptRouter1, INET_ADDRSTRLEN, pRouterIp, INET_ADDRSTRLEN - 1) != EOK) {
                free(pRouterIp);
                pRouterIp = NULL;
                return;
            }
            free(pRouterIp);
            pRouterIp = NULL;
        }
        if ((u32Data2 > 0) && ((pRouterIp = Ip4IntConToStr(u32Data2, true)) != NULL)) {
            DHCP_LOGI("ParseNetworkInfo() recv DHCP_ACK 3, router2: %{private}u->%{private}s.", u32Data2, pRouterIp);
            if (strncpy_s(result->strOptRouter2, INET_ADDRSTRLEN, pRouterIp, INET_ADDRSTRLEN - 1) != EOK) {
                free(pRouterIp);
                pRouterIp = NULL;
                return;
            }
            free(pRouterIp);
            pRouterIp = NULL;
        }
    }

    ParseOtherNetworkInfo(packet, result);
}

void DhcpClientStateMachine::FormatString(struct DhcpIpResult *result)
{
    if (result == nullptr) {
        DHCP_LOGE("FormatString error, result == nullptr!");
        return;
    }

    if (strlen(result->strYiaddr) == 0) {
        if (strncpy_s(result->strYiaddr, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) != EOK) {
            DHCP_LOGE("FormatString strncpy_s strYiaddr failed!");
            return;
        }
    }
    if (strlen(result->strOptServerId) == 0) {
        if (strncpy_s(result->strOptServerId, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) != EOK) {
            DHCP_LOGE("FormatString strncpy_s strOptServerId failed!");
            return;
        }
    }
    if (strlen(result->strOptSubnet) == 0) {
        if (strncpy_s(result->strOptSubnet, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) != EOK) {
            DHCP_LOGE("FormatString strncpy_s strOptSubnet failed!");
            return;
        }
    }
    if (strlen(result->strOptDns1) == 0) {
        if (strncpy_s(result->strOptDns1, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) != EOK) {
            DHCP_LOGE("FormatString strncpy_s strOptDns1 failed!");
            return;
        }
    }
    if (strlen(result->strOptDns2) == 0) {
        if (strncpy_s(result->strOptDns2, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) != EOK) {
            DHCP_LOGE("FormatString strncpy_s strOptDns2 failed!");
            return;
        }
    }
    if (strlen(result->strOptRouter1) == 0) {
        if (strncpy_s(result->strOptRouter1, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) != EOK) {
            DHCP_LOGE("FormatString strncpy_s strOptRouter1 failed!");
            return;
        }
    }
    if (strlen(result->strOptRouter2) == 0) {
        if (strncpy_s(result->strOptRouter2, INET_ADDRSTRLEN, "*", INET_ADDRSTRLEN - 1) != EOK) {
            DHCP_LOGE("FormatString strncpy_s strOptRouter2 failed!");
            return;
        }
    }
    if (strlen(result->strOptVendor) == 0) {
        if (strncpy_s(result->strOptVendor, DHCP_FILE_MAX_BYTES, "*", DHCP_FILE_MAX_BYTES - 1) != EOK) {
            DHCP_LOGE("FormatString strncpy_s strOptVendor failed!");
            return;
        }
    }
}

int DhcpClientStateMachine::GetDHCPServerHostName(const struct DhcpPacket *packet, struct DhcpIpResult *result)
{
    if ((packet == NULL) || (result == NULL)) {
        DHCP_LOGE("GetDHCPServerHostName() error, packet == NULL or result == NULL!");
        return DHCP_OPT_FAILED;
    }
    const uint8_t *p = packet->sname;
    char *pSname = NULL;
    if (p == NULL || *p == '\0') {
        DHCP_LOGW("GetDHCPServerHostName() recv DHCP_ACK sname, pSname is NULL!");
    } else {
        pSname = (char*)p;
        DHCP_LOGI("GetDHCPServerHostName() recv DHCP_ACK sname, original pSname is %{public}s.", pSname);
        const char *pHostName = "hostname:";
        if (strncpy_s(result->strOptVendor, DHCP_FILE_MAX_BYTES, pHostName, DHCP_FILE_MAX_BYTES - 1) != EOK) {
            DHCP_LOGE("GetDHCPServerHostName() error, strncpy_s pHostName failed!");
            pHostName = NULL;
            return DHCP_OPT_FAILED;
        } else {
            DHCP_LOGI("GetDHCPServerHostName() recv DHCP_ACK sname, save ""hostname:"" only, \
                result->strOptVendor is %{public}s.", result->strOptVendor);
            if (strncat_s(result->strOptVendor, DHCP_FILE_MAX_BYTES,
                          pSname, DHCP_FILE_MAX_BYTES - strlen(pHostName) - 1) != EOK) {
                DHCP_LOGE("GetDHCPServerHostName() error, strncat_s pSname failed!");
                pHostName = NULL;
                return DHCP_OPT_FAILED;
            } else {
                DHCP_LOGI("SyncDhcpResult() recv DHCP_ACK sname, add pSname, \
                    result->strOptVendor is %{public}s.", result->strOptVendor);
            }
            pHostName = NULL;
        }
    }
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::SyncDhcpResult(const struct DhcpPacket *packet, struct DhcpIpResult *result)
{
    if ((packet == NULL) || (result == NULL)) {
        DHCP_LOGE("SyncDhcpResult() error, packet == NULL or result == NULL!");
        return DHCP_OPT_FAILED;
    }

    char *pVendor = GetDhcpOptionString(packet, VENDOR_SPECIFIC_INFO_OPTION);
    if (pVendor == NULL) {
        DHCP_LOGW("SyncDhcpResult() recv DHCP_ACK 43, pVendor is NULL!");
        if (GetDHCPServerHostName(packet, result) != DHCP_OPT_SUCCESS) {
            DHCP_LOGE("GetDHCPServerHostName() error, GetDHCPServerHostName failed!");
            return DHCP_OPT_FAILED;
        }
    /* Get option43 success. */
    } else {
        DHCP_LOGI("SyncDhcpResult() recv DHCP_ACK 43, pVendor is %{public}s.", pVendor);
        if (strncpy_s(result->strOptVendor, DHCP_FILE_MAX_BYTES, pVendor, DHCP_FILE_MAX_BYTES - 1) != EOK) {
            DHCP_LOGE("SyncDhcpResult() error, strncpy_s pVendor failed!");
            free(pVendor);
            pVendor = NULL;
            return DHCP_OPT_FAILED;
        }
        free(pVendor);
        pVendor = NULL;
    }

    /* Set the specified client process interface network info. */
    if (SetLocalInterface(m_cltCnf.ifaceName, inet_addr(result->strYiaddr), inet_addr(result->strOptSubnet))
        != DHCP_OPT_SUCCESS) {
        DHCP_LOGE("SyncDhcpResult() error, SetLocalInterface yiaddr:%{public}s failed!", result->strYiaddr);
        return DHCP_OPT_FAILED;
    }

     /* Format dhcp result. */
    FormatString(result);
#ifndef OHOS_ARCH_LITE
    StopGetIpTimer(); //stop get ip timer
#endif
    /* Publish dhcp success result event. */
    if (PublishDhcpResultEvent(m_cltCnf.ifaceName, PUBLISH_CODE_SUCCESS, result) != DHCP_OPT_SUCCESS) {
        DHCP_LOGE("SyncDhcpResult() error, PublishDhcpResultEvent result failed!");
        return DHCP_OPT_FAILED;
    }
    DHCP_LOGI("SyncDhcpResult() handle dhcp result success, ifaceName:%{public}s.", m_cltCnf.ifaceName);
    return DHCP_OPT_SUCCESS;
}

void DhcpClientStateMachine::ParseDhcpAckPacket(const struct DhcpPacket *packet, time_t timestamp)
{
    if (packet == NULL) {
        DHCP_LOGE("ParseDhcpAckPacket() error, packet == NULL!");
        return;
    }

    struct DhcpIpResult dhcpResult;
    if (memset_s(&dhcpResult, sizeof(struct DhcpIpResult), 0, sizeof(struct DhcpIpResult)) != EOK) {
        DHCP_LOGE("ParseDhcpAckPacket() error, memset_s failed!");
        return;
    }

    /* Set default leasetime. */
    m_leaseTime = LEASETIME_DEFAULT * ONE_HOURS_SEC;
    m_requestedIp4 = packet->yiaddr;
    uint32_t u32Data = 0;
    if (GetDhcpOptionUint32(packet, IP_ADDRESS_LEASE_TIME_OPTION, &u32Data)) {
        m_leaseTime = u32Data;
        DHCP_LOGI("ParseDhcpAckPacket() recv DHCP_ACK 51, lease:%{public}u.", m_leaseTime);
    }
    m_renewalSec = m_leaseTime * RENEWAL_SEC_MULTIPLE;  /* First renewal seconds. */
    m_rebindSec  = m_leaseTime * REBIND_SEC_MULTIPLE;   /* Second rebind seconds. */
    m_renewalTimestamp = timestamp;   /* Record begin renewing or rebinding timestamp. */
    dhcpResult.uOptLeasetime = m_leaseTime;
    DHCP_LOGI("ParseDhcpAckPacket() Last get lease:%{public}u,renewal:%{public}u,rebind:%{public}u.",
        m_leaseTime, m_renewalSec, m_rebindSec);

    if (!GetDhcpOptionUint32(packet, SERVER_IDENTIFIER_OPTION, &u32Data)) {
        DHCP_LOGE("ParseDhcpAckPacket() GetDhcpOptionUint32 SERVER_IDENTIFIER_OPTION failed!");
    } else {
        m_serverIp4 = htonl(u32Data);
        char *pSerIp = Ip4IntConToStr(m_serverIp4, false);
        if (pSerIp != NULL) {
            DHCP_LOGI("ParseDhcpAckPacket() recv DHCP_ACK 54, serid: %{private}u->%{private}s.", u32Data, pSerIp);
            if (strncpy_s(dhcpResult.strOptServerId, INET_ADDRSTRLEN, pSerIp, INET_ADDRSTRLEN - 1) != EOK) {
                free(pSerIp);
                pSerIp = NULL;
                return;
            }
            free(pSerIp);
            pSerIp = NULL;
        }
    }

    /* Parse the specified client process interface network info. */
    ParseNetworkInfo(packet, &dhcpResult);

    /* Sync the specified client process interface network info to the file. */
    if (SyncDhcpResult(packet, &dhcpResult) != DHCP_OPT_SUCCESS) {
        /* Publish dhcp failed result event. */
        PublishDhcpResultEvent(m_cltCnf.ifaceName, PUBLISH_CODE_FAILED, NULL);
        return;
    }

    /* Receive dhcp ack packet finished, m_leaseTime * T1 later enter renewing state. */
    m_dhcp4State = DHCP_STATE_BOUND;
    m_sentPacketNum = 0;
    m_resendTimer = 0;
    SetSocketMode(SOCKET_MODE_INVALID);
    m_timeoutTimestamp = timestamp + m_renewalSec;
    DHCP_LOGI("DHCP_STATE_BOUND m_renewalSec:%{public}u, m_timeoutTimestamp:%{public}u.", m_renewalSec,
        m_timeoutTimestamp);
}

void DhcpClientStateMachine::DhcpAckOrNakPacketHandle(uint8_t type, struct DhcpPacket *packet, time_t timestamp)
{
    if ((type != DHCP_ACK) && (type != DHCP_NAK)) {
        DHCP_LOGI("DhcpAckOrNakPacketHandle() type:%{public}d error!", type);
        if (m_dhcp4State == DHCP_STATE_INITREBOOT) {
            m_dhcp4State = DHCP_STATE_INIT;
            m_timeoutTimestamp = timestamp;
        }
        return;
    }

    if (packet == NULL) {
        DHCP_LOGE("DhcpAckOrNakPacketHandle() type:%{public}d error, packet == NULL!", type);
        return;
    }

    if (type == DHCP_NAK) {
        /* If receive dhcp nak packet, init m_dhcp4State, resend dhcp discover packet. */
        DHCP_LOGI("DhcpAckOrNakPacketHandle() receive DHCP_NAK 53, init m_dhcp4State, resend dhcp discover packet!");
        m_dhcp4State = DHCP_STATE_INIT;
        SetSocketMode(SOCKET_MODE_RAW);
        m_requestedIp4 = 0;
        m_sentPacketNum = 0;
        m_timeoutTimestamp = timestamp;

        /* Avoid excessive network traffic. */
        DHCP_LOGI("DhcpAckOrNakPacketHandle() receive DHCP_NAK 53, avoid excessive network traffic, need sleep!");
        if (m_resendTimer == 0) {
            m_resendTimer = FIRST_TIMEOUT_SEC;
        } else {
            sleep(m_resendTimer);

            m_resendTimer *= DOUBLE_TIME;
            if (m_resendTimer > MAX_TIMEOUT_SEC) {
                m_resendTimer = MAX_TIMEOUT_SEC;
            }
        }
        return;
    }
    DHCP_LOGI("DhcpAckOrNakPacketHandle() recv DHCP_ACK 53.");

    /* Parse received dhcp ack packet. */
    ParseDhcpAckPacket(packet, timestamp);

    /* ack packet success. */
    if (m_dhcp4State == DHCP_STATE_BOUND) {
        WriteLease(packet);
    }
}

void DhcpClientStateMachine::DhcpResponseHandle(time_t timestamp)
{
    DHCP_LOGI("DhcpResponseHandle() enter");
    struct DhcpPacket packet;
    int getLen;
    uint8_t u8Message = 0;

    if (memset_s(&packet, sizeof(packet), 0, sizeof(packet)) != EOK) {
        DHCP_LOGE("DhcpResponseHandle() memset_s packet failed!");
        return;
    }
    getLen = (m_socketMode == SOCKET_MODE_RAW) ? GetDhcpRawPacket(&packet, m_sockFd)
                                               : GetDhcpKernelPacket(&packet, m_sockFd);
    if (getLen < 0) {
        if ((getLen == SOCKET_OPT_ERROR) && (errno != EINTR)) {
            DHCP_LOGI(" DhcpResponseHandle() get packet read error, reopening socket!");
            /* Reopen m_sockFd. */
            SetSocketMode(m_socketMode);
        }
        DHCP_LOGI("DhcpResponseHandle() get packet failed, error:%{public}d!", errno);
        if (m_dhcp4State == DHCP_STATE_INITREBOOT) {
            m_dhcp4State = DHCP_STATE_INIT;
            m_timeoutTimestamp = timestamp;
        }
        return;
    }
    DHCP_LOGI("DhcpResponseHandle() get packet success, getLen:%{public}d.", getLen);

    /* Check packet data. */
    if (packet.xid != m_transID) {
        DHCP_LOGW("DhcpResponseHandle() get xid:%{public}u and m_transID:%{public}u not same!", packet.xid, m_transID);
        return;
    }
    if (!GetDhcpOptionUint8(&packet, DHCP_MESSAGE_TYPE_OPTION, &u8Message)) {
        DHCP_LOGE("DhcpResponseHandle() GetDhcpOptionUint8 DHCP_MESSAGE_TYPE_OPTION failed!");
        return;
    }
    DHCP_LOGI("DhcpResponseHandle() m_dhcp4State:%{public}d.", m_dhcp4State);
    switch (m_dhcp4State) {
        case DHCP_STATE_SELECTING:
            DHCP_LOGI("DhcpResponseHandle() DHCP_STATE_SELECTING");
            DhcpOfferPacketHandle(u8Message, &packet, timestamp);
            break;
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:
        case DHCP_STATE_INITREBOOT:
        case DHCP_STATE_RENEWED:
            DHCP_LOGI("DhcpResponseHandle() DHCP_STATE_RENEWED");
            DhcpAckOrNakPacketHandle(u8Message, &packet, timestamp);
            break;
        case DHCP_STATE_BOUND:
        case DHCP_STATE_RELEASED:
            DHCP_LOGI("DhcpResponseHandle() m_dhcp4State is BOUND or RELEASED, ignore all packets!");
            break;
        default:
            break;
    }
}

/* Receive signals. */
void DhcpClientStateMachine::SignalReceiver(void)
{
    int signum;
    if (read(m_sigSockFds[0], &signum, sizeof(signum)) < 0) {
        DHCP_LOGE("SignalReceiver read failed, m_sigSockFds[0]:%{public}d read error:%{public}d!", m_sigSockFds[0],
            errno);
        return;
    }
    DHCP_LOGE("SignalReceiver read sigSockFds[0]:%{public}d signum:%{public}d!", m_sigSockFds[0], signum);
    switch (signum) {
        case SIG_START :
            DhcpInit();
            break;
        case SIG_STOP :
            DhcpStop();
            break;
        case SIG_RENEW:   
            ExecDhcpRenew();
            break;
        default:
            DHCP_LOGI("SignalReceiver default, signum:%{public}d", signum);
            break;
    }
}

/* Set dhcp ipv4 state. */
int DhcpClientStateMachine::SetIpv4State(int state)
{
    if (state < 0) {
        DHCP_LOGE("SetIpv4State() failed, state:%{public}d!", state);
        return DHCP_OPT_FAILED;
    }
    m_dhcp4State = state;
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::PublishDhcpResultEvent(const char *ifname, const int code, struct DhcpIpResult *result)
{
    if (ifname == NULL) {
        DHCP_LOGE("PublishDhcpResultEvent() failed, ifname == NULL!");
        return DHCP_OPT_FAILED;
    }
    if ((code != PUBLISH_CODE_SUCCESS) && (code != PUBLISH_CODE_FAILED)) {
        DHCP_LOGE("PublishDhcpResultEvent() ifname:%{public}s failed, code:%{public}d error!", ifname, code);
        return DHCP_OPT_FAILED;
    }
    if ((code == PUBLISH_CODE_SUCCESS) && (result == NULL)) {
        DHCP_LOGE("PublishDhcpResultEvent() ifname:%{public}s,code:%{public}d failed, result == NULL!", ifname, code);
        return DHCP_OPT_FAILED;
    }
    
    /* Data format - ipv4:ifname,time,cliIp,lease,servIp,subnet,dns1,dns2,router1,router2,vendor */
    int nBytes;
    uint32_t curTime = (uint32_t)time(NULL);
    char strData[STRING_MAX_LEN] = {0};
    if (code == PUBLISH_CODE_SUCCESS) {
        nBytes = snprintf_s(strData, STRING_MAX_LEN, STRING_MAX_LEN - 1, "ipv4:%s,%u,%s,%u,%s,%s,%s,%s,%s,%s,%s ",
            ifname, curTime, result->strYiaddr, result->uOptLeasetime, result->strOptServerId, result->strOptSubnet,
            result->strOptDns1, result->strOptDns2, result->strOptRouter1, result->strOptRouter2, result->strOptVendor);
    } else {
        nBytes = snprintf_s(strData, STRING_MAX_LEN, STRING_MAX_LEN - 1, "ipv4:%s,%u,*,*,*,*,*,*,*,*,*",
            ifname, curTime);
    }
    if (nBytes < 0) {
        DHCP_LOGE("PublishDhcpResultEvent() failed, snprintf_s %{public}s error:%{public}d!", ifname, errno);
        return DHCP_OPT_FAILED;
    }

    if (!PublishDhcpIpv4ResultEvent(code, strData, ifname)) {
        DHCP_LOGI("PublishDhcpResultEvent() PublishDhcpIpv4ResultEvent %{public}d failed!", code);
        return DHCP_OPT_FAILED;
    }
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::GetPacketHeaderInfo(struct DhcpPacket *packet, uint8_t type)
{
    if (packet == NULL) {
        DHCP_LOGE("GetPacketHeaderInfo() failed, packet == NULL!");
        return DHCP_OPT_FAILED;
    }

    switch (type) {
        case DHCP_DISCOVER:
        case DHCP_REQUEST:
        case DHCP_DECLINE:
        case DHCP_RELEASE:
        case DHCP_INFORM:
            packet->op = BOOT_REQUEST;
            break;
        case DHCP_OFFER:
        case DHCP_ACK:
        case DHCP_NAK:
            packet->op = BOOT_REPLY;
            break;
        default:
            break;
    }
    packet->htype = ETHERNET_TYPE;
    packet->hlen = ETHERNET_LEN;
    packet->cookie = htonl(MAGIC_COOKIE);
    packet->options[0] = END_OPTION;
    AddOptValueToOpts(packet->options, DHCP_MESSAGE_TYPE_OPTION, type);

    return DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::GetPacketCommonInfo(struct DhcpPacket *packet)
{
    if (packet == NULL) {
        DHCP_LOGE("GetPacketCommonInfo() failed, packet == NULL!");
        return DHCP_OPT_FAILED;
    }

    /* Add packet client_cfg info. */
    if (memcpy_s(packet->chaddr, sizeof(packet->chaddr), m_cltCnf.ifaceMac, MAC_ADDR_LEN) != EOK) {
        DHCP_LOGE("GetPacketCommonInfo() failed, memcpy_s error!");
        return DHCP_OPT_FAILED;
    }
    int nClientIdLen = DHCP_OPT_CODE_BYTES + DHCP_OPT_LEN_BYTES + m_cltCnf.pOptClientId[DHCP_OPT_LEN_INDEX];
    AddOptStrToOpts(packet->options, m_cltCnf.pOptClientId, nClientIdLen);

    /* Add packet vendor info, vendor format: pro-version. */
    char buf[VENDOR_MAX_LEN - DHCP_OPT_CODE_BYTES - DHCP_OPT_LEN_BYTES] = {0};
    unsigned char vendorId[VENDOR_MAX_LEN] = {0};
    unsigned char *pVendorId = vendorId;
    int nRes = snprintf_s(buf,
        VENDOR_MAX_LEN - DHCP_OPT_DATA_INDEX,
        VENDOR_MAX_LEN - DHCP_OPT_DATA_INDEX - 1,
        "%s-%s",
        DHCPC_NAME,
        DHCPC_VERSION);
    if (nRes < 0) {
        DHCP_LOGE("GetPacketCommonInfo() failed, snprintf_s res:%{public}d error!", nRes);
        return DHCP_OPT_FAILED;
    }
    pVendorId[DHCP_OPT_CODE_INDEX] = VENDOR_SPECIFIC_INFO_OPTION;
    pVendorId[DHCP_OPT_LEN_INDEX] = strlen(buf);
    if (strncpy_s((char *)pVendorId + DHCP_OPT_DATA_INDEX, VENDOR_MAX_LEN - DHCP_OPT_DATA_INDEX, buf, strlen(buf)) !=
        EOK) {
        DHCP_LOGE("GetPacketCommonInfo() failed, strncpy_s error!");
        return DHCP_OPT_FAILED;
    }
    if (strlen((char *)vendorId) > 0) {
        int nVendorIdLen = DHCP_OPT_CODE_BYTES + DHCP_OPT_LEN_BYTES + pVendorId[DHCP_OPT_LEN_INDEX];
        AddOptStrToOpts(packet->options, vendorId, nVendorIdLen);
    }

    return DHCP_OPT_SUCCESS;
}

/* Broadcast dhcp discover packet, discover dhcp servers that can provide ip address. */
int DhcpClientStateMachine::DhcpDiscover(uint32_t transid, uint32_t requestip)
{
    DHCP_LOGI("DhcpDiscover() enter, transid:%{public}u,requestip:%{public}u.", transid, requestip);
    struct DhcpPacket packet;
    if (memset_s(&packet, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket)) != EOK) {
        return -1;
    }

    /* Get packet header and common info. */
    if ((GetPacketHeaderInfo(&packet, DHCP_DISCOVER) != DHCP_OPT_SUCCESS) ||
        (GetPacketCommonInfo(&packet) != DHCP_OPT_SUCCESS)) {
        DHCP_LOGE("DhcpDiscover() GetPacketHeaderInfo failed!");
        return -1;
    }

    /* Get packet not common info. */
    packet.xid = transid;
    AddParamaterRequestList(&packet);

    /* Begin broadcast dhcp discover packet. */
    DHCP_LOGI("DhcpDiscover() discover, begin broadcast discover packet...");
    return SendToDhcpPacket(&packet, INADDR_ANY, INADDR_BROADCAST, m_cltCnf.ifaceIndex, (uint8_t *)MAC_BCAST_ADDR);
}

/* Broadcast dhcp request packet, tell dhcp servers that which ip address to choose. */
int DhcpClientStateMachine::DhcpRequest(uint32_t transid, uint32_t reqip, uint32_t servip)
{
    DHCP_LOGI("DhcpRequest() enter, transid:%{public}u,reqip:%{private}u.", transid, reqip);

    struct DhcpPacket packet;
    if (memset_s(&packet, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket)) != EOK) {
        return -1;
    }

    /* Get packet header and common info. */
    if ((GetPacketHeaderInfo(&packet, DHCP_REQUEST) != DHCP_OPT_SUCCESS) ||
        (GetPacketCommonInfo(&packet) != DHCP_OPT_SUCCESS)) {
        return -1;
    }

    /* Get packet not common info. */
    packet.xid = transid;
    AddOptValueToOpts(packet.options, REQUESTED_IP_ADDRESS_OPTION, reqip);
    AddOptValueToOpts(packet.options, SERVER_IDENTIFIER_OPTION, servip);
    AddParamaterRequestList(&packet);

    /* Begin broadcast dhcp request packet. */
    char *pReqIp = Ip4IntConToStr(reqip, false);
    if (pReqIp != NULL) {
        DHCP_LOGI("DhcpRequest() broadcast req packet, reqip: host %{private}u->%{private}s.", ntohl(reqip), pReqIp);
        free(pReqIp);
        pReqIp = NULL;
    }
    char *pSerIp = Ip4IntConToStr(servip, false);
    if (pSerIp != NULL) {
        DHCP_LOGI("DhcpRequest() broadcast req packet, servIp: host %{private}u->%{private}s.", ntohl(servip), pSerIp);
        free(pSerIp);
        pSerIp = NULL;
    }
    return SendToDhcpPacket(&packet, INADDR_ANY, INADDR_BROADCAST, m_cltCnf.ifaceIndex, (uint8_t *)MAC_BCAST_ADDR);
}

/* Unicast or broadcast dhcp request packet, request to extend the lease from the dhcp server. */
int DhcpClientStateMachine::DhcpRenew(uint32_t transid, uint32_t clientip, uint32_t serverip)
{
    DHCP_LOGI("DhcpRenew() enter, transid:%{public}u,clientip:%{public}u.", transid, clientip);

    struct DhcpPacket packet;
    if (memset_s(&packet, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket)) != EOK) {
        return -1;
    }

    /* Get packet header and common info. */
    if ((GetPacketHeaderInfo(&packet, DHCP_REQUEST) != DHCP_OPT_SUCCESS) ||
        (GetPacketCommonInfo(&packet) != DHCP_OPT_SUCCESS)) {
        return -1;
    }

    /* Get packet not common info. */
    packet.xid = transid;
    packet.ciaddr = clientip;
    AddParamaterRequestList(&packet);

    /* Begin broadcast or unicast dhcp request packet. */
    if (serverip == 0) {
        DHCP_LOGI("DhcpRenew() rebind, begin broadcast req packet");
        return SendToDhcpPacket(&packet, INADDR_ANY, INADDR_BROADCAST, m_cltCnf.ifaceIndex, (uint8_t *)MAC_BCAST_ADDR);
    }
    DHCP_LOGI("DhcpRenew() renew, begin unicast request packet");
    return SendDhcpPacket(&packet, clientip, serverip);
}

/* Unicast dhcp release packet, releasing an ip address in Use from the dhcp server. */
int DhcpClientStateMachine::DhcpRelease(uint32_t clientip, uint32_t serverip)
{
    DHCP_LOGI("DhcpRelease enter, clientip:%{private}u.", clientip);
    struct DhcpPacket packet;
    if (memset_s(&packet, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket)) != EOK) {
        return -1;
    }

    /* Get packet header and common info. */
    if ((GetPacketHeaderInfo(&packet, DHCP_RELEASE) != DHCP_OPT_SUCCESS) ||
        (GetPacketCommonInfo(&packet) != DHCP_OPT_SUCCESS)) {
        return -1;
    }

    /* Get packet not common info. */
    packet.xid = GetRandomId();
    AddOptValueToOpts(packet.options, REQUESTED_IP_ADDRESS_OPTION, clientip);
    AddOptValueToOpts(packet.options, SERVER_IDENTIFIER_OPTION, serverip);
    DHCP_LOGI("DhcpRelease begin unicast release packet, clientip:%{private}u, serverip:%{private}u", clientip,
        serverip);
    return SendDhcpPacket(&packet, clientip, serverip);
}

#ifndef OHOS_ARCH_LITE
using TimeOutCallback = std::function<void()>;
void DhcpClientStateMachine::GetIpTimerCallback()
{
    DHCP_LOGI("enter GetIpTimerCallback, getIpTimerId:%{public}u timeoutExit:%{public}d", getIpTimerId,
        m_cltCnf.timeoutExit);
    if (m_cltCnf.timeoutExit) {
        DHCP_LOGE("GetIpTimerCallback return!");
        return;
    }
    StopGetIpTimer();
    PublishDhcpIpv4ResultEvent(PUBLISH_CODE_TIMEOUT, "get dhcp result timeout!", m_ifName.c_str());
}

void DhcpClientStateMachine::StartGetIpTimer()
{
    DHCP_LOGI("StartGetIpTimer getIpTimerId:%{public}u", getIpTimerId);
    std::unique_lock<std::mutex> lock(getIpTimerMutex);
    if (getIpTimerId == 0) {
        TimeOutCallback timeoutCallback = std::bind(&DhcpClientStateMachine::GetIpTimerCallback, this);
        DhcpTimer::GetInstance()->Register(timeoutCallback, getIpTimerId, DhcpTimer::DEFAULT_TIMEROUT);
        DHCP_LOGI("StartGetIpTimer success! getIpTimerId:%{public}u", getIpTimerId);
    }
    return;
}

void DhcpClientStateMachine::StopGetIpTimer()
{
    DHCP_LOGI("StopGetIpTimer getIpTimerId:%{public}u", getIpTimerId);
    std::unique_lock<std::mutex> lock(getIpTimerMutex);
    DhcpTimer::GetInstance()->UnRegister(getIpTimerId);
    getIpTimerId = 0;
    return;
}

DhcpClientStateMachine::DhcpTimer * DhcpClientStateMachine::DhcpTimer::GetInstance()
{
    static DhcpTimer instance;
    return &instance;
}

DhcpClientStateMachine::DhcpTimer::DhcpTimer() : timer_(std::make_unique<Utils::Timer>("DhcpGetIpTimer"))
{
    timer_->Setup();
}

DhcpClientStateMachine::DhcpTimer::~DhcpTimer()
{
    if (timer_) {
        timer_->Shutdown(true);
    }
}

EnumErrCode DhcpClientStateMachine::DhcpTimer::Register(const TimerCallback &callback, uint32_t &outTimerId,
    uint32_t interval, bool once)
{
    if (timer_ == nullptr) {
        DHCP_LOGI("timer_ is nullptr");
        return DHCP_OPT_FAILED;
    }

    uint32_t ret = timer_->Register(callback, interval, once);
    if (ret == Utils::TIMER_ERR_DEAL_FAILED) {
        DHCP_LOGI("Register timer failed");
        return DHCP_OPT_FAILED;
    }
    outTimerId = ret;
    return DHCP_OPT_SUCCESS;
}

void DhcpClientStateMachine::DhcpTimer::UnRegister(uint32_t timerId)
{
    if (timerId == 0) {
        DHCP_LOGI("timerId is 0, no register timer");
        return;
    }

    if (timer_ == nullptr) {
        DHCP_LOGI("timer_ is nullptr");
        return;
    }
    timer_->Unregister(timerId);
    return;
}
#endif
}  // namespace DHCP
}  // namespace OHOS
