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
#include "dhcp_common_utils.h"
#include "dhcp_result.h"
#include "dhcp_result_store_manager.h"
#include "dhcp_options.h"
#include "dhcp_socket.h"
#include "dhcp_function.h" 
#include "dhcp_logger.h"
#include "dhcp_thread.h"

#ifndef OHOS_ARCH_LITE
#include "dhcp_system_timer.h"
#endif

#ifdef INIT_LIB_ENABLE
#include "parameter.h"
#endif
DEFINE_DHCPLOG_DHCP_LABEL("DhcpIpv4");

namespace OHOS {
namespace DHCP {
constexpr uint32_t FAST_ARP_DETECTION_TIME_MS = 50;
constexpr uint32_t SLOW_ARP_DETECTION_TIME_MS = 80;
constexpr uint32_t SLOW_ARP_TOTAL_TIME_MS = 4 * 1000;
constexpr uint32_t SLOW_ARP_DETECTION_TRY_CNT = 2;
constexpr uint32_t RATE_S_MS = 1000;
constexpr int DHCP_IP_TYPE_A = 128;
constexpr int DHCP_IP_TYPE_B = 192;
constexpr int DHCP_IP_TYPE_C = 224;

DhcpClientStateMachine::DhcpClientStateMachine(std::string ifname) :
    m_dhcp4State(DHCP_STATE_INIT),
    m_sockFd(-1),
    m_resendTimer(0),
    m_sentPacketNum(0),
    m_timeoutTimestamp(0),
    m_renewalTimestamp(0),
    m_renewalTimestampBoot(0),
    m_leaseTime(0),
    m_renewalSec(0),
    m_rebindSec(0),
    m_requestedIp4(0),
    m_serverIp4(0),
    m_socketMode(SOCKET_MODE_INVALID),
    m_transID(0),
    m_ifName(ifname),
    ipv4Thread_(nullptr),
    m_slowArpDetecting(false),
    firstSendPacketTime_(0)
{
#ifndef OHOS_ARCH_LITE
    m_slowArpTaskId =0 ;
    getIpTimerId = 0;
    renewDelayTimerId = 0;
    rebindDelayTimerId = 0;
    remainingDelayTimerId = 0;
#endif
    m_cltCnf.ifaceIndex = 0;
    threadExit_ = true;
    m_cltCnf.ifaceIpv4 = 0;
    m_cltCnf.getMode = DHCP_IP_TYPE_NONE;
    m_cltCnf.isIpv6 = false;
    m_slowArpCallback = [this](bool isReachable) { this->SlowArpDetectCallback(isReachable); };
    DHCP_LOGI("DhcpClientStateMachine()");
    ipv4Thread_ = std::make_unique<DhcpThread>("InnerIpv4Thread");
}

DhcpClientStateMachine::~DhcpClientStateMachine()
{
    DHCP_LOGI("~DhcpClientStateMachine()");
    if (ipv4Thread_) {
        DHCP_LOGI("~DhcpClientStateMachine ipv4Thread_ reset!");
        ipv4Thread_.reset();
    }
}

int DhcpClientStateMachine::InitSignalHandle()
{
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, m_sigSockFds) != 0) {
        DHCP_LOGE("InitSignalHandle socketpair m_sigSockFds failed, error:%{public}d", errno);
        return DHCP_OPT_FAILED;
    }
    DHCP_LOGI("InitSignalHandle socketpair 0:%{public}d 1:%{public}d", m_sigSockFds[0], m_sigSockFds[1]);
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::CloseSignalHandle()
{
    for (int i = 0; i < NUMBER_TWO; i++) {
        DHCP_LOGI("CloseSignalHandle m_sigSockFds, i:%{public}d %{public}d", i, m_sigSockFds[i]);
        close(m_sigSockFds[i]);
    }
    return DHCP_OPT_SUCCESS;
}

void DhcpClientStateMachine::RunGetIPThreadFunc(const DhcpClientStateMachine &instance)
{
    DHCP_LOGI("RunGetIPThreadFunc begin.");
    if ((m_cltCnf.getMode == DHCP_IP_TYPE_ALL) || (m_cltCnf.getMode == DHCP_IP_TYPE_V4)) {
        threadExit_ = false;
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
    m_slowArpDetecting = false;
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::StartIpv4Type(const std::string &ifname, bool isIpv6, ActionMode action)
{
    DHCP_LOGI("StartIpv4Type ifname:%{public}s isIpv6:%{public}d threadExit:%{public}d action:%{public}d",
        ifname.c_str(), isIpv6, threadExit_.load(), action);
    m_ifName = ifname;
    m_action = action;
#ifndef OHOS_ARCH_LITE
    StopTimer(getIpTimerId);
    StartTimer(TIMER_GET_IP, getIpTimerId, DhcpTimer::DEFAULT_TIMEROUT, true);
#endif
    if (InitConfig(ifname, isIpv6) != DHCP_OPT_SUCCESS) {
        DHCP_LOGE("StartIpv4Type InitConfig failed!");
        return DHCP_OPT_FAILED;
    }
    if ((m_action == ACTION_START_NEW) || (m_action == ACTION_START_OLD)) {
        InitStartIpv4Thread(ifname, isIpv6);
    } else {
        DHCP_LOGI("StartIpv4Type not supported m_action:%{public}d", m_action);
    }
    return DHCP_OPT_SUCCESS;
}


int DhcpClientStateMachine::InitStartIpv4Thread(const std::string &ifname, bool isIpv6)
{
    DHCP_LOGI("InitStartIpv4Thread, ifname:%{public}s, isIpv6:%{public}d, threadExit:%{public}d", ifname.c_str(),
        isIpv6, threadExit_.load());
    if (!threadExit_) {
        DHCP_LOGI("InitStartIpv4Thread ipv4Thread is run!");
        return DHCP_OPT_FAILED;
    }
    InitSignalHandle();
    if (!ipv4Thread_) {
        DHCP_LOGI("InitStartIpv4Thread make_unique ipv4Thread_");
        ipv4Thread_ = std::make_unique<DhcpThread>("InnerIpv4Thread");
    }
    std::function<void()> func = [this]() { RunGetIPThreadFunc(std::ref(*this)); };
    int delayTime = 0;
    bool result = ipv4Thread_->PostAsyncTask(func, delayTime);
    if (!result) {
        DHCP_LOGE("InitStartIpv4Thread ipv4Thread_ RunGetIPThreadFunc failed!");
        return DHCP_OPT_FAILED;
    }
    DHCP_LOGE("InitStartIpv4Thread ipv4Thread_ RunGetIPThreadFunc ok");
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
    m_cltCnf.isIpv6 = isIpv6;
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
    std::string cIp = Ip4IntConvertToStr(m_cltCnf.ifaceIpv4, true);
    if (cIp.empty()) {
        DHCP_LOGE("GetClientNetworkInfo() Ip4IntConvertToStr m_cltCnf.ifaceIpv4 failed!");
        return DHCP_OPT_FAILED;
    }
    DHCP_LOGI("GetClientNetworkInfo() GetLocalIp ifaceName:%{public}s -> ifaceIpv4:%{private}u - %{private}s.",
        m_cltCnf.ifaceName, m_cltCnf.ifaceIpv4, cIp.c_str());
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::StartIpv4(void)
{
    DHCP_LOGI("StartIpv4 function start");
    int nRet, nMaxFds;
    fd_set readfds;
    fd_set exceptfds;
    struct timeval timeout;
    time_t curTimestamp;
 
    if ((m_action != ACTION_RENEW_T1) && (m_action != ACTION_RENEW_T2) && (m_action != ACTION_RENEW_T3)) {
         DhcpInit();
    }
    firstSendPacketTime_ = 0;
    DHCP_LOGI("StartIpv4 m_dhcp4State:%{public}d m_action:%{public}d", m_dhcp4State, m_action);
    for (; ;) {
        if (threadExit_) {
            DHCP_LOGI("StartIpv4 send packet timed out, now break!");
            break;
        }
        
        FD_ZERO(&readfds);
        FD_ZERO(&exceptfds);
        timeout.tv_sec = m_timeoutTimestamp - time(NULL);
        timeout.tv_usec = (GetRandomId() % USECOND_CONVERT) * USECOND_CONVERT;
        InitSocketFd();

        if (m_sockFd >= 0) {
            FD_SET(m_sockFd, &readfds);
            FD_SET(m_sockFd, &exceptfds);
        }
        FD_SET(m_sigSockFds[0], &readfds);
        FD_SET(m_sigSockFds[0], &exceptfds);
        FD_SET(m_sigSockFds[1], &exceptfds);
        DHCP_LOGD("StartIpv4 m_sigSockFds[0]:%{public}d m_sigSockFds[1]:%{public}d m_sentPacketNum:%{public}d",
            m_sigSockFds[0], m_sigSockFds[1], m_sentPacketNum);

        if (timeout.tv_sec <= 0) {
            DHCP_LOGI("StartIpv4 already timed out, need send or resend packet...");
            nRet = 0;
        } else {
            nMaxFds = (m_sigSockFds[0] > m_sockFd) ? m_sigSockFds[0] : m_sockFd;
            DHCP_LOGD("StartIpv4 waiting on select, m_dhcp4State:%{public}d", m_dhcp4State);
            nRet = select(nMaxFds + 1, &readfds, NULL, &exceptfds, &timeout);
            DHCP_LOGD("StartIpv4 select nMaxFds:%{public}d,m_sigSockFds[0]:%{public}d,m_sigSockFds[1]:%{public}d",
                nMaxFds, m_sigSockFds[0], m_sigSockFds[1]);
        }

        if (nRet < 0) {
            if ((nRet == -1) && (errno == EINTR)) {
                DHCP_LOGI("StartIpv4 select err:%{public}d, a signal was caught!", errno);
            } else {
                DHCP_LOGD("StartIpv4 failed, select maxFds:%{public}d error:%{public}d!", nMaxFds, errno);
            }
            continue;
        }
        curTimestamp = time(NULL);
        if (nRet == 0) {
            DhcpRequestHandle(curTimestamp);
        } else if (FD_ISSET(m_sigSockFds[0], &readfds)) {
            SignalReceiver();
        } else if ((m_socketMode != SOCKET_MODE_INVALID) && FD_ISSET(m_sockFd, &readfds)) {
            DhcpResponseHandle(curTimestamp);
        } else {
            DHCP_LOGI("StartIpv4 nRet:%{public}d, m_socketMode:%{public}d, continue select...", nRet, m_socketMode);
        }
        if ((m_socketMode != SOCKET_MODE_INVALID) && (FD_ISSET(m_sigSockFds[0], &exceptfds) ||
            FD_ISSET(m_sigSockFds[1], &exceptfds))) {
            DHCP_LOGI("StartIpv4 exceptfds close socketpair, fds[0]:%{public}d fds[1]:%{public}d m_sockFd:%{public}d",
                m_sigSockFds[0], m_sigSockFds[1], m_sockFd);
            CloseSignalHandle();
            InitSignalHandle();
        } else if ((m_socketMode != SOCKET_MODE_INVALID) && FD_ISSET(m_sockFd, &exceptfds)) {
            DHCP_LOGI("StartIpv4 exceptfds close m_sockFd, fds[0]:%{public}d fds[1]:%{public}d m_sockFd:%{public}d",
                m_sigSockFds[0], m_sigSockFds[1], m_sockFd);
            close(m_sockFd);
            m_sockFd = -1;
        }
    }
    return threadExit_ ? ExitIpv4() : DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::ExitIpv4(void)
{
    CloseSignalHandle();
    DHCP_LOGI("ExitIpv4 threadExit:%{public}d", threadExit_.load());
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::StopIpv4(void)
{
    DHCP_LOGI("StopIpv4 threadExit:%{public}d", threadExit_.load());
    if (!threadExit_) {
        SetSocketMode(SOCKET_MODE_INVALID);
        threadExit_ = true;
        m_slowArpDetecting = false;
        m_conflictCount = 0;
        int signum = SIG_STOP;
        if (send(m_sigSockFds[1], &signum, sizeof(signum), MSG_DONTWAIT) < 0) { // SIG_STOP SignalReceiver
            DHCP_LOGI("StopIpv4 send m_sigSockFds failed.");
        }
#ifndef OHOS_ARCH_LITE
        StopTimer(getIpTimerId);
        DHCP_LOGI("UnRegister slowArpTask: %{public}u", m_slowArpTaskId);
        DhcpTimer::GetInstance()->UnRegister(m_slowArpTaskId);
        m_slowArpTaskId = 0;
#endif
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
    m_conflictCount = 0;
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
    threadExit_ = true;
}

void DhcpClientStateMachine::InitSocketFd(void)
{
    DHCP_LOGD("InitSocketFd fd:%{public}d,mode:%{public}d,index:%{public}d,name:%{public}s,timeoutTimestamp:%{public}u",
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
    if (m_sockFd >= 0) {
        close(m_sockFd);
    }
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
    const uint8_t arrReqCode[DHCP_REQ_CODE_NUM] = {
        SUBNET_MASK_OPTION,
        ROUTER_OPTION,
        DOMAIN_NAME_SERVER_OPTION,
        DOMAIN_NAME_OPTION,
        INTERFACE_MTU_OPTION,
        BROADCAST_ADDRESS_OPTION,
        IP_ADDRESS_LEASE_TIME_OPTION,
        RENEWAL_TIME_VALUE_OPTION,
        REBINDING_TIME_VALUE_OPTION,
        VENDOR_SPECIFIC_INFO_OPTION,
        CAPTIVE_PORTAL_OPTION,
        IPV6_ONLY_PREFERRED_OPTION
    };

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
        m_timeoutTimestamp = static_cast<uint32_t>(timestamp) + TIMEOUT_MORE_WAIT_SEC;
        m_sentPacketNum = 0;
        threadExit_ = true;
        return;
    }
    
    if (m_sentPacketNum == 0) {
        m_transID = GetRandomId();
    }

    /* Broadcast dhcp discover packet. */
    DhcpDiscover(m_transID, m_requestedIp4);
    m_dhcp4State = DHCP_STATE_SELECTING;

    uint32_t uTimeoutSec = TIMEOUT_WAIT_SEC << (m_sentPacketNum > MAX_WAIT_TIMES ? MAX_WAIT_TIMES : m_sentPacketNum);
    if ((uTimeoutSec > DHCP_FAILE_TIMEOUT_THR) && (m_action != ACTION_RENEW_T3)) {
        TryCachedIp();
    }
    m_timeoutTimestamp = static_cast<uint32_t>(timestamp) + uTimeoutSec;
    DHCP_LOGI("InitSelecting() DhcpDiscover m_sentPacketNum:%{public}u,timeoutSec:%{public}u,timestamp:%{public}u.",
        m_sentPacketNum,
        uTimeoutSec,
        m_timeoutTimestamp);
    m_sentPacketNum++;
}

void DhcpClientStateMachine::AddParamaterRebootList(struct DhcpPacket *packet)
{
    int end = GetEndOptionIndex(packet->options);
    int i;
    int len = 0;
    const uint8_t arrReqCode[DHCP_REQ_CODE_NUM] = {
        SUBNET_MASK_OPTION,
        ROUTER_OPTION,
        DOMAIN_NAME_SERVER_OPTION,
        DOMAIN_NAME_OPTION,
        INTERFACE_MTU_OPTION,
        BROADCAST_ADDRESS_OPTION,
        IP_ADDRESS_LEASE_TIME_OPTION,
        RENEWAL_TIME_VALUE_OPTION,
        REBINDING_TIME_VALUE_OPTION,
        VENDOR_SPECIFIC_INFO_OPTION,
        CAPTIVE_PORTAL_OPTION,
        IPV6_ONLY_PREFERRED_OPTION
    };

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
    DHCP_LOGI("DhcpReboot send request, transid:%{public}u, clientip:%{public}s", transid,
        IntIpv4ToAnonymizeStr(reqip).c_str());
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
    packet.xid = transid;
    /* Set Reboot Request seconds elapsed. */
    SetSecondsElapsed(&packet);
    AddClientIdToOpts(&packet); // 61
    AddOptValueToOpts(packet.options, REQUESTED_IP_ADDRESS_OPTION, reqip); //50
    AddOptValueToOpts(packet.options, MAXIMUM_DHCP_MESSAGE_SIZE_OPTION, MAX_MSG_SIZE); //57
    AddHostNameToOpts(&packet); // 60 12
    AddParamaterRebootList(&packet); // 55
    DHCP_LOGI("DhcpReboot begin broadcast dhcp request packet");
    return SendToDhcpPacket(&packet, INADDR_ANY, INADDR_BROADCAST, m_cltCnf.ifaceIndex, (uint8_t *)MAC_BCAST_ADDR);
}

void DhcpClientStateMachine::SendReboot(uint32_t targetIp, time_t timestamp)
{
    if (m_sentPacketNum >= NUMBER_TWO) {
        m_dhcp4State = DHCP_STATE_INIT;
        SetSocketMode(SOCKET_MODE_RAW);
        m_sentPacketNum = 0;
        m_timeoutTimestamp = static_cast<uint32_t>(timestamp);
        return;
    }

    uint32_t uTimeoutSec = TIMEOUT_WAIT_SEC << (m_sentPacketNum > MAX_WAIT_TIMES ? MAX_WAIT_TIMES : m_sentPacketNum);
    m_timeoutTimestamp = static_cast<uint32_t>(timestamp) + uTimeoutSec;
    m_requestedIp4 = targetIp;
    DhcpReboot(m_transID, m_requestedIp4);
    DHCP_LOGI("SendReboot() SendReboot m_sentPacketNum:%{public}u,timeoutSec:%{public}u,timeoutTimestamp:%{public}u.",
        m_sentPacketNum,
        uTimeoutSec,
        m_timeoutTimestamp);
    m_sentPacketNum++;
}

void DhcpClientStateMachine::Reboot(time_t timestamp)
{
    if (strncmp(m_cltCnf.ifaceName, "wlan", NUMBER_FOUR) != 0) {
        DHCP_LOGI("ifaceName is not wlan, not Reboot");
        return;
    }

    if (m_routerCfg.bssid.empty()) {
        DHCP_LOGE("m_routerCfg.bssid is empty, no need reboot");
        return;
    }

    IpInfoCached ipInfoCached;
    if (GetCachedDhcpResult(m_routerCfg.bssid, ipInfoCached) != 0) {
        DHCP_LOGE("not find cache ip for m_routerCfg.bssid");
        return;
    }
    if (static_cast<int64_t>(timestamp) > ipInfoCached.absoluteLeasetime) {
        DHCP_LOGE("Lease has expired, need get new ip");
        return;
    }
    
    uint32_t lastAssignedIpv4Addr = 0;
    if (!Ip4StrConToInt(ipInfoCached.ipResult.strYiaddr, &lastAssignedIpv4Addr, false)) {
        DHCP_LOGE("lastAssignedIpv4Addr get failed");
        return;
    }
    
    if (lastAssignedIpv4Addr != 0) {
        m_transID = GetRandomId();
        m_dhcp4State = DHCP_STATE_INITREBOOT;
        m_sentPacketNum = 0;
        SendReboot(lastAssignedIpv4Addr, timestamp);
    }
}

void DhcpClientStateMachine::Requesting(time_t timestamp)
{
    if (m_sentPacketNum > TIMEOUT_TIMES_MAX) {
        /* Send packet timed out, now enter init state. */
        m_dhcp4State = DHCP_STATE_INIT;
        SetSocketMode(SOCKET_MODE_RAW);
        m_sentPacketNum = 0;
        m_timeoutTimestamp = static_cast<uint32_t>(timestamp);
        return;
    }

    if (m_dhcp4State == DHCP_STATE_RENEWED) {
        /* Unicast dhcp request packet in the renew state. */
        DhcpRenew(m_transID, m_requestedIp4, m_serverIp4);
    } else {
        /* Broadcast dhcp request packet in the requesting state. */
        DhcpRequest(m_transID, m_requestedIp4, m_serverIp4);
    }

    uint32_t uTimeoutSec = TIMEOUT_WAIT_SEC << (m_sentPacketNum > MAX_WAIT_TIMES ? MAX_WAIT_TIMES : m_sentPacketNum);
    if (uTimeoutSec > DHCP_FAILE_TIMEOUT_THR) {
        TryCachedIp();
    }
    m_timeoutTimestamp = static_cast<uint32_t>(timestamp) + uTimeoutSec;
    DHCP_LOGI("Requesting() DhcpRequest m_sentPacketNum:%{public}u,timeoutSec:%{public}u,timeoutTimestamp:%{public}u.",
        m_sentPacketNum,
        uTimeoutSec,
        m_timeoutTimestamp);

    m_sentPacketNum++;
}

void DhcpClientStateMachine::Renewing(time_t timestamp)
{
    if (m_dhcp4State == DHCP_STATE_RENEWING) {
        DhcpRenew(m_transID, m_requestedIp4, m_serverIp4);
    }
    uint32_t uTimeoutSec = TIMEOUT_WAIT_SEC << (m_sentPacketNum > MAX_WAIT_TIMES ? MAX_WAIT_TIMES : m_sentPacketNum);
    m_timeoutTimestamp = static_cast<uint32_t>(timestamp) + uTimeoutSec;
    m_sentPacketNum++;
    DHCP_LOGI("Renewing sentPacketNum:%{public}u timeoutSec:%{public}u timeoutTimestamp:%{public}u state:%{public}u",
        m_sentPacketNum, uTimeoutSec, m_timeoutTimestamp, m_dhcp4State);
}

void DhcpClientStateMachine::Rebinding(time_t timestamp)
{
    if (m_dhcp4State == DHCP_STATE_REBINDING) {
        DhcpRenew(m_transID, m_requestedIp4, 0);
    }
    uint32_t uTimeoutSec = TIMEOUT_WAIT_SEC << (m_sentPacketNum > MAX_WAIT_TIMES ? MAX_WAIT_TIMES : m_sentPacketNum);
    m_timeoutTimestamp = static_cast<uint32_t>(timestamp) + uTimeoutSec;
    m_sentPacketNum++;
    DHCP_LOGI("Rebinding sentPacketNum:%{public}u timeoutSec:%{public}u timeoutTimestamp:%{public}u state:%{public}u",
        m_sentPacketNum, uTimeoutSec, m_timeoutTimestamp, m_dhcp4State);
}

void DhcpClientStateMachine::Declining(time_t timestamp)
{
    DHCP_LOGI("Declining() m_conflictCount is :%{public}u", m_conflictCount);
    if (++m_conflictCount > MAX_CONFLICTS_COUNT) {
        if (PublishDhcpResultEvent(m_cltCnf.ifaceName, PUBLISH_CODE_SUCCESS, &m_dhcpIpResult) != DHCP_OPT_SUCCESS) {
            PublishDhcpResultEvent(m_cltCnf.ifaceName, PUBLISH_CODE_FAILED, &m_dhcpIpResult);
            DHCP_LOGE("Declining publish dhcp result failed!");
        }
        SaveIpInfoInLocalFile(m_dhcpIpResult);
        StopIpv4();
        m_dhcp4State = DHCP_STATE_BOUND;
        m_sentPacketNum = 0;
        m_resendTimer = 0;
        m_timeoutTimestamp = static_cast<uint32_t>(timestamp);
        return;
    }
    m_timeoutTimestamp = static_cast<uint32_t>(timestamp) + TIMEOUT_WAIT_SEC;
    DhcpDecline(m_transID, m_requestedIp4, m_serverIp4);
    m_dhcp4State = DHCP_STATE_INIT;
    m_sentPacketNum = 0;
}

void DhcpClientStateMachine::DhcpRequestHandle(time_t timestamp)
{
    DHCP_LOGI("DhcpRequestHandle state:%{public}d[init-0 selecting-1 requesting-2 bound-3 renewing-4 rebinding-5 "
        "initreboot-6 released-7 renewed-8 fastarp-9 slowarp-10 decline-11]", m_dhcp4State);
    switch (m_dhcp4State) {
        case DHCP_STATE_INIT:
        case DHCP_STATE_SELECTING:
            InitSelecting(timestamp);
            break;
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RENEWED:
            Requesting(timestamp);
            break;
        case DHCP_STATE_BOUND:
            /* Now the renewal time run out, ready to enter renewing state. */
            m_dhcp4State = DHCP_STATE_RENEWING;
            SetSocketMode(SOCKET_MODE_KERNEL);
            /* fall through */
        case DHCP_STATE_RENEWING:
            Renewing(timestamp);
            break;
        case DHCP_STATE_REBINDING:
            Rebinding(timestamp);
            break;
        case DHCP_STATE_INITREBOOT:
            SendReboot(m_requestedIp4, timestamp);
            break;
        case DHCP_STATE_RELEASED:
            /* Ensure that the function select() is always blocked and don't need to receive ip from dhcp server. */
            DHCP_LOGI("DhcpRequestHandle() DHCP_STATE_RELEASED-7 m_timeoutTimestamp:%{public}d", m_timeoutTimestamp);
            m_timeoutTimestamp = SIGNED_INTEGER_MAX;
            break;
        case DHCP_STATE_FAST_ARP:
            FastArpDetect();
            break;
        case DHCP_STATE_SLOW_ARP:
            SlowArpDetect(timestamp);
            break;
        case DHCP_STATE_DECLINE:
            Declining(timestamp);
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
        DHCP_LOGE("DhcpOfferPacketHandle() type:%{public}d GetDhcpOptionUint32 SERVER_IDENTIFIER_OPTION failed!",
            type);
        return;
    }

    m_transID = packet->xid;
    m_requestedIp4 = packet->yiaddr;
    m_serverIp4 = htonl(u32Data);

    std::string pReqIp = Ip4IntConvertToStr(m_requestedIp4, false);
    if (pReqIp.length() > 0) {
        DHCP_LOGI(
            "DhcpOfferPacketHandle() receive DHCP_OFFER, xid:%{public}u, requestIp: host %{private}u->%{private}s.",
            m_transID,
            ntohl(m_requestedIp4),
            pReqIp.c_str());
    }
    std::string pSerIp = Ip4IntConvertToStr(m_serverIp4, false);
    if (pSerIp.length() > 0) {
        DHCP_LOGI("DhcpOfferPacketHandle() receive DHCP_OFFER, serverIp: host %{private}u->%{private}s.",
            ntohl(m_serverIp4),
            pSerIp.c_str());
    }

    /* Receive dhcp offer packet finished, next send dhcp request packet. */
    m_dhcp4State = DHCP_STATE_REQUESTING;
    m_sentPacketNum = 0;
    m_timeoutTimestamp = static_cast<uint32_t>(timestamp);
}

void DhcpClientStateMachine::ParseNetworkServerIdInfo(const struct DhcpPacket *packet, struct DhcpIpResult *result)
{
    if ((packet == nullptr) || (result == nullptr)) {
        DHCP_LOGE("ParseNetworkServerIdInfo packet == nullptr or result == nullptr!");
        return;
    }
    uint32_t u32Data = 0;
    if (!GetDhcpOptionUint32(packet, SERVER_IDENTIFIER_OPTION, &u32Data)) {
        DHCP_LOGE("ParseNetworkServerIdInfo SERVER_IDENTIFIER_OPTION failed!");
    } else {
        m_serverIp4 = htonl(u32Data);
        std::string pSerIp = Ip4IntConvertToStr(m_serverIp4, false);
        if (pSerIp.length() > 0) {
            DHCP_LOGI("ParseNetworkServerIdInfo recv DHCP_ACK 54, serid: %{private}u->%{private}s.",
                u32Data, pSerIp.c_str());
            if (strncpy_s(result->strOptServerId, INET_ADDRSTRLEN, pSerIp.c_str(), INET_ADDRSTRLEN - 1) != EOK) {
                return;
            }
        }
    }
}

void DhcpClientStateMachine::SetIpv4DefaultDns(struct DhcpIpResult *result)
{
    if (result == nullptr) {
        DHCP_LOGE("SetIpv4DefaultDns result == nullptr!");
        return;
    }
    if (strncpy_s(result->strOptDns1, INET_ADDRSTRLEN, DEFAULT_IPV4_DNS_PRI, INET_ADDRSTRLEN - 1) != EOK) {
        DHCP_LOGE("SetIpv4DefaultDns strncpy_s defult strOptDns1 Failed.");
        return;
    }
    if (strncpy_s(result->strOptDns2, INET_ADDRSTRLEN, DEFAULT_IPV4_DNS_SEC, INET_ADDRSTRLEN - 1) != EOK) {
        DHCP_LOGE("SetIpv4DefaultDns strncpy_s defult strOptDns2 Failed.");
        return;
    }
    result->dnsAddr.clear();
    result->dnsAddr.push_back(DEFAULT_IPV4_DNS_PRI);
    result->dnsAddr.push_back(DEFAULT_IPV4_DNS_SEC);
    DHCP_LOGI("SetIpv4DefaultDns make defult dns!");
}

void DhcpClientStateMachine::ParseNetworkDnsInfo(const struct DhcpPacket *packet, struct DhcpIpResult *result)
{
    if ((packet == nullptr) || (result == nullptr)) {
        DHCP_LOGE("ParseNetworkDnsInfo error, packet == nullptr or result == nullptr!");
        return;
    }
    size_t len = 0;
    const uint8_t *p = GetDhcpOption(packet, DOMAIN_NAME_SERVER_OPTION, &len);
    if (p == nullptr) {
        DHCP_LOGE("ParseNetworkDnsInfo nullptr!");
        SetIpv4DefaultDns(result);
        return;
    }
    uint32_t uData = 0;
    int count = 0;
    if ((len < (ssize_t)sizeof(uData)) || (len % (ssize_t)sizeof(uData) != 0)) {
        DHCP_LOGE("ParseNetworkDnsInfo failed, len:%{public}zu is not %{public}zu * n, code:%{public}d!",
            len, sizeof(uData), DOMAIN_NAME_SERVER_OPTION);
        SetIpv4DefaultDns(result);
        return;
    }
    DHCP_LOGI("ParseNetworkDnsInfo len:%{public}zu count:%{public}d", len, count);
    while (len >= (ssize_t)sizeof(uData)) {
        uData = 0;
        if (memcpy_s(&uData, sizeof(uData), p, sizeof(uData)) != EOK) {
            DHCP_LOGE("ParseNetworkDnsInfo memcpy_s failed!");
            continue;
        }
        if (uData > 0) {
            ParseNetworkDnsValue(result, uData, len, count);
        }
        p += sizeof(uData);
        len -= sizeof(uData);
    }
    return;
}

void DhcpClientStateMachine::ParseNetworkDnsValue(struct DhcpIpResult *result, uint32_t uData, size_t &len, int &count)
{
    if (result == nullptr) {
        DHCP_LOGE("ParseNetworkDnsValue error, result == nullptr!");
        return;
    }
    uint32_t u32Data = ntohl(uData);
    std::string pDnsIp = Ip4IntConvertToStr(u32Data, true);
    if (pDnsIp.length() > 0) {
        count++;
        result->dnsAddr.push_back(pDnsIp);
        DHCP_LOGI("ParseNetworkDnsInfo recv DHCP_ACK 6, dns:%{private}u->%{private}s len:%{public}zu %{public}d",
            u32Data, pDnsIp.c_str(), len, count);
        if (count == DHCP_DNS_FIRST) {
            if (strncpy_s(result->strOptDns1, INET_ADDRSTRLEN, pDnsIp.c_str(), INET_ADDRSTRLEN - 1) != EOK) {
                DHCP_LOGE("ParseNetworkDnsInfo strncpy_s strOptDns1 Failed.");
                return;
            }
        } else if (count == DHCP_DNS_SECOND) {
            if (strncpy_s(result->strOptDns2, INET_ADDRSTRLEN, pDnsIp.c_str(), INET_ADDRSTRLEN - 1) != EOK) {
                DHCP_LOGE("ParseNetworkDnsInfo strncpy_s strOptDns2 Failed.");
                return;
            }
        }
    } else {
        DHCP_LOGI("ParseNetworkDnsInfo pDnsIp is nullptr, len:%{public}zu %{public}d ", len, count);
    }
}

void DhcpClientStateMachine::SetDefaultNetMask(struct DhcpIpResult *result)
{
    if (result == nullptr) {
        DHCP_LOGE("SetDefaultNetMask result is nullptr!");
        return;
    }
    std::string strYiaddr = result->strYiaddr;
    std::string strNetmask = result->strOptSubnet;
    size_t pos = strYiaddr.find(".");
    std::string yiaddrTmp = strYiaddr.substr(0, pos);
    int firstByte = static_cast<int>(CheckDataLegal(yiaddrTmp, DECIMAL_NOTATION));
    if ((!strYiaddr.empty()) && strNetmask.empty()) {
        if (firstByte < DHCP_IP_TYPE_A) {
            if (strncpy_s(result->strOptSubnet, INET_ADDRSTRLEN, "255.0.0.0", INET_ADDRSTRLEN - 1) != EOK) {
                DHCP_LOGE("SetDefaultNetMask strncpy_s failed!");
                return;
            }
        } else if (firstByte < DHCP_IP_TYPE_B) {
            if (strncpy_s(result->strOptSubnet, INET_ADDRSTRLEN, "255.255.0.0", INET_ADDRSTRLEN - 1) != EOK) {
                DHCP_LOGE("SetDefaultNetMask strncpy_s failed!");
                return;
            }
        } else if (firstByte < DHCP_IP_TYPE_C) {
            if (strncpy_s(result->strOptSubnet, INET_ADDRSTRLEN, "255.255.255.0", INET_ADDRSTRLEN - 1) != EOK) {
                DHCP_LOGE("SetDefaultNetMask strncpy_s failed!");
                return;
            }
        } else {
            if (strncpy_s(result->strOptSubnet, INET_ADDRSTRLEN, "255.255.255.255", INET_ADDRSTRLEN - 1) != EOK) {
                DHCP_LOGE("SetDefaultNetMask strncpy_s failed!");
                return;
            }
        }
    }
}

void DhcpClientStateMachine::ParseNetworkInfo(const struct DhcpPacket *packet, struct DhcpIpResult *result)
{
    if ((packet == NULL) || (result == NULL)) {
        DHCP_LOGE("ParseNetworkInfo() error, packet == NULL or result == NULL!");
        return;
    }

    std::string pReqIp = Ip4IntConvertToStr(m_requestedIp4, false);
    if (pReqIp.length() > 0) {
        DHCP_LOGI("ParseNetworkInfo() recv DHCP_ACK yiaddr: %{private}u->%{public}s.",
            ntohl(m_requestedIp4), Ipv4Anonymize(pReqIp).c_str());
        if (strncpy_s(result->strYiaddr, INET_ADDRSTRLEN, pReqIp.c_str(), INET_ADDRSTRLEN - 1) != EOK) {
            DHCP_LOGI("ParseNetworkInfo() strncpy_s failed!");
            return;
        }
    }

    uint32_t u32Data = 0;
    if (GetDhcpOptionUint32(packet, SUBNET_MASK_OPTION, &u32Data)) {
        std::string pSubIp = Ip4IntConvertToStr(u32Data, true);
        if (pSubIp.length() > 0) {
            DHCP_LOGI("ParseNetworkInfo() recv DHCP_ACK 1, subnetmask: %{private}u->%{private}s.",
                u32Data, pSubIp.c_str());
            if (strncpy_s(result->strOptSubnet, INET_ADDRSTRLEN, pSubIp.c_str(), INET_ADDRSTRLEN - 1) != EOK) {
                DHCP_LOGE("strncpy_s strOptSubnet failed!");
                SetDefaultNetMask(result);
                return;
            }
        } else {
            DHCP_LOGE("Ip4IntConvertToStr() failed!");
            SetDefaultNetMask(result);
        }
    } else {
        DHCP_LOGE("GetDhcpOptionUint32() failed!");
        SetDefaultNetMask(result);
    }

    u32Data = 0;
    uint32_t u32Data2 = 0;
    if (GetDhcpOptionUint32n(packet, ROUTER_OPTION, &u32Data, &u32Data2)) {
        std::string pRouterIp = Ip4IntConvertToStr(u32Data, true);
        if (pRouterIp.length() > 0) {
            DHCP_LOGI("ParseNetworkInfo() recv DHCP_ACK 3, router1: %{private}u->%{private}s.",
                u32Data, pRouterIp.c_str());
            if (strncpy_s(result->strOptRouter1, INET_ADDRSTRLEN, pRouterIp.c_str(), INET_ADDRSTRLEN - 1) != EOK) {
                return;
            }
        }
        pRouterIp = Ip4IntConvertToStr(u32Data2, true);
        if ((u32Data2 > 0) && (pRouterIp.length() > 0)) {
            DHCP_LOGI("ParseNetworkInfo() recv DHCP_ACK 3, router2: %{private}u->%{private}s.",
                u32Data2, pRouterIp.c_str());
            if (strncpy_s(result->strOptRouter2, INET_ADDRSTRLEN, pRouterIp.c_str(), INET_ADDRSTRLEN - 1) != EOK) {
                return;
            }
        }
    }
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
                DHCP_LOGI("GetDHCPServerHostName() recv DHCP_ACK sname, add pSname, \
                    result->strOptVendor is %{public}s.", result->strOptVendor);
            }
            pHostName = NULL;
        }
    }
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::ParseNetworkVendorInfo(const struct DhcpPacket *packet, struct DhcpIpResult *result)
{
    if ((packet == NULL) || (result == NULL)) {
        DHCP_LOGE("ParseNetworkVendorInfo() error, packet == NULL or result == NULL!");
        return DHCP_OPT_FAILED;
    }

    char *pVendor = GetDhcpOptionString(packet, VENDOR_SPECIFIC_INFO_OPTION);
    if (pVendor == NULL) {
        DHCP_LOGW("ParseNetworkVendorInfo() recv DHCP_ACK 43, pVendor is NULL!");
        if (GetDHCPServerHostName(packet, result) != DHCP_OPT_SUCCESS) {
            DHCP_LOGE("GetDHCPServerHostName() error, GetDHCPServerHostName failed!");
            return DHCP_OPT_FAILED;
        }
    /* Get option43 success. */
    } else {
        DHCP_LOGI("ParseNetworkVendorInfo() recv DHCP_ACK 43, pVendor is %{public}s.", pVendor);
        if (strncpy_s(result->strOptVendor, DHCP_FILE_MAX_BYTES, pVendor, DHCP_FILE_MAX_BYTES - 1) != EOK) {
            DHCP_LOGE("ParseNetworkVendorInfo() error, strncpy_s pVendor failed!");
            free(pVendor);
            pVendor = NULL;
            return DHCP_OPT_FAILED;
        }
        free(pVendor);
        pVendor = NULL;
    }
    return DHCP_OPT_SUCCESS;
}

void DhcpClientStateMachine::DhcpAckOrNakPacketHandle(uint8_t type, struct DhcpPacket *packet, time_t timestamp)
{
    if ((type != DHCP_ACK) && (type != DHCP_NAK)) {
        DHCP_LOGI("DhcpAckOrNakPacketHandle type:%{public}d error!", type);
        if (m_dhcp4State == DHCP_STATE_INITREBOOT) {
            m_dhcp4State = DHCP_STATE_INIT;
            m_timeoutTimestamp = static_cast<uint32_t>(timestamp);
        }
        return;
    }
    if (packet == NULL) {
        DHCP_LOGE("DhcpAckOrNakPacketHandle type:%{public}d error, packet == NULL!", type);
        return;
    }

    m_dhcpIpResult.dnsAddr.clear();

    m_dhcpIpResult.ifname.clear();

    if (memset_s(&m_dhcpIpResult, sizeof(struct DhcpIpResult), 0, sizeof(struct DhcpIpResult)) != EOK) {
        DHCP_LOGE("DhcpAckOrNakPacketHandle error, memset_s failed!");
        return;
    }
    if (type == DHCP_NAK) {
        ParseDhcpNakPacket(packet, timestamp);
        return;
    }

    ParseDhcpAckPacket(packet, timestamp);
    if (SetLocalInterface(m_cltCnf.ifaceName,
        inet_addr(m_dhcpIpResult.strYiaddr), inet_addr(m_dhcpIpResult.strOptSubnet)) != DHCP_OPT_SUCCESS) {
        DHCP_LOGE("DhcpAckOrNakPacketHandle error, SetLocalInterface yiaddr:%{public}s failed!",
            m_dhcpIpResult.strYiaddr);
        return;
    }
    FormatString(&m_dhcpIpResult);
    CloseAllRenewTimer();
    if (m_dhcp4State == DHCP_STATE_REQUESTING || m_dhcp4State == DHCP_STATE_INITREBOOT) {
        IpConflictDetect();
    } else {
        if (PublishDhcpResultEvent(m_cltCnf.ifaceName, PUBLISH_CODE_SUCCESS, &m_dhcpIpResult) != DHCP_OPT_SUCCESS) {
            DHCP_LOGE("DhcpAckOrNakPacketHandle PublishDhcpResultEvent result failed!");
            return;
        }
        m_dhcp4State = DHCP_STATE_BOUND;
        m_sentPacketNum = 0;
        m_resendTimer = 0;
        m_timeoutTimestamp = static_cast<uint32_t>(timestamp) + m_renewalSec;
        StopIpv4();
        ScheduleLeaseTimers(false);
    }
}

void DhcpClientStateMachine::ParseDhcpAckPacket(const struct DhcpPacket *packet, time_t timestamp)
{
    if (packet == nullptr) {
        DHCP_LOGE("ParseDhcpAckPacket error, packet == nullptr!");
        return;
    }
    /* Set default leasetime. */
    m_leaseTime = LEASETIME_DEFAULT * ONE_HOURS_SEC;
    m_requestedIp4 = packet->yiaddr;
    uint32_t u32Data = 0;
    if (GetDhcpOptionUint32(packet, IP_ADDRESS_LEASE_TIME_OPTION, &u32Data)) {
        m_leaseTime = u32Data;
        DHCP_LOGI("ParseDhcpAckPacket recv DHCP_ACK 51, lease:%{public}u.", m_leaseTime);
    }
    m_renewalSec = m_leaseTime * RENEWAL_SEC_MULTIPLE;  /* First renewal seconds. */
    m_rebindSec = m_leaseTime * REBIND_SEC_MULTIPLE;   /* Second rebind seconds. */
    m_renewalTimestamp = static_cast<int64_t>(timestamp);   /* Record begin renewing or rebinding timestamp. */
    m_renewalTimestampBoot = GetElapsedSecondsSinceBoot();
    m_dhcpIpResult.uOptLeasetime = m_leaseTime;
    DHCP_LOGI("ParseDhcpAckPacket Last get lease:%{public}u,renewal:%{public}u,rebind:%{public}u.",
        m_leaseTime, m_renewalSec, m_rebindSec);
    ParseNetworkServerIdInfo(packet, &m_dhcpIpResult); // m_dhcpIpResult.strOptServerId
    ParseNetworkInfo(packet, &m_dhcpIpResult); // strYiaddr/strOptSubnet/strOptRouter1/strOptRouter2
    ParseNetworkDnsInfo(packet, &m_dhcpIpResult);
    ParseNetworkVendorInfo(packet, &m_dhcpIpResult);
}

void DhcpClientStateMachine::ParseDhcpNakPacket(const struct DhcpPacket *packet, time_t timestamp)
{
    if (packet == NULL) {
        DHCP_LOGE("ParseDhcpNakPacket error, packet == NULL!");
        return;
    }
    /* If receive dhcp nak packet, init m_dhcp4State, resend dhcp discover packet. */
    DHCP_LOGI("ParseDhcpNakPacket receive DHCP_NAK 53, init m_dhcp4State, resend dhcp discover packet!");
    m_dhcp4State = DHCP_STATE_INIT;
    SetSocketMode(SOCKET_MODE_RAW);
    m_requestedIp4 = 0;
    m_sentPacketNum = 0;
    m_timeoutTimestamp = static_cast<uint32_t>(timestamp);
    /* Avoid excessive network traffic. */
    DHCP_LOGI("ParseDhcpNakPacket receive DHCP_NAK 53, avoid excessive network traffic, need sleep!");
    if (m_resendTimer == 0) {
        m_resendTimer = FIRST_TIMEOUT_SEC;
    } else {
        sleep(m_resendTimer);
        DHCP_LOGI("ParseDhcpNakPacket sleep:%{public}u", m_resendTimer);
        m_resendTimer *= DOUBLE_TIME;
        if (m_resendTimer > MAX_TIMEOUT_SEC) {
            m_resendTimer = MAX_TIMEOUT_SEC;
        }
    }
}
#ifndef OHOS_ARCH_LITE
void DhcpClientStateMachine::GetDhcpOffer(DhcpPacket *packet, int64_t timestamp)
{
    DHCP_LOGI("GetDhcpOffer enter");
    if (strncmp(m_cltCnf.ifaceName, "wlan", NUMBER_FOUR) != 0) {
        DHCP_LOGI("ifaceName is not wlan, no need deal multi Offer");
        return;
    }

    if (packet == nullptr) {
        DHCP_LOGW("GetDhcpOffer() packet is nullptr!");
        return;
    }
    uint8_t u8Message = 0;
    if (!GetDhcpOptionUint8(packet, DHCP_MESSAGE_TYPE_OPTION, &u8Message)) {
        DHCP_LOGE("GetDhcpOffer GetDhcpOptionUint8 DHCP_MESSAGE_TYPE_OPTION failed!");
        return;
    }
    if (u8Message != DHCP_OFFER) {
        DHCP_LOGW("GetDhcpOffer() not offer, type:%{public}d!", u8Message);
        return;
    }

    uint32_t leaseTime = LEASETIME_DEFAULT * ONE_HOURS_SEC;
    uint32_t u32Data = 0;
    if (GetDhcpOptionUint32(packet, IP_ADDRESS_LEASE_TIME_OPTION, &u32Data)) {
        leaseTime = u32Data;
    }
    m_requestedIp4 = packet->yiaddr;
    DhcpIpResult dhcpIpResult;
    dhcpIpResult.code = PUBLISH_DHCP_OFFER_REPORT;
    dhcpIpResult.ifname = m_cltCnf.ifaceName;
    dhcpIpResult.uOptLeasetime = leaseTime;
    ParseNetworkServerIdInfo(packet, &dhcpIpResult);
    ParseNetworkInfo(packet, &dhcpIpResult);
    ParseNetworkDnsInfo(packet, &dhcpIpResult);
    ParseNetworkVendorInfo(packet, &dhcpIpResult);
    PublishDhcpIpv4Result(dhcpIpResult);
}
#endif
void DhcpClientStateMachine::DhcpResponseHandle(time_t timestamp)
{
    struct DhcpPacket packet;
    int getLen;
    uint8_t u8Message = 0;

    if (memset_s(&packet, sizeof(packet), 0, sizeof(packet)) != EOK) {
        DHCP_LOGE("DhcpResponseHandle memset_s packet failed!");
        return;
    }
    getLen = (m_socketMode == SOCKET_MODE_RAW) ? GetDhcpRawPacket(&packet, m_sockFd)
                                               : GetDhcpKernelPacket(&packet, m_sockFd);
    if (getLen < 0) {
        if ((getLen == SOCKET_OPT_ERROR) && (errno != EINTR)) {
            DHCP_LOGI(" DhcpResponseHandle get packet read error, reopening socket!");
            /* Reopen m_sockFd. */
            SetSocketMode(m_socketMode);
        }
        DHCP_LOGD("DhcpResponseHandle get packet failed, error:%{public}d len:%{public}d", errno, getLen);
        if (m_dhcp4State == DHCP_STATE_INITREBOOT) {
            m_dhcp4State = DHCP_STATE_INIT;
            m_timeoutTimestamp = static_cast<uint32_t>(timestamp);
        }
        return;
    }
    DHCP_LOGI("DhcpResponseHandle get packet success, getLen:%{public}d.", getLen);
    /* Check packet data. */
    if (packet.xid != m_transID) {
        DHCP_LOGW("DhcpResponseHandle get xid:%{public}u and m_transID:%{public}u not same!", packet.xid, m_transID);
        return;
    }
#ifndef OHOS_ARCH_LITE
    GetDhcpOffer(&packet, timestamp);
#endif
    if (!GetDhcpOptionUint8(&packet, DHCP_MESSAGE_TYPE_OPTION, &u8Message)) {
        DHCP_LOGE("DhcpResponseHandle GetDhcpOptionUint8 DHCP_MESSAGE_TYPE_OPTION failed!");
        return;
    }
    DHCP_LOGI("DhcpResponseHandle m_dhcp4State:%{public}d.", m_dhcp4State);
    switch (m_dhcp4State) {
        case DHCP_STATE_SELECTING:
            DhcpOfferPacketHandle(u8Message, &packet, timestamp);
            break;
        case DHCP_STATE_REQUESTING:
        case DHCP_STATE_RENEWING:
        case DHCP_STATE_REBINDING:
        case DHCP_STATE_INITREBOOT:
        case DHCP_STATE_RENEWED:
            DhcpAckOrNakPacketHandle(u8Message, &packet, timestamp);
            break;
        default:
            break;
    }
}

/* Receive signals. */
void DhcpClientStateMachine::SignalReceiver(void)
{
    int signum = SIG_INVALID;
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
    if (ifname == nullptr) {
        DHCP_LOGE("PublishDhcpResultEvent failed, ifname is nullptr!");
        return DHCP_OPT_FAILED;
    }
    if ((code != PUBLISH_CODE_SUCCESS) && (code != PUBLISH_CODE_FAILED) && (code != PUBLISH_CODE_TIMEOUT)) {
        DHCP_LOGE("PublishDhcpResultEvent ifname:%{public}s failed, code:%{public}d error!", ifname, code);
        return DHCP_OPT_FAILED;
    }
    if (result == nullptr) {
        DHCP_LOGE("PublishDhcpResultEvent ifname:%{public}s, code:%{public}d failed, result==nullptr!", ifname, code);
        return DHCP_OPT_FAILED;
    }
    result->code = code;
    result->uAddTime = (uint32_t)time(NULL);
    result->ifname = ifname;
    DHCP_LOGI("PublishDhcpResultEvent code:%{public}d ifname:%{public}s uAddTime:%{public}u", result->code,
        result->ifname.c_str(), result->uAddTime);
    bool ret = PublishDhcpIpv4Result(*result);
    if (!ret) {
        DHCP_LOGE("PublishDhcpResultEvent failed!");
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
    AddClientIdToOpts(packet); // 61
    AddHostNameToOpts(packet); // 60 12
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::AddClientIdToOpts(struct DhcpPacket *packet)
{
    if (packet == nullptr) {
        DHCP_LOGE("AddClientIdToOpts failed, packet == nullptr!");
        return DHCP_OPT_FAILED;
    }
    char macAddr[MAC_ADDR_LEN * MAC_ADDR_CHAR_NUM] = {0};
    MacChConToMacStr(m_cltCnf.ifaceMac, MAC_ADDR_LEN, macAddr, sizeof(macAddr));

    unsigned char optValue[VENDOR_MAX_LEN - DHCP_OPT_CODE_BYTES - DHCP_OPT_LEN_BYTES] = {0};
    optValue[DHCP_OPT_CODE_INDEX] = CLIENT_IDENTIFIER_OPTION;
    optValue[DHCP_OPT_LEN_INDEX] = MAC_ADDR_LEN  + 1;
    optValue[DHCP_OPT_DATA_INDEX] = NUMBER_ONE; /* Generate format: 1 + ifaceMac. */
    if (memcpy_s(optValue + DHCP_OPT_DATA_INDEX + 1, MAC_ADDR_LEN, m_cltCnf.ifaceMac, MAC_ADDR_LEN) != EOK) {
        DHCP_LOGE("AddClientIdToOpts memcpy_s failed!");
        return DHCP_OPT_FAILED;
    }
    int optValueLen = DHCP_OPT_CODE_BYTES + DHCP_OPT_LEN_BYTES + optValue[DHCP_OPT_LEN_INDEX];
    DHCP_LOGI("AddClientIdToOpts option=%{public}d len=%{public}d", CLIENT_IDENTIFIER_OPTION, optValueLen);
    AddOptStrToOpts(packet->options, optValue, optValueLen);
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::AddHostNameToOpts(struct DhcpPacket *packet)
{
    if (packet == nullptr) {
        DHCP_LOGE("AddHostNameToOpts failed, packet == nullptr!");
        return DHCP_OPT_FAILED;
    }
    std::string strProductModel;
#ifdef INIT_LIB_ENABLE
    strProductModel = GetProductModel();
    DHCP_LOGD("AddHostNameOptions strProductModel:%{public}s", strProductModel.c_str());
#endif
    std::string venderName = VENDOR_NAME_PREFIX;
    std::string venderClass = venderName + ":" + strProductModel; // xxxx:openharmony:yyyy
    AddStrToOpts(packet, VENDOR_CLASS_IDENTIFIER_OPTION, venderClass); // add option 60
    AddStrToOpts(packet, HOST_NAME_OPTION, strProductModel);  // add option 12
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStateMachine::AddStrToOpts(struct DhcpPacket *packet, int option, std::string &value)
{
    if (packet == nullptr) {
        DHCP_LOGE("AddStrToOpts failed, packet is nullptr!");
        return DHCP_OPT_FAILED;
    }
    char buf[VENDOR_MAX_LEN - DHCP_OPT_CODE_BYTES - DHCP_OPT_LEN_BYTES] = {0};
    int nRes = snprintf_s(buf, VENDOR_MAX_LEN - DHCP_OPT_DATA_INDEX,
        VENDOR_MAX_LEN - DHCP_OPT_DATA_INDEX - 1, "%s", value.c_str());
    if (nRes < 0) {
        DHCP_LOGE("AddStrToOpts buf snprintf_s failed, nRes:%{public}d", nRes);
        return DHCP_OPT_FAILED;
    }
    unsigned char optValue[VENDOR_MAX_LEN] = {0};
    optValue[DHCP_OPT_CODE_INDEX] = option;
    optValue[DHCP_OPT_LEN_INDEX] = strlen(buf);
    if (strncpy_s((char *)optValue + DHCP_OPT_DATA_INDEX, VENDOR_MAX_LEN - DHCP_OPT_DATA_INDEX, buf,
        strlen(buf)) != EOK) {
        DHCP_LOGE("AddStrToOpts optValue strncpy_s failed!");
        return DHCP_OPT_FAILED;
    }
    int optValueLen = DHCP_OPT_CODE_BYTES + DHCP_OPT_LEN_BYTES + optValue[DHCP_OPT_LEN_INDEX];
    DHCP_LOGD("AddStrToOpts option=%{public}d buf=%{public}s len=%{public}d", option, buf, optValueLen);
    AddOptStrToOpts(packet->options, optValue, optValueLen);
    return DHCP_OPT_SUCCESS;
}

/* Broadcast dhcp discover packet, discover dhcp servers that can provide ip address. */
int DhcpClientStateMachine::DhcpDiscover(uint32_t transid, uint32_t requestip)
{
    DHCP_LOGI("DhcpDiscover send discover transid:%{public}u reqip:%{public}s", transid,
        IntIpv4ToAnonymizeStr(requestip).c_str());
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
    /* Set Discover seconds elapsed. */
    SetSecondsElapsed(&packet);
    AddOptValueToOpts(packet.options, MAXIMUM_DHCP_MESSAGE_SIZE_OPTION, MAX_MSG_SIZE); // 57
    AddParamaterRequestList(&packet); // 55
    DHCP_LOGI("DhcpDiscover begin broadcast discover packet");
    return SendToDhcpPacket(&packet, INADDR_ANY, INADDR_BROADCAST, m_cltCnf.ifaceIndex, (uint8_t *)MAC_BCAST_ADDR);
}

/* Broadcast dhcp request packet, tell dhcp servers that which ip address to choose. */
int DhcpClientStateMachine::DhcpRequest(uint32_t transid, uint32_t reqip, uint32_t servip)
{
    DHCP_LOGI("DhcpRequest send request transid:%{public}u reqip:%{public}s servip:%{public}s", transid,
        IntIpv4ToAnonymizeStr(reqip).c_str(), IntIpv4ToAnonymizeStr(servip).c_str());
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
    /* Set Request seconds elapsed. */
    SetSecondsElapsed(&packet);
    AddOptValueToOpts(packet.options, SERVER_IDENTIFIER_OPTION, servip); // 50
    AddOptValueToOpts(packet.options, REQUESTED_IP_ADDRESS_OPTION, reqip); // 54
    AddOptValueToOpts(packet.options, MAXIMUM_DHCP_MESSAGE_SIZE_OPTION, MAX_MSG_SIZE); //57
    AddParamaterRequestList(&packet); // 55
    DHCP_LOGI("DhcpRequest begin broadcast dhcp request packet");
    return SendToDhcpPacket(&packet, INADDR_ANY, INADDR_BROADCAST, m_cltCnf.ifaceIndex, (uint8_t *)MAC_BCAST_ADDR);
}

/* Unicast or broadcast dhcp request packet, request to extend the lease from the dhcp server. */
int DhcpClientStateMachine::DhcpRenew(uint32_t transid, uint32_t clientip, uint32_t serverip)
{
    DHCP_LOGI("DhcpRenew send request transid:%{public}u, clientip:%{public}s serverip:%{public}s", transid,
        IntIpv4ToAnonymizeStr(clientip).c_str(), IntIpv4ToAnonymizeStr(serverip).c_str());
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
    /* Set Renew Request seconds elapsed. */
    SetSecondsElapsed(&packet);
    packet.ciaddr = clientip;
    AddParamaterRequestList(&packet);

    /* Begin broadcast or unicast dhcp request packet. */
    if (serverip == 0) {
        DHCP_LOGI("DhcpRenew rebind, begin broadcast req packet");
        return SendToDhcpPacket(&packet, INADDR_ANY, INADDR_BROADCAST, m_cltCnf.ifaceIndex, (uint8_t *)MAC_BCAST_ADDR);
    }
    DHCP_LOGI("DhcpRenew send renew, begin unicast request packet");
    return SendDhcpPacket(&packet, clientip, serverip);
}

/* Unicast dhcp release packet, releasing an ip address in Use from the dhcp server. */
int DhcpClientStateMachine::DhcpRelease(uint32_t clientip, uint32_t serverip)
{
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
    DHCP_LOGI("DhcpRelease begin unicast release packet, transid:%{public}u clientip:%{public}s serverip:%{public}s",
        packet.xid, IntIpv4ToAnonymizeStr(clientip).c_str(), IntIpv4ToAnonymizeStr(serverip).c_str());
    return SendDhcpPacket(&packet, clientip, serverip);
}

int DhcpClientStateMachine::DhcpDecline(uint32_t transId, uint32_t clientIp, uint32_t serverIp)
{
    DHCP_LOGI("DhcpDecline send decline transid:%{public}u, clientip:%{public}s serverip:%{public}s", transId,
        IntIpv4ToAnonymizeStr(clientIp).c_str(), IntIpv4ToAnonymizeStr(serverIp).c_str());
    struct DhcpPacket packet;
    if (memset_s(&packet, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket)) != EOK) {
        return -1;
    }

    /* Get packet header and common info. */
    if (GetPacketHeaderInfo(&packet, DHCP_DECLINE) != DHCP_OPT_SUCCESS) {
        return -1;
    }

    /* Get packet not common info. */
    packet.xid = transId;
    if (memcpy_s(packet.chaddr, sizeof(packet.chaddr), m_cltCnf.ifaceMac, MAC_ADDR_LEN) != EOK) {
        DHCP_LOGE("DhcpDecline, memcpy_s error!");
        return -1;
    }
    AddClientIdToOpts(&packet);
    AddOptValueToOpts(packet.options, REQUESTED_IP_ADDRESS_OPTION, clientIp);
    AddOptValueToOpts(packet.options, SERVER_IDENTIFIER_OPTION, serverIp);
    AddOptValueToOpts(packet.options, REQUESTED_IP_ADDRESS_OPTION, clientIp);
    AddOptValueToOpts(packet.options, SERVER_IDENTIFIER_OPTION, serverIp);
    DHCP_LOGI("DhcpDecline send decline, transid:%{public}u", transId);
    return SendToDhcpPacket(&packet, INADDR_ANY, INADDR_BROADCAST, m_cltCnf.ifaceIndex, (uint8_t *)MAC_BCAST_ADDR);
}

void DhcpClientStateMachine::IpConflictDetect()
{
    DHCP_LOGI("IpConflictDetect start");
    m_sentPacketNum = 0;
    m_timeoutTimestamp = 0;
    m_dhcp4State = DHCP_STATE_FAST_ARP;
    m_arpDectionTargetIp = Ip4IntConvertToStr(m_requestedIp4, false);
}

void DhcpClientStateMachine::FastArpDetect()
{
    DHCP_LOGI("FastArpDetect() enter");
    if (IsArpReachable(FAST_ARP_DETECTION_TIME_MS, m_arpDectionTargetIp)) {
        m_dhcp4State = DHCP_STATE_DECLINE;
        SetSocketMode(SOCKET_MODE_RAW);
    } else {
        if (PublishDhcpResultEvent(m_cltCnf.ifaceName, PUBLISH_CODE_SUCCESS, &m_dhcpIpResult) != DHCP_OPT_SUCCESS) {
            PublishDhcpResultEvent(m_cltCnf.ifaceName, PUBLISH_CODE_FAILED, &m_dhcpIpResult);
            DHCP_LOGE("FastArpDetect PublishDhcpResultEvent result failed!");
            StopIpv4();
            return;
        }
        SaveIpInfoInLocalFile(m_dhcpIpResult);
        m_dhcp4State = DHCP_STATE_SLOW_ARP;
        m_slowArpDetecting = true;
    }
}

void DhcpClientStateMachine::SlowArpDetectCallback(bool isReachable)
{
    DHCP_LOGI("SlowArpDetectCallback() enter");
    if (!m_slowArpDetecting) {
        DHCP_LOGI("it is not arpchecking");
        return;
    }
    if (isReachable) {
        m_dhcp4State = DHCP_STATE_DECLINE;
        m_timeoutTimestamp = 0;
        SetSocketMode(SOCKET_MODE_RAW);
    } else {
        m_dhcp4State = DHCP_STATE_BOUND;
        m_sentPacketNum = 0;
        m_resendTimer = 0;
        m_timeoutTimestamp = m_renewalSec + static_cast<uint32_t>(time(NULL));
        StopIpv4();
        ScheduleLeaseTimers(false);
    }
    m_slowArpDetecting = false;
#ifndef OHOS_ARCH_LITE
    DhcpTimer::GetInstance()->UnRegister(m_slowArpTaskId);
#endif
}

void DhcpClientStateMachine::SlowArpDetect(time_t timestamp)
{
    DHCP_LOGI("SlowArpDetect() enter, %{public}d", m_sentPacketNum);
    if (m_sentPacketNum > SLOW_ARP_DETECTION_TRY_CNT) {
        m_dhcp4State = DHCP_STATE_BOUND;
        m_sentPacketNum = 0;
        m_resendTimer = 0;
        m_timeoutTimestamp = static_cast<uint32_t>(timestamp) + m_renewalSec;
        StopIpv4();
        ScheduleLeaseTimers(false);
    } else if (m_sentPacketNum == SLOW_ARP_DETECTION_TRY_CNT) {
        m_timeoutTimestamp = SLOW_ARP_TOTAL_TIME_MS / RATE_S_MS + static_cast<uint32_t>(time(NULL)) + 1;
    #ifndef OHOS_ARCH_LITE
        std::function<void()> func = [this]() {
            DHCP_LOGI("SlowArpDetectTask enter");
            uint32_t tastId = m_slowArpTaskId;
            uint32_t timeout = SLOW_ARP_TOTAL_TIME_MS - SLOW_ARP_DETECTION_TIME_MS * SLOW_ARP_DETECTION_TRY_CNT;
            bool ret = IsArpReachable(timeout, m_arpDectionTargetIp);
            if (tastId != m_slowArpTaskId) {
                ret = false;
                DHCP_LOGW("tastId != m_slowArpTaskId, %{public}u, %{public}u", tastId, m_slowArpTaskId);
            }
            m_slowArpCallback(ret);
            };
        DhcpTimer::GetInstance()->Register(func, m_slowArpTaskId, 0);
        DHCP_LOGI("Register m_slowArpTaskId is %{public}u", m_slowArpTaskId);
    #endif
    } else {
        if (IsArpReachable(SLOW_ARP_DETECTION_TIME_MS, m_arpDectionTargetIp)) {
            m_dhcp4State = DHCP_STATE_DECLINE;
            m_slowArpDetecting = false;
            SetSocketMode(SOCKET_MODE_RAW);
        }
    }
    m_sentPacketNum++;
}

bool DhcpClientStateMachine::IsArpReachable(uint32_t timeoutMillis, std::string ipAddress)
{
    std::string senderIp = "0.0.0.0";
    char macAddr[MAC_ADDR_CHAR_NUM * MAC_ADDR_LEN];
    if (memset_s(macAddr, sizeof(macAddr), 0, sizeof(macAddr)) != EOK) {
        DHCP_LOGI("IsArpReachable memset_s error");
        return false;
    }
    MacChConToMacStr(m_cltCnf.ifaceMac, MAC_ADDR_LEN, macAddr, sizeof(macAddr));
    std::string localMac = macAddr;
    uint64_t timeCost = 0;
    m_dhcpArpChecker.Start(m_ifName, localMac, senderIp, ipAddress);
    if (m_dhcpArpChecker.DoArpCheck(timeoutMillis, false, timeCost)) {
        DHCP_LOGI("Arp detection get response");
        return true;
    }
    DHCP_LOGI("Arp detection not get response");
    return false;
}

int32_t DhcpClientStateMachine::GetCachedDhcpResult(std::string targetBssid, IpInfoCached &ipcached)
{
    return DhcpResultStoreManager::GetInstance().GetCachedIp(targetBssid, ipcached);
}

void DhcpClientStateMachine::SaveIpInfoInLocalFile(const DhcpIpResult ipResult)
{
    DHCP_LOGI("SaveIpInfoInLocalFile() enter");
    if (strncmp(m_cltCnf.ifaceName, "wlan", NUMBER_FOUR) != 0) {
        DHCP_LOGI("ifaceName is not wlan, no need save");
        return;
    }

    if (m_routerCfg.bssid.empty()) {
        DHCP_LOGI("m_routerCfg.bssid is empty, no need save");
        return;
    }
    IpInfoCached ipInfoCached;
    ipInfoCached.bssid = m_routerCfg.bssid;
    ipInfoCached.absoluteLeasetime = static_cast<int64_t>(ipResult.uOptLeasetime) + static_cast<int64_t>(time(NULL));
    ipInfoCached.ipResult = ipResult;
    DhcpResultStoreManager::GetInstance().SaveIpInfoInLocalFile(ipInfoCached);
}

void DhcpClientStateMachine::TryCachedIp()
{
    DHCP_LOGI("TryCachedIp() enter, action:%{public}d dhcpState:%{public}d", m_action, m_dhcp4State);
    if (m_routerCfg.prohibitUseCacheIp) {
        DHCP_LOGW("don not make default IP");
        return;
    }

    if (strncmp(m_cltCnf.ifaceName, "wlan", NUMBER_FOUR) != 0) {
        DHCP_LOGW("ifaceName is not wlan, not use cache ip");
        return;
    }

    IpInfoCached ipCached;
    if (GetCachedDhcpResult(m_routerCfg.bssid, ipCached) != 0) {
        DHCP_LOGE("TryCachedIp() not find cache ip");
        return;
    }
    if (PublishDhcpResultEvent(m_cltCnf.ifaceName, PUBLISH_CODE_SUCCESS, &ipCached.ipResult) != DHCP_OPT_SUCCESS) {
        PublishDhcpResultEvent(m_cltCnf.ifaceName, PUBLISH_CODE_FAILED, &ipCached.ipResult);
        DHCP_LOGE("TryCachedIp publish dhcp result failed!");
    }
    StopIpv4();
    m_leaseTime = ipCached.ipResult.uOptLeasetime;
    m_renewalSec = ipCached.ipResult.uOptLeasetime * RENEWAL_SEC_MULTIPLE;
    m_rebindSec = ipCached.ipResult.uOptLeasetime * REBIND_SEC_MULTIPLE;
    m_renewalTimestamp = static_cast<int64_t>(ipCached.ipResult.uAddTime);
    DHCP_LOGI("TryCachedIp m_leaseTime:%{public}u %{public}u %{public}u", m_leaseTime, m_renewalSec, m_rebindSec);
    ScheduleLeaseTimers(true);
}

void DhcpClientStateMachine::SetConfiguration(const RouterCfg routerCfg)
{
    m_routerCfg = routerCfg;
}

void DhcpClientStateMachine::SetSecondsElapsed(struct DhcpPacket *packet)
{
    if (packet == nullptr) {
        DHCP_LOGE("packet is nullptr!");
        return;
    }
    int64_t curTimeSeconds = GetElapsedSecondsSinceBoot();
    if (firstSendPacketTime_ == 0) {
        firstSendPacketTime_ = curTimeSeconds;
    }
    packet->secs = htons(static_cast<uint16_t>(curTimeSeconds - firstSendPacketTime_));
    DHCP_LOGI("SetSecondsElapsed curTimeSeconds:%{public}" PRId64" %{public}" PRId64", secs:%{public}u",
        curTimeSeconds, firstSendPacketTime_, static_cast<uint16_t>(curTimeSeconds - firstSendPacketTime_));
}

#ifndef OHOS_ARCH_LITE
void DhcpClientStateMachine::GetIpTimerCallback()
{
    DHCP_LOGI("GetIpTimerCallback isExit:%{public}d action:%{public}d [%{public}u %{public}u %{public}u %{public}u",
        threadExit_.load(), m_action, getIpTimerId, renewDelayTimerId, rebindDelayTimerId, remainingDelayTimerId);
    if (threadExit_) {
        DHCP_LOGE("GetIpTimerCallback return!");
        return;
    }
    StopTimer(getIpTimerId);
    SendStopSignal();
    if (m_action == ACTION_RENEW_T1 || m_action == ACTION_RENEW_T2) {
        DHCP_LOGI("GetIpTimerCallback T1 or T2 Timeout!");
    } else if (m_action == ACTION_RENEW_T3) {
        DHCP_LOGI("GetIpTimerCallback T3 Expired!");
        struct DhcpIpResult ipResult;
        ipResult.code = PUBLISH_CODE_EXPIRED;
        ipResult.ifname = m_cltCnf.ifaceName;
        PublishDhcpIpv4Result(ipResult);
    } else {
        struct DhcpIpResult ipResult;
        ipResult.code = PUBLISH_CODE_TIMEOUT;
        ipResult.ifname = m_cltCnf.ifaceName;
        PublishDhcpIpv4Result(ipResult);
    }
}

void DhcpClientStateMachine::StartTimer(TimerType type, uint32_t &timerId, int64_t interval, bool once)
{
    DHCP_LOGI("StartTimer timerId:%{public}u type:%{public}u interval:%{public}" PRId64" once:%{public}d", timerId,
        type, interval, once);
    std::unique_lock<std::mutex> lock(getIpTimerMutex);
    std::function<void()> timeCallback = nullptr;
    if (timerId != 0) {
        DHCP_LOGE("StartTimer timerId !=0 id:%{public}u", timerId);
        return;
    }
    switch (type) {
        case TIMER_GET_IP:
            timeCallback = [this] { this->GetIpTimerCallback(); };
            break;
        case TIMER_RENEW_DELAY:
            timeCallback = [this] { this->RenewDelayCallback(); };
            break;
        case TIMER_REBIND_DELAY:
            timeCallback = [this] { this->RebindDelayCallback(); };
            break;
        case TIMER_REMAINING_DELAY:
            timeCallback = [this] { this->RemainingDelayCallback(); };
            break;
        default:
            DHCP_LOGE("StartTimer default timerId:%{public}u", timerId);
            break;
    }
    if (timeCallback != nullptr && (timerId == 0)) {
        std::shared_ptr<OHOS::DHCP::DhcpSysTimer> dhcpSysTimer =
            std::make_shared<OHOS::DHCP::DhcpSysTimer>(false, 0, false, false);
        dhcpSysTimer->SetCallbackInfo(timeCallback);
        timerId = MiscServices::TimeServiceClient::GetInstance()->CreateTimer(dhcpSysTimer);
        int64_t currentTime = MiscServices::TimeServiceClient::GetInstance()->GetBootTimeMs();
        MiscServices::TimeServiceClient::GetInstance()->StartTimer(timerId, currentTime + interval);
        DHCP_LOGI("StartTimer timerId:%{public}u [%{public}u %{public}u %{public}u %{public}u]", timerId, getIpTimerId,
            renewDelayTimerId, rebindDelayTimerId, remainingDelayTimerId);
    }
}

void DhcpClientStateMachine::StopTimer(uint32_t &timerId)
{
    uint32_t stopTimerId = timerId;
    if (timerId == 0) {
        DHCP_LOGE("StopTimer timerId is 0, no unregister timer");
        return;
    }
    std::unique_lock<std::mutex> lock(getIpTimerMutex);
    MiscServices::TimeServiceClient::GetInstance()->StopTimer(timerId);
    MiscServices::TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    timerId = 0;
    DHCP_LOGI("StopTimer stopTimerId:%{public}u [%{public}u %{public}u %{public}u %{public}u]", stopTimerId,
        getIpTimerId, renewDelayTimerId, rebindDelayTimerId, remainingDelayTimerId);
}

void DhcpClientStateMachine::RenewDelayCallback()
{
    DHCP_LOGI("RenewDelayCallback timerId:%{public}u", renewDelayTimerId);
    StopTimer(renewDelayTimerId);
    m_action = ACTION_RENEW_T1; // T1 begin renew
    InitConfig(m_ifName, m_cltCnf.isIpv6);
    StopTimer(getIpTimerId);
    StartTimer(TIMER_GET_IP, getIpTimerId, DhcpTimer::DEFAULT_TIMEROUT, true);
    m_dhcp4State = DHCP_STATE_RENEWING;
    m_sentPacketNum = 0;
    m_timeoutTimestamp = 0;
    SetSocketMode(SOCKET_MODE_KERNEL); // Set socket mode, send unicast packet
    InitStartIpv4Thread(m_ifName, m_cltCnf.isIpv6);
}

void DhcpClientStateMachine::RebindDelayCallback()
{
    DHCP_LOGI("RebindDelayCallback timerId:%{public}u", rebindDelayTimerId);
    StopTimer(rebindDelayTimerId);
    StopIpv4();
    m_action = ACTION_RENEW_T2; // T2 begin rebind
    InitConfig(m_ifName, m_cltCnf.isIpv6);
    StartTimer(TIMER_GET_IP, getIpTimerId, DhcpTimer::DEFAULT_TIMEROUT, true);
    m_dhcp4State = DHCP_STATE_REBINDING;
    m_sentPacketNum = 0;
    m_timeoutTimestamp = 0;
    SetSocketMode(SOCKET_MODE_RAW);
    InitStartIpv4Thread(m_ifName, m_cltCnf.isIpv6);
}

void DhcpClientStateMachine::RemainingDelayCallback()
{
    DHCP_LOGI("RemainingDelayCallback timerId:%{public}u", remainingDelayTimerId);
    StopTimer(remainingDelayTimerId);
    StopIpv4();
    m_action = ACTION_RENEW_T3;  // T3 expired,
    InitConfig(m_ifName, m_cltCnf.isIpv6);
    StartTimer(TIMER_GET_IP, getIpTimerId, DhcpTimer::DEFAULT_TIMEROUT, true);
    m_dhcp4State = DHCP_STATE_INIT;
    m_sentPacketNum = 0;
    m_timeoutTimestamp = 0;
    SetSocketMode(SOCKET_MODE_RAW);
    InitStartIpv4Thread(m_ifName, m_cltCnf.isIpv6);  // int discover
}
#endif

int DhcpClientStateMachine::SendStopSignal()
{
    DHCP_LOGI("SendStopSignal isExit:%{public}d", threadExit_.load());
    if (!threadExit_) {
        int signum = SIG_STOP;
        if (send(m_sigSockFds[1], &signum, sizeof(signum), MSG_DONTWAIT) < 0) {
            DHCP_LOGE("SendStopSignal send SIG_STOP failed.");
            return DHCP_OPT_FAILED;
        }
        DHCP_LOGE("SendStopSignal send SIG_STOP ok");
    }
    return DHCP_OPT_SUCCESS;
}

void DhcpClientStateMachine::CloseAllRenewTimer()
{
    DHCP_LOGI("CloseAllRenewTimer enter!");
#ifndef OHOS_ARCH_LITE
    StopTimer(renewDelayTimerId);
    StopTimer(rebindDelayTimerId);
    StopTimer(remainingDelayTimerId);
#endif
}

void DhcpClientStateMachine::ScheduleLeaseTimers(bool isCachedIp)
{
    DHCP_LOGI("ScheduleLeaseTimers threadExit:%{public}d m_action:%{public}d isCachedIp:%{public}d",
        threadExit_.load(), m_action, isCachedIp);
    int64_t delay = 0;
    if (isCachedIp) {
        time_t curTimestamp = time(nullptr);
        if (curTimestamp == static_cast<time_t>(-1)) {
            DHCP_LOGE("time return failed, errno:%{public}d", errno);
            return;
        }
        delay = (static_cast<int64_t>(curTimestamp) < m_renewalTimestamp) ? 0 : (static_cast<int64_t>(curTimestamp) -
            m_renewalTimestamp);
        DHCP_LOGI("ScheduleLeaseTimers delay:%{public}" PRId64", curTimestamp:%{public}" PRId64","
            "m_renewalTimestamp:%{public}" PRId64, delay, static_cast<int64_t>(curTimestamp), m_renewalTimestamp);
    } else {
        int64_t curTimestampBoot = GetElapsedSecondsSinceBoot();
        delay = (curTimestampBoot < m_renewalTimestampBoot) ? 0 : (curTimestampBoot - m_renewalTimestampBoot);
        DHCP_LOGI("ScheduleLeaseTimers delay:%{public}" PRId64", curTimestampBoot:%{public}" PRId64","
            "m_renewalTimestampBoot:%{public}" PRId64, delay, curTimestampBoot, m_renewalTimestampBoot);
    }

    int64_t remainingDelay = ((static_cast<int64_t>(m_leaseTime) < delay) ? (static_cast<int64_t>(m_leaseTime)) :
        (static_cast<int64_t>(m_leaseTime) - delay)) * USECOND_CONVERT;
    int64_t renewalSec = remainingDelay * RENEWAL_SEC_MULTIPLE;
    int64_t rebindSec = remainingDelay * REBIND_SEC_MULTIPLE;
    DHCP_LOGI("ScheduleLeaseTimers renewalSec:%{public}" PRId64", rebindSec:%{public}" PRId64","
        "remainingDelay:%{public}" PRId64, renewalSec, rebindSec, remainingDelay);
#ifndef OHOS_ARCH_LITE
    StopTimer(renewDelayTimerId);
    StopTimer(rebindDelayTimerId);
    StopTimer(remainingDelayTimerId);
    StartTimer(TIMER_RENEW_DELAY, renewDelayTimerId, renewalSec, true);
    StartTimer(TIMER_REBIND_DELAY, rebindDelayTimerId, rebindSec, true);
    StartTimer(TIMER_REMAINING_DELAY, remainingDelayTimerId, remainingDelay, true);
#endif
}
}  // namespace DHCP
}  // namespace OHOS