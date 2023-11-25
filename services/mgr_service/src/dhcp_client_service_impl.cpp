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

#include "dhcp_client_service_impl.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include "dhcp_func.h"
#include "securec.h"
#include "wifi_logger.h"
#include "dhcp_event_subscriber.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_DHCP_LABEL("DhcpClientServiceImpl");

pthread_mutex_t DhcpClientServiceImpl::m_DhcpResultInfoMutex;
std::map<std::string, std::vector<DhcpResult>> DhcpClientServiceImpl::m_mapDhcpResult;
std::map<std::string, DhcpServiceInfo> DhcpClientServiceImpl::m_mapDhcpInfo;
DhcpClientServiceImpl::DhcpClientServiceImpl()
{
    pthread_mutex_init(&m_DhcpResultInfoMutex, NULL);
    isExitDhcpResultHandleThread = false;
    isRenewAction = false;
    pDhcpResultHandleThread = nullptr;
    pDhcpIpv6ClientThread = nullptr;
#ifdef OHOS_ARCH_LITE
    m_mapDhcpRecvMsgThread.clear();
#endif
    if (!m_mapDhcpResultNotify.empty()) {
        ReleaseResultNotifyMemory();
        m_mapDhcpResultNotify.clear();
    }
    m_mapEventSubscriber.clear();
    InitDhcpMgrThread();
    DhcpFunc::CreateDirs(DHCP_WORK_DIR);
    using namespace std::placeholders;
    ipv6Client.SetCallback(std::bind(&DhcpClientServiceImpl::OnAddressChangedCallback, this, _1, _2));
}

DhcpClientServiceImpl::~DhcpClientServiceImpl()
{
    std::unique_lock<std::mutex> lock(m_subscriberMutex);
    if (!m_mapEventSubscriber.empty()) {
        WIFI_LOGE("DhcpClientServiceImpl destructor mapEventSubscriber is not empty!");
        if (UnsubscribeAllDhcpEvent() != DHCP_OPT_SUCCESS) {
            WIFI_LOGE("DhcpClientServiceImpl unregister all dhcp event failed!");
        }
    }

    ExitDhcpMgrThread();
    pthread_mutex_destroy(&m_DhcpResultInfoMutex);
}

void DhcpClientServiceImpl::ReleaseResultNotifyMemory()
{
    for (auto& item : m_mapDhcpResultNotify) {
        auto& secondItem = item.second;
        for (auto& each : secondItem) {
            if (each != nullptr) {
                delete each;
                each = nullptr;
            }
        }
    }
}

int DhcpClientServiceImpl::InitDhcpMgrThread()
{
    pDhcpResultHandleThread = new std::thread(&DhcpClientServiceImpl::RunDhcpResultHandleThreadFunc, this);
    if (pDhcpResultHandleThread == nullptr) {
        WIFI_LOGE("DhcpClientServiceImpl::InitDhcpMgrThread() init pDhcpResultHandleThread failed!");
        return DHCP_OPT_FAILED;
    }

    return DHCP_OPT_SUCCESS;
}

void DhcpClientServiceImpl::ExitDhcpMgrThread()
{
    isExitDhcpResultHandleThread = true;

    if (pDhcpResultHandleThread != nullptr) {
        pDhcpResultHandleThread->join();
        delete pDhcpResultHandleThread;
        pDhcpResultHandleThread = nullptr;
    }
    ipv6Client.DhcpIPV6Stop();

    std::unique_lock<std::mutex> lock(m_dhcpIpv6Mutex);
    if (pDhcpIpv6ClientThread != nullptr) {
        pDhcpIpv6ClientThread->join();
        delete pDhcpIpv6ClientThread;
        pDhcpIpv6ClientThread = nullptr;
    }

    if (!m_mapDhcpResultNotify.empty()) {
        WIFI_LOGE("ExitDhcpMgrThread() error, m_mapDhcpResultNotify is not empty!");
        ReleaseResultNotifyMemory();
        m_mapDhcpResultNotify.clear();
    }
#ifdef OHOS_ARCH_LITE
    if (!m_mapDhcpRecvMsgThread.empty()) {
        WIFI_LOGE("ExitDhcpMgrThread() error, m_mapDhcpRecvMsgThread is not empty!");
        for (auto &mapThread : m_mapDhcpRecvMsgThread) {
            int nStatus = GetDhcpStatus(mapThread.first);
            WIFI_LOGE("ExitDhcpMgrThread() ifname:%{public}s, status:%{public}d!",
                (mapThread.first).c_str(), nStatus);
        }
    }
#endif
}

void DhcpClientServiceImpl::CheckTimeout()
{
    uint32_t tempTime = 0;
    uint32_t curTime = (uint32_t)time(NULL);
    for (auto &itemNotify : m_mapDhcpResultNotify) {
        std::string ifname = itemNotify.first;
        WIFI_LOGD("CheckTimeout() ifname:%{public}s, notify1 second size:%{public}d.",
            ifname.c_str(),
            (int)itemNotify.second.size());
        auto iterReq = itemNotify.second.begin();
        while (iterReq != itemNotify.second.end()) {
            if ((*iterReq == nullptr) || ((*iterReq)->pResultNotify == nullptr)) {
                WIFI_LOGE("DhcpClientServiceImpl::CheckTimeout() error, *iterReq or pResultNotify is nullptr!");
                return;
            }
            tempTime = (*iterReq)->getTimestamp + (*iterReq)->timeouts;
            if (tempTime <= curTime && ((*iterReq)->status & DHCP_IPV4_GETTED) == 0) {
                /* get dhcp result timeout */
                WIFI_LOGW("CheckTimeout() ifname:%{public}s get timeout, getTime:%{public}u,timeout:%{public}d, "
                          "curTime:%{public}u isRenewAction:%{public}d",
                    ifname.c_str(),
                    (*iterReq)->getTimestamp,
                    (*iterReq)->timeouts,
                    curTime,
                    isRenewAction);
                isRenewAction ? ((*iterReq)->pResultNotify->OnFailed(DHCP_OPT_RENEW_TIMEOUT, ifname,
                    "get dhcp renew result timeout!")) :
                ((*iterReq)->pResultNotify->OnFailed(DHCP_OPT_TIMEOUT, ifname, "get dhcp ip result timeout!"));
                isRenewAction = false;
                delete *iterReq;
                *iterReq = nullptr;
                iterReq = itemNotify.second.erase(iterReq);
            } else {
                ++iterReq;
            }
        }
    }
}

void DhcpClientServiceImpl::DhcpResultHandle(uint32_t &second)
{
    std::unique_lock<std::mutex> lock(mResultNotifyMutex);
    if (m_mapDhcpResultNotify.empty()) {
        second = SLEEP_TIME_200_MS;
        return;
    }

    /* Check timeout */
    CheckTimeout();
    auto iterNotify = m_mapDhcpResultNotify.begin();
    while (iterNotify != m_mapDhcpResultNotify.end()) {
        /* Check dhcp result notify size */
        std::string ifname = iterNotify->first;
        if (iterNotify->second.size() <= 0) {
            iterNotify = m_mapDhcpResultNotify.erase(iterNotify);
            WIFI_LOGD("DhcpResultHandle() ifname:%{public}s, dhcp result notify size:0, erase!", ifname.c_str());
            continue;
        }
        /* Check dhcp result */
        pthread_mutex_lock(&m_DhcpResultInfoMutex);
        std::map<std::string, std::vector<DhcpResult>>::iterator dhcpRlt =
            DhcpClientServiceImpl::m_mapDhcpResult.find(ifname);
        if (dhcpRlt == DhcpClientServiceImpl::m_mapDhcpResult.end()) {
            WIFI_LOGD("DhcpResultHandle() ifname:%{public}s, dhcp result is getting...", ifname.c_str());
            ++iterNotify;
            pthread_mutex_unlock(&m_DhcpResultInfoMutex);
            continue;
        }
        std::vector<DhcpResult> results(dhcpRlt->second);
        DhcpClientServiceImpl::m_mapDhcpResult.erase(dhcpRlt);
        pthread_mutex_unlock(&m_DhcpResultInfoMutex);
        for (auto resRlt : results) {
            auto dhcpResult = resRlt;
            bool isOptSuc =  dhcpResult.isOptSuc;
            auto iterReq = iterNotify->second.begin();
            while (iterReq != iterNotify->second.end()) {
                if ((*iterReq == nullptr) || ((*iterReq)->pResultNotify == nullptr)) {
                    WIFI_LOGE("DhcpResultHandle() %{public}s iterReq or pResultNotify is nullptr!", ifname.c_str());
                    second = SLEEP_TIME_500_MS;
                    return;
                }

                /* Handle dhcp result notify */
                WIFI_LOGI("DhcpResultHandle() ifname:%{public}s, isOptSuc:%{public}d.", ifname.c_str(), isOptSuc);
                if (isOptSuc) {
                    /* get dhcp result success */
                    WIFI_LOGI("DhcpResultHandle() ifname:%{public}s get dhcp result success!, isRenewAction:%{public}d",
                        ifname.c_str(), isRenewAction);
                    (*iterReq)->pResultNotify->OnSuccess(DHCP_OPT_SUCCESS, ifname, dhcpResult);
                } else {
                    /* get dhcp result failed */
                    WIFI_LOGE("DhcpResultHandle() ifname:%{public}s get dhcp result failed!, isRenewAction:%{public}d",
                        ifname.c_str(), isRenewAction);
                    isRenewAction ? ((*iterReq)->pResultNotify->OnFailed(DHCP_OPT_RENEW_FAILED, ifname,
                        "get dhcp renew result failed!")) :
                    ((*iterReq)->pResultNotify->OnFailed(DHCP_OPT_FAILED, ifname, "get dhcp ip result failed!"));
                    isRenewAction = false;
                }
                if (dhcpResult.iptype == 0) {
                    (*iterReq)->status |= DHCP_IPV4_GETTED;
                } else if (dhcpResult.iptype == 1) {
                    (*iterReq)->status |= DHCP_IPV6_GETTED;
                }
                ++iterReq;
            }
        }
        ++iterNotify;
    }

    WIFI_LOGD("DhcpResultHandle() dhcp result notify finished.");
    second = SLEEP_TIME_500_MS;
}

int DhcpClientServiceImpl::SubscribeDhcpEvent(const std::string &strAction)
{
    if (strAction.empty()) {
        WIFI_LOGE("SubscribeDhcpEvent error, strAction is empty!");
        return DHCP_OPT_ERROR;
    }
#ifndef OHOS_ARCH_LITE
    std::unique_lock<std::mutex> lock(m_subscriberMutex);
    auto iterSubscriber = m_mapEventSubscriber.find(strAction);
    if (iterSubscriber == m_mapEventSubscriber.end()) {
        EventFwk::MatchingSkills matchingSkills;
        matchingSkills.AddEvent(strAction);
        EventFwk::CommonEventSubscribeInfo subInfo(matchingSkills);
        auto dhcpSubscriber = std::make_shared<OHOS::Wifi::DhcpEventSubscriber>(subInfo);
        m_mapEventSubscriber.emplace(std::make_pair(strAction, dhcpSubscriber));
    } else {
        return DHCP_OPT_SUCCESS;
    }
    if (m_mapEventSubscriber[strAction] == nullptr) {
        WIFI_LOGE("SubscribeDhcpEvent mapEventSubscriber %{public}s nullptr!", strAction.c_str());
        return DHCP_OPT_FAILED;
    }
    if (!DhcpFunc::SubscribeDhcpCommonEvent(m_mapEventSubscriber[strAction])) {
        WIFI_LOGE("SubscribeDhcpEvent SubscribeDhcpCommonEvent %{public}s failed!", strAction.c_str());
        return DHCP_OPT_FAILED;
    }
    WIFI_LOGI("SubscribeDhcpEvent %{public}s success", strAction.c_str());
#endif
    return DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::UnsubscribeDhcpEvent(const std::string &strAction)
{
    if (strAction.empty()) {
        WIFI_LOGE("UnsubscribeDhcpEvent error, strAction is empty!");
        return DHCP_OPT_ERROR;
    }
    std::unique_lock<std::mutex> lock(m_subscriberMutex);
    auto iterSubscriber = m_mapEventSubscriber.find(strAction);
    if (iterSubscriber == m_mapEventSubscriber.end()) {
        WIFI_LOGI("UnsubscribeDhcpEvent map no exist %{public}s, no need unsubscriber", strAction.c_str());
        return DHCP_OPT_SUCCESS;
    }

    if (m_mapEventSubscriber[strAction] == nullptr) {
        WIFI_LOGE("UnsubscribeDhcpEvent mapEventSubscriber %{public}s nullptr!", strAction.c_str());
        return DHCP_OPT_FAILED;
    }
#ifndef OHOS_ARCH_LITE
    if (!DhcpFunc::UnsubscribeDhcpCommonEvent(m_mapEventSubscriber[strAction])) {
        WIFI_LOGE("UnsubscribeDhcpEvent UnsubscribeDhcpCommonEvent %{public}s failed!", strAction.c_str());
        return DHCP_OPT_FAILED;
    }
#endif
    m_mapEventSubscriber.erase(iterSubscriber);
    WIFI_LOGI("UnsubscribeDhcpEvent %{public}s success", strAction.c_str());
    return DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::UnsubscribeAllDhcpEvent()
{
#ifndef OHOS_ARCH_LITE
    for (auto& e : m_mapEventSubscriber) {
        if (e.second != nullptr) {
            if (!DhcpFunc::UnsubscribeDhcpCommonEvent(e.second)) {
                WIFI_LOGE("UnsubscribeDhcpEvent UnsubscribeDhcpCommonEvent %{public}s failed!", e.first.c_str());
                return DHCP_OPT_FAILED;
            }
        }
    }
#endif
    m_mapEventSubscriber.clear();
    WIFI_LOGI("UnsubscribeDhcpEvent all dhcp event success!");
    return DHCP_OPT_SUCCESS;
}

void DhcpClientServiceImpl::RunDhcpResultHandleThreadFunc()
{
    for (; ;) {
        if (isExitDhcpResultHandleThread) {
            WIFI_LOGI("RunDhcpResultHandleThreadFunc() isExitDhcpResultHandleThread:1, break!");
            break;
        }

        uint32_t uSleepSec = SLEEP_TIME_500_MS;
        DhcpResultHandle(uSleepSec);
        usleep(uSleepSec);
    }

    WIFI_LOGI("DhcpClientServiceImpl::RunDhcpResultHandleThreadFunc() end!");
}

#ifdef OHOS_ARCH_LITE
void DhcpClientServiceImpl::RunDhcpRecvMsgThreadFunc(const std::string &ifname)
{
    if (ifname.empty()) {
        WIFI_LOGE("DhcpClientServiceImpl::RunDhcpRecvMsgThreadFunc() error, ifname is empty!");
        return;
    }

    struct DhcpPacketResult result;
    std::string strResultFile = DHCP_WORK_DIR + ifname + DHCP_RESULT_FILETYPE;
    for (; ;) {
        /* Check break condition. */
        pthread_mutex_lock(&m_DhcpResultInfoMutex);
        auto iter = this->m_mapDhcpInfo.find(ifname);
        if ((iter != this->m_mapDhcpInfo.end()) && ((iter->second).clientRunStatus) != 1) {
            pthread_mutex_unlock(&m_DhcpResultInfoMutex);
            WIFI_LOGI("RunDhcpRecvMsgThreadFunc() Status != 1, need break, ifname:%{public}s.", ifname.c_str());
            break;
        }
        pthread_mutex_unlock(&m_DhcpResultInfoMutex);

        /* Check dhcp result file is or not exist. */
        if (!DhcpFunc::IsExistFile(strResultFile)) {
            usleep(SLEEP_TIME_200_MS);
            continue;
        }

        if (memset_s(&result, sizeof(result), 0, sizeof(result)) != EOK) {
            return;
        }
        int nGetRet = DhcpFunc::GetDhcpPacketResult(strResultFile, result);
        if (nGetRet == DHCP_OPT_SUCCESS) {
            /* Get success, add or reload dhcp packet info. */
            this->DhcpPacketInfoHandle(ifname, result);
            usleep(SLEEP_TIME_500_MS);
        } else if (nGetRet == DHCP_OPT_FAILED) {
            /* Get failed, print dhcp packet info. */
            this->DhcpPacketInfoHandle(ifname, result, false);
            usleep(SLEEP_TIME_500_MS);
        } else {
            /* Get null, continue get dhcp packet info. */
            WIFI_LOGI("RunDhcpRecvMsgThreadFunc() GetDhcpPacketResult NULL, ifname:%{public}s.", ifname.c_str());
            usleep(SLEEP_TIME_200_MS);
        }
    }
}

void DhcpClientServiceImpl::DhcpPacketInfoHandle(
    const std::string &ifname, struct DhcpPacketResult &packetResult, bool success)
{
    if (ifname.empty()) {
        WIFI_LOGE("DhcpClientServiceImpl::DhcpPacketInfoHandle() error, ifname is empty!");
        return;
    }

    DhcpResult result;
    if (!success) {
        PushDhcpResult(ifname, result);
        return;
    }

    /* get success, add or reload dhcp packet info */
    auto iterInfo = m_mapDhcpInfo.find(ifname);
    if (iterInfo != m_mapDhcpInfo.end()) {
        m_mapDhcpInfo[ifname].serverIp = packetResult.strOptServerId;
    }

    result.iptype = 0;
    result.isOptSuc = true;
    result.strYourCli = packetResult.strYiaddr;
    result.strServer = packetResult.strOptServerId;
    result.strSubnet = packetResult.strOptSubnet;
    result.strDns1 = packetResult.strOptDns1;
    result.strDns2 = packetResult.strOptDns2;
    result.strRouter1 = packetResult.strOptRouter1;
    result.strRouter2 = packetResult.strOptRouter2;
    result.strVendor = packetResult.strOptVendor;
    result.uLeaseTime = packetResult.uOptLeasetime;
    result.uAddTime = packetResult.uAddTime;
    result.uGetTime = (uint32_t)time(NULL);
    PushDhcpResult(ifname, result);
    WIFI_LOGI("DhcpPacketInfoHandle %{public}s, type:%{public}d, opt:%{public}d, cli:%{private}s, server:%{private}s, "
        "strSubnet:%{private}s, Dns1:%{private}s, Dns2:%{private}s, strRouter1:%{private}s, strRouter2:%{private}s, "
        "strVendor:%{public}s, uLeaseTime:%{public}u, uAddTime:%{public}u, uGetTime:%{public}u.",
        ifname.c_str(), result.iptype, result.isOptSuc, result.strYourCli.c_str(), result.strServer.c_str(),
        result.strSubnet.c_str(), result.strDns1.c_str(), result.strDns2.c_str(), result.strRouter1.c_str(),
        result.strRouter2.c_str(), result.strVendor.c_str(), result.uLeaseTime, result.uAddTime, result.uGetTime);
}
#endif

int DhcpClientServiceImpl::ForkExecChildProcess(const std::string &ifname, bool bIpv6, bool bStart)
{
    if (bIpv6) {
        /* get ipv4 and ipv6 */
        if (bStart) {
            const char *args[DHCP_CLI_ARGSNUM] = {DHCP_CLIENT_FILE.c_str(), "start", ifname.c_str(), "-a", nullptr};
            if (execv(args[0], const_cast<char *const *>(args)) == -1) {
                WIFI_LOGE("execv start v4 v6 failed,errno:%{public}d,ifname:%{public}s", errno, ifname.c_str());
            }
        } else {
            const char *args[DHCP_CLI_ARGSNUM] = {DHCP_CLIENT_FILE.c_str(), "stop", ifname.c_str(), "-a", nullptr};
            if (execv(args[0], const_cast<char *const *>(args)) == -1) {
                WIFI_LOGE("execv stop v4 v6 failed,errno:%{public}d,ifname:%{public}s", errno, ifname.c_str());
            }
        }
    } else {
        /* only get ipv4 */
        if (bStart) {
            const char *args[DHCP_CLI_ARGSNUM] = {DHCP_CLIENT_FILE.c_str(), "start", ifname.c_str(), "-4", nullptr};
            if (execv(args[0], const_cast<char *const *>(args)) == -1) {
                WIFI_LOGE("execv start v4 failed,errno:%{public}d,ifname:%{public}s", errno, ifname.c_str());
            }
        } else {
            const char *args[DHCP_CLI_ARGSNUM] = {DHCP_CLIENT_FILE.c_str(), "stop", ifname.c_str(), "-4", nullptr};
            if (execv(args[0], const_cast<char *const *>(args)) == -1) {
                WIFI_LOGE("execv stop v4 failed,errno:%{public}d,ifname:%{public}s", errno, ifname.c_str());
            }
        }
    }
    _exit(-1);
}

int DhcpClientServiceImpl::DealParentProcessStart(const std::string& ifname, bool bIpv6, pid_t pid)
{
    std::string strAction = OHOS::Wifi::COMMON_EVENT_DHCP_GET_IPV4 + "." + ifname;
#ifdef OHOS_ARCH_LITE
    /* check and new receive dhcp packet msg thread */
    std::unique_lock<std::mutex> lock(mRecvMsgThreadMutex);
    auto iterRecvMsgThread = m_mapDhcpRecvMsgThread.find(ifname);
    if (iterRecvMsgThread != m_mapDhcpRecvMsgThread.end()) {
        WIFI_LOGE("ForkExecParentProcess() RecvMsgThread exist ifname:%{public}s, need erase!", ifname.c_str());
        return DHCP_OPT_FAILED;
    }
    std::thread *pThread = new std::thread(&DhcpClientServiceImpl::RunDhcpRecvMsgThreadFunc, this, ifname);
    if (pThread == nullptr) {
        WIFI_LOGE("ForkExecParentProcess() init pThread failed, ifname:%{public}s.", ifname.c_str());
        return DHCP_OPT_FAILED;
    }
    m_mapDhcpRecvMsgThread.emplace(std::make_pair(ifname, pThread));
#endif
    /* normal started, update dhcp client service running status */
    pthread_mutex_lock(&m_DhcpResultInfoMutex);
    auto iter = DhcpClientServiceImpl::m_mapDhcpInfo.find(ifname);
    if (iter != DhcpClientServiceImpl::m_mapDhcpInfo.end()) {
        DhcpClientServiceImpl::m_mapDhcpInfo[ifname].enableIPv6 = bIpv6;
        DhcpClientServiceImpl::m_mapDhcpInfo[ifname].clientRunStatus = 1;
        DhcpClientServiceImpl::m_mapDhcpInfo[ifname].clientProPid = pid;
    } else {
        DhcpServiceInfo dhcpInfo;
        dhcpInfo.enableIPv6 = bIpv6;
        dhcpInfo.clientRunStatus = 1;
        dhcpInfo.clientProPid = pid;
        DhcpClientServiceImpl::m_mapDhcpInfo.emplace(std::make_pair(ifname, dhcpInfo));
    }
    /* Subscribe dhcp event. */
    if (SubscribeDhcpEvent(strAction) != DHCP_OPT_SUCCESS) {
        pthread_mutex_unlock(&m_DhcpResultInfoMutex);
        return DHCP_OPT_FAILED;
    }
    pthread_mutex_unlock(&m_DhcpResultInfoMutex);
    return DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::DealParentProcessStop(const std::string& ifname, bool bIpv6, pid_t pid)
{
    pthread_mutex_lock(&m_DhcpResultInfoMutex);
    auto iter = DhcpClientServiceImpl::m_mapDhcpInfo.find(ifname);
    if (iter != DhcpClientServiceImpl::m_mapDhcpInfo.end()) {
        /* not start */
        DhcpClientServiceImpl::m_mapDhcpInfo[ifname].clientRunStatus = 0;
        DhcpClientServiceImpl::m_mapDhcpInfo[ifname].clientProPid = 0;
        pthread_mutex_unlock(&m_DhcpResultInfoMutex);
#ifdef OHOS_ARCH_LITE
        std::unique_lock<std::mutex> lock(mRecvMsgThreadMutex);
        auto iterRecvMsgThreadMap = m_mapDhcpRecvMsgThread.find(ifname);
        if (iterRecvMsgThreadMap == m_mapDhcpRecvMsgThread.end()) {
            WIFI_LOGI("ForkExecParentProcess() RecvMsgThread already del ifname:%{public}s.", ifname.c_str());
            return DHCP_OPT_SUCCESS;
        }
        if (iterRecvMsgThreadMap->second != nullptr) {
            iterRecvMsgThreadMap->second->join();
            delete iterRecvMsgThreadMap->second;
            iterRecvMsgThreadMap->second = nullptr;
            WIFI_LOGI("ForkExecParentProcess() destroy RecvThread success, ifname:%{public}s.", ifname.c_str());
        }
        WIFI_LOGI("ForkExecParentProcess() m_mapDhcpRecvMsgThread erase ifname:%{public}s.", ifname.c_str());
        m_mapDhcpRecvMsgThread.erase(iterRecvMsgThreadMap);
#endif
    } else {
        pthread_mutex_unlock(&m_DhcpResultInfoMutex);
    }
    /* UnSubscribe dhcp event. */
    std::string strAction = OHOS::Wifi::COMMON_EVENT_DHCP_GET_IPV4 + "." + ifname;
    if (UnsubscribeDhcpEvent(strAction) != DHCP_OPT_SUCCESS) {
        return DHCP_OPT_FAILED;
    }
    return DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::ForkExecParentProcess(const std::string &ifname, bool bIpv6, bool bStart, pid_t pid)
{
    if (bStart) {
        return DealParentProcessStart(ifname, bStart, pid);
    } else {
        return DealParentProcessStop(ifname, bStart, pid);
    }
}

pid_t DhcpClientServiceImpl::GetDhcpClientProPid(const std::string &ifname)
{
    if (ifname.empty()) {
        WIFI_LOGE("GetDhcpClientProPid() error, ifname is empty!");
        return 0;
    }
    pthread_mutex_lock(&m_DhcpResultInfoMutex);
    auto iter = DhcpClientServiceImpl::m_mapDhcpInfo.find(ifname);
    if (iter == DhcpClientServiceImpl::m_mapDhcpInfo.end()) {
        pthread_mutex_unlock(&m_DhcpResultInfoMutex);
        WIFI_LOGI("GetDhcpClientProPid() m_mapDhcpInfo no find ifname:%{public}s.", ifname.c_str());
        return 0;
    }

    std::string pidFile = DHCP_WORK_DIR + ifname + DHCP_CLIENT_PID_FILETYPE;
    pid_t newPid = DhcpFunc::GetPID(pidFile);
    if ((newPid > 0) && (newPid != (iter->second).clientProPid)) {
        WIFI_LOGI("GetDhcpClientProPid() GetPID %{public}s new pid:%{public}d, old pid:%{public}d, need update.",
            pidFile.c_str(), newPid, (iter->second).clientProPid);
        DhcpClientServiceImpl::m_mapDhcpInfo[ifname].clientProPid = newPid;
    }
    pid_t clientProPid = DhcpClientServiceImpl::m_mapDhcpInfo[ifname].clientProPid;
    pthread_mutex_unlock(&m_DhcpResultInfoMutex);
    WIFI_LOGI("GetDhcpClientProPid() m_mapDhcpInfo find ifname:%{public}s, pid:%{public}d.",
        ifname.c_str(), clientProPid);
    return clientProPid;
}

int DhcpClientServiceImpl::CheckDhcpClientRunning(const std::string &ifname)
{
    if (ifname.empty()) {
        WIFI_LOGE("CheckDhcpClientRunning param error, ifname is empty!");
        return DHCP_OPT_ERROR;
    }

    std::string pidFile = DHCP_WORK_DIR + ifname + DHCP_CLIENT_PID_FILETYPE;
    pid_t pid = DhcpFunc::GetPID(pidFile);
    if (pid <= 0) {
        return DHCP_OPT_SUCCESS;
    }

    int nRet = DhcpFunc::CheckProRunning(pid, DHCP_CLIENT_FILE);
    if (nRet == -1) {
        WIFI_LOGE("CheckDhcpClientRunning %{public}s failed, pid:%{public}d", ifname.c_str(), pid);
        return DHCP_OPT_FAILED;
    }
    if (nRet == 0) {
        WIFI_LOGI("CheckDhcpClientRunning %{public}s, %{public}s is not running, need remove %{public}s",
            ifname.c_str(), DHCP_CLIENT_FILE.c_str(), pidFile.c_str());
        DhcpFunc::RemoveFile(pidFile);
    } else {
        WIFI_LOGI("CheckDhcpClientRunning %{public}s, %{public}s is running, pid:%{public}d",
            ifname.c_str(), DHCP_CLIENT_FILE.c_str(), pid);
        int nStatus = GetDhcpStatus(ifname);
        if (nStatus == -1) {
            nStatus = StopDhcpClient(ifname, false);
            WIFI_LOGI("CheckDhcpClientRunning, NOT find dhcp info, stop dhcp client, nStatus:%{public}d", nStatus);
        }
    }

    WIFI_LOGI("CheckDhcpClientRunning %{public}s finished, pid:%{public}d, pro:%{public}s",
        ifname.c_str(), pid, DHCP_CLIENT_FILE.c_str());
    return DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::GetSuccessIpv4Result(const std::vector<std::string> &splits)
{
    /* Result format - ifname,time,cliIp,lease,servIp,subnet,dns1,dns2,router1,router2,vendor */
    if ((splits.size() != EVENT_DATA_NUM) || (splits[DHCP_NUM_TWO] == INVALID_STRING)) {
        WIFI_LOGE("GetSuccessIpv4Result() splits.size:%{public}d cliIp:%{public}s error!", (int)splits.size(),
            splits[DHCP_NUM_TWO].c_str());
        return DHCP_OPT_FAILED;
    }

    DhcpResult result;
    result.uAddTime = atoi(splits[DHCP_NUM_ONE].c_str());
    result.iptype = 0;
    std::string ifname = splits[DHCP_NUM_ZERO];
    if (CheckDhcpResultExist(ifname, result)) {
        WIFI_LOGI("GetSuccessIpv4Result() %{public}s equal new %{public}u, no need update.",
            ifname.c_str(), result.uAddTime);
        return DHCP_OPT_SUCCESS;
    }

    WIFI_LOGI("GetSuccessIpv4Result() DhcpResult %{public}s no equal new %{public}u, need update...",
        ifname.c_str(), result.uAddTime);

    /* Reload dhcp packet info. */
    auto iterInfo = DhcpClientServiceImpl::m_mapDhcpInfo.find(ifname);
    if (iterInfo != DhcpClientServiceImpl::m_mapDhcpInfo.end()) {
        WIFI_LOGI("GetSuccessIpv4Result() m_mapDhcpInfo find ifname:%{public}s.", ifname.c_str());
        DhcpClientServiceImpl::m_mapDhcpInfo[ifname].serverIp = splits[DHCP_NUM_FOUR];
    }

    result.isOptSuc     = true;
    result.strYourCli   = splits[DHCP_NUM_TWO];
    result.uLeaseTime   = atoi(splits[DHCP_NUM_THREE].c_str());
    result.strServer    = splits[DHCP_NUM_FOUR];
    result.strSubnet    = splits[DHCP_NUM_FIVE];
    result.strDns1      = splits[DHCP_NUM_SIX];
    result.strDns2      = splits[DHCP_NUM_SEVEN];
    result.strRouter1   = splits[DHCP_NUM_EIGHT];
    result.strRouter2   = splits[DHCP_NUM_NINE];
    result.strVendor    = splits[DHCP_NUM_TEN];
    result.uGetTime     = (uint32_t)time(NULL);
    PushDhcpResult(ifname, result);
    WIFI_LOGI("GetSuccessIpv4Result() %{public}s, %{public}d, opt:%{public}d, cli:%{private}s, server:%{private}s, "
        "strSubnet:%{private}s, strDns1:%{private}s, Dns2:%{private}s, strRouter1:%{private}s, Router2:%{private}s, "
        "strVendor:%{public}s, uLeaseTime:%{public}u, uAddTime:%{public}u, uGetTime:%{public}u.",
        ifname.c_str(), result.iptype, result.isOptSuc, result.strYourCli.c_str(), result.strServer.c_str(),
        result.strSubnet.c_str(), result.strDns1.c_str(), result.strDns2.c_str(), result.strRouter1.c_str(),
        result.strRouter2.c_str(), result.strVendor.c_str(), result.uLeaseTime, result.uAddTime, result.uGetTime);
    return DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::GetDhcpEventIpv4Result(const int code, const std::vector<std::string> &splits)
{
    /* Result format - ifname,time,cliIp,lease,servIp,subnet,dns1,dns2,router1,router2,vendor */
    if (splits.size() != EVENT_DATA_NUM) {
        WIFI_LOGE("GetDhcpEventIpv4Result() splits.size:%{public}d error!", (int)splits.size());
        return DHCP_OPT_FAILED;
    }

    /* Check field ifname and time. */
    if (splits[DHCP_NUM_ZERO].empty() || splits[DHCP_NUM_ONE].empty()) {
        WIFI_LOGE("GetDhcpEventIpv4Result() ifname or time is empty!");
        return DHCP_OPT_FAILED;
    }

    /* Check field cliIp. */
    if (((code == PUBLISH_CODE_SUCCESS) && (splits[DHCP_NUM_TWO] == INVALID_STRING))
    || ((code == PUBLISH_CODE_FAILED) && (splits[DHCP_NUM_TWO] != INVALID_STRING))) {
        WIFI_LOGE("GetDhcpEventIpv4Result() code:%{public}d,%{public}s error!", code, splits[DHCP_NUM_TWO].c_str());
        return DHCP_OPT_FAILED;
    }

    std::string ifname = splits[DHCP_NUM_ZERO];
    if (code == PUBLISH_CODE_FAILED) {
        /* Get failed. */
        DhcpResult result;
        result.iptype = 0;
        result.isOptSuc = false;
        result.uAddTime = atoi(splits[DHCP_NUM_ONE].c_str());
        PushDhcpResult(ifname, result);
        WIFI_LOGI("GetDhcpEventIpv4Result() ifname:%{public}s result.isOptSuc:false!", ifname.c_str());
        return DHCP_OPT_SUCCESS;
    }

    /* Get success. */
    if (GetSuccessIpv4Result(splits) != DHCP_OPT_SUCCESS) {
        WIFI_LOGE("GetDhcpEventIpv4Result() GetSuccessIpv4Result failed!");
        return DHCP_OPT_FAILED;
    }
    WIFI_LOGI("GetDhcpEventIpv4Result() ifname:%{public}s result.isOptSuc:true!", ifname.c_str());
    return DHCP_OPT_SUCCESS;
}

bool DhcpClientServiceImpl::CheckDhcpResultExist(const std::string &ifname, DhcpResult &result)
{
    bool exist = false;
    pthread_mutex_lock(&m_DhcpResultInfoMutex);
    auto iterResult = m_mapDhcpResult.find(ifname);
    if (iterResult != m_mapDhcpResult.end()) {
        for (int i = 0; i < iterResult->second.size(); i++) {
            if (iterResult->second[i].iptype != result.iptype) {
                continue;
            }
            if (iterResult->second[i].uAddTime == result.uAddTime) {
                exist = true;
                break;
            }
        }
    }
    pthread_mutex_unlock(&m_DhcpResultInfoMutex);
    return exist;
}

void DhcpClientServiceImpl::PushDhcpResult(const std::string &ifname, DhcpResult &result)
{
    pthread_mutex_lock(&m_DhcpResultInfoMutex);
    auto iterResult = m_mapDhcpResult.find(ifname);
    if (iterResult != m_mapDhcpResult.end()) {
        for (int i = 0; i < iterResult->second.size(); i++) {
            if (iterResult->second[i].iptype != result.iptype) {
                continue;
            }
            if (iterResult->second[i].iptype == 0) {
                if (iterResult->second[i].uAddTime != result.uAddTime) {
                    iterResult->second[i] = result;
                }
            } else {
                iterResult->second[i] = result;
            }
            pthread_mutex_unlock(&m_DhcpResultInfoMutex);
            return;
        }
        iterResult->second.push_back(result);
    } else {
        std::vector<DhcpResult> results;
        results.push_back(result);
        m_mapDhcpResult.emplace(std::make_pair(ifname, results));
    }
    pthread_mutex_unlock(&m_DhcpResultInfoMutex);
}

int DhcpClientServiceImpl::DhcpEventResultHandle(const int code, const std::string &data)
{
    if (data.empty()) {
        WIFI_LOGE("DhcpClientServiceImpl::DhcpEventResultHandle() error, data is empty!");
        return DHCP_OPT_FAILED;
    }
    WIFI_LOGI("Enter DhcpEventResultHandle() code:%{public}d,data:%{private}s.", code, data.c_str());

    /* Data format - ipv4:ifname,time,cliIp,lease,servIp,subnet,dns1,dns2,router1,router2,vendor */
    std::string strData(data);
    std::string strFlag;
    std::string strResult;
    if (strData.find(EVENT_DATA_IPV4) != std::string::npos) {
        strFlag = strData.substr(0, (int)EVENT_DATA_IPV4.size());
        if (strFlag != EVENT_DATA_IPV4) {
            WIFI_LOGE("DhcpEventResultHandle() %{public}s ipv4flag:%{public}s error!", data.c_str(), strFlag.c_str());
            return DHCP_OPT_FAILED;
        }
        /* Skip separator ":" */
        strResult = strData.substr((int)EVENT_DATA_IPV4.size() + 1);
    } else if (strData.find(EVENT_DATA_IPV6) != std::string::npos) {
        strFlag = strData.substr(0, (int)EVENT_DATA_IPV6.size());
        if (strFlag != EVENT_DATA_IPV6) {
            WIFI_LOGE("DhcpEventResultHandle() %{public}s ipv6flag:%{public}s error!", data.c_str(), strFlag.c_str());
            return DHCP_OPT_FAILED;
        }
        strResult = strData.substr((int)EVENT_DATA_IPV6.size() + 1);
    } else {
        WIFI_LOGE("DhcpEventResultHandle() data:%{public}s error, no find ipflag!", data.c_str());
        return DHCP_OPT_FAILED;
    }
    WIFI_LOGI("DhcpEventResultHandle() flag:%{public}s, result:%{private}s.", strFlag.c_str(), strResult.c_str());

    if (strFlag == EVENT_DATA_IPV4) {
        std::vector<std::string> vecSplits;
        if (!DhcpFunc::SplitString(strResult, EVENT_DATA_DELIMITER, EVENT_DATA_NUM, vecSplits)) {
            WIFI_LOGE("DhcpEventResultHandle() SplitString strResult:%{public}s failed!", strResult.c_str());
            return DHCP_OPT_FAILED;
        }

        if (GetDhcpEventIpv4Result(code, vecSplits) != DHCP_OPT_SUCCESS) {
            WIFI_LOGE("DhcpEventResultHandle() GetDhcpEventIpv4Result failed!");
            return DHCP_OPT_FAILED;
        }
    }

    return DHCP_OPT_SUCCESS;
}

void DhcpClientServiceImpl::RunIpv6ThreadFunc()
{
    ipv6Client.DhcpIpv6Start(currIfName.c_str());
}

void DhcpClientServiceImpl::OnAddressChangedCallback(const std::string ifname, DhcpIpv6Info &info)
{
    if (strlen(info.globalIpv6Addr) == 0 || strlen(info.routeAddr) == 0) {
        WIFI_LOGE("OnAddressChangedCallback invalid, ipaddr:%{private}s, route:%{private}s",
            info.globalIpv6Addr, info.routeAddr);
        return;
    }

    DhcpResult result;
    result.uAddTime = (uint32_t)time(NULL);
    result.iptype = 1;
    result.isOptSuc     = true;
    result.strYourCli   = info.globalIpv6Addr;
    result.strSubnet    = info.ipv6SubnetAddr;
    result.strRouter1   = info.routeAddr;
    result.strDns1      = info.dnsAddr;
    result.strDns2      = info.dnsAddr2;
    result.strRouter2   = "*";
    result.uGetTime     = (uint32_t)time(NULL);
    PushDhcpResult(ifname, result);
    WIFI_LOGI("OnAddressChangedCallback %{public}s, %{public}d, opt:%{public}d, cli:%{private}s, server:%{private}s, "
        "strSubnet:%{private}s, strDns1:%{private}s, Dns2:%{private}s, strRouter1:%{private}s, Router2:%{private}s, "
        "strVendor:%{public}s, uLeaseTime:%{public}u, uAddTime:%{public}u, uGetTime:%{public}u.",
        ifname.c_str(), result.iptype, result.isOptSuc, result.strYourCli.c_str(), result.strServer.c_str(),
        result.strSubnet.c_str(), result.strDns1.c_str(), result.strDns2.c_str(), result.strRouter1.c_str(),
        result.strRouter2.c_str(), result.strVendor.c_str(), result.uLeaseTime, result.uAddTime, result.uGetTime);
}

int DhcpClientServiceImpl::StartDhcpClient(const std::string &ifname, bool bIpv6)
{
    if (ifname.empty()) {
        WIFI_LOGE("DhcpClientServiceImpl::StartDhcpClient() error, ifname is empty!");
        return DHCP_OPT_FAILED;
    }
    currIfName = ifname;
    WIFI_LOGI("enter StartDhcpClient()...ifname:%{public}s, bIpv6:%{public}d.", ifname.c_str(), bIpv6);
    if (bIpv6) {
        ipv6Client.Reset();
        std::unique_lock<std::mutex> lock(m_dhcpIpv6Mutex);
        if (!pDhcpIpv6ClientThread) {
            pDhcpIpv6ClientThread = new std::thread(&DhcpClientServiceImpl::RunIpv6ThreadFunc, this);
            if (pDhcpIpv6ClientThread == nullptr) {
                WIFI_LOGE("dhcp ipv6 start client thread failed!");
            }
        }
    }
    /* check config */
    /* check dhcp client service running status */
    if (CheckDhcpClientRunning(ifname) != DHCP_OPT_SUCCESS) {
        WIFI_LOGE("StartDhcpClient CheckDhcpClientRunning ifname:%{public}s failed.", ifname.c_str());
        return DHCP_OPT_FAILED;
    }
    int nStatus = GetDhcpStatus(ifname);
    if (nStatus == 1) {
        WIFI_LOGI("StartDhcpClient() running status:%{public}d, service already started, ifname:%{public}s.",
            nStatus, ifname.c_str());
        /* reload config */
        return DHCP_OPT_SUCCESS;
    }

    /* start dhcp client service */
    pid_t pid;
    if ((pid = vfork()) < 0) {
        WIFI_LOGE("StartDhcpClient() vfork() failed, pid:%{public}d.", pid);
        return DHCP_OPT_FAILED;
    }
    if (pid == 0) {
        /* Child process */
        ForkExecChildProcess(ifname, bIpv6, true);
    } else {
        /* Parent process */
        WIFI_LOGI("StartDhcpClient() vfork %{public}d success, parent:%{public}d, begin waitpid...", pid, getpid());
        int ret = ForkExecParentProcess(ifname, bIpv6, true, pid);
        int pidRet = DhcpFunc::WaitProcessExit(pid);
        if (pidRet == 0) {
            WIFI_LOGI("StartDhcpClient() waitpid child:%{public}d success.", pid);
        } else {
            WIFI_LOGE("StartDhcpClient() waitpid child:%{public}d failed, pidRet:%{public}d!", pid, pidRet);
        }

        return ret;
    }

    return DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::StopDhcpClient(const std::string &ifname, bool bIpv6)
{
    isRenewAction = false;
    if (ifname.empty()) {
        WIFI_LOGE("DhcpClientServiceImpl::StopDhcpClient() error, ifname is empty!");
        return DHCP_OPT_FAILED;
    }

    WIFI_LOGI("enter StopDhcpClient()...ifname:%{public}s, bIpv6:%{public}d.", ifname.c_str(), bIpv6);

    /* check dhcp client service running status */
    bool bExecParentProcess = true;
    int nStatus = GetDhcpStatus(ifname);
    if (nStatus == 0) {
        WIFI_LOGI("StopDhcpClient() status:%{public}d, service already stopped, ifname:%{public}s.",
            nStatus, ifname.c_str());
        return DHCP_OPT_SUCCESS;
    } else if (nStatus == -1) {
        WIFI_LOGI("StopDhcpClient() status:%{public}d, service not start or started, not need ExecParentProcess, "
                  "ifname:%{public}s.", nStatus, ifname.c_str());
        bExecParentProcess = false;
    }

    /* stop dhcp client service */
    pid_t pid;
    if ((pid = vfork()) < 0) {
        WIFI_LOGE("StopDhcpClient() vfork() failed, pid:%{public}d.", pid);
        return DHCP_OPT_FAILED;
    }
    if (pid == 0) {
        /* Child process */
        ForkExecChildProcess(ifname, bIpv6);
        return DHCP_OPT_SUCCESS;
    } else {
        /* Parent process */
        WIFI_LOGI("StopDhcpClient() vfork %{public}d success, parent:%{public}d, begin waitpid...", pid, getpid());
        int pidRet = DhcpFunc::WaitProcessExit(pid);
        if (pidRet == 0) {
            WIFI_LOGI("StopDhcpClient() waitpid child:%{public}d success.", pid);
        } else {
            WIFI_LOGE("StopDhcpClient() waitpid child:%{public}d failed, pidRet:%{public}d!", pid, pidRet);
        }

        return bExecParentProcess ? ForkExecParentProcess(ifname, bIpv6) : DHCP_OPT_SUCCESS;
    }
}

int DhcpClientServiceImpl::GetDhcpStatus(const std::string &ifname)
{
    if (ifname.empty()) {
        WIFI_LOGE("DhcpClientServiceImpl::GetDhcpStatus() error, ifname is empty!");
        return -1;
    }
    pthread_mutex_lock(&m_DhcpResultInfoMutex);
    auto iter = DhcpClientServiceImpl::m_mapDhcpInfo.find(ifname);
    if (iter == DhcpClientServiceImpl::m_mapDhcpInfo.end()) {
        pthread_mutex_unlock(&m_DhcpResultInfoMutex);
        WIFI_LOGI("DhcpClientServiceImpl::GetDhcpStatus() m_mapDhcpInfo no find ifname:%{public}s.", ifname.c_str());
        return -1;
    }
    int clientRunStatus = (iter->second).clientRunStatus;
    pthread_mutex_unlock(&m_DhcpResultInfoMutex);
    WIFI_LOGI("GetDhcpStatus() m_mapDhcpInfo find ifname:%{public}s, clientRunStatus:%{public}d.",
        ifname.c_str(),
        clientRunStatus);
    return clientRunStatus;
}

int DhcpClientServiceImpl::GetDhcpResult(const std::string &ifname, IDhcpResultNotify *pResultNotify, int timeouts)
{
    if (ifname.empty()) {
        WIFI_LOGE("DhcpClientServiceImpl::GetDhcpResult() error, ifname is empty!");
        return DHCP_OPT_FAILED;
    }

    if (pResultNotify == nullptr) {
        WIFI_LOGE("GetDhcpResult() ifname:%{public}s error, pResultNotify is nullptr!", ifname.c_str());
        return DHCP_OPT_FAILED;
    }

    DhcpResultReq *pResultReq = new DhcpResultReq;
    if (pResultReq == nullptr) {
        WIFI_LOGE("GetDhcpResult() new failed! ifname:%{public}s.", ifname.c_str());
        return DHCP_OPT_FAILED;
    }
    pResultReq->timeouts = timeouts;
    pResultReq->getTimestamp = (uint32_t)time(NULL);
    pResultReq->status = 0;
    pResultReq->pResultNotify = pResultNotify;

    std::unique_lock<std::mutex> lock(mResultNotifyMutex);
    ReleaseResultNotifyMemory();
    m_mapDhcpResultNotify.clear();
    std::list<DhcpResultReq *> listDhcpResultReq;
    listDhcpResultReq.push_back(pResultReq);
    m_mapDhcpResultNotify.emplace(std::make_pair(ifname, listDhcpResultReq));
    WIFI_LOGI("GetDhcpResult() ifname:%{public}s,timeouts:%{public}d, result push_back!", ifname.c_str(), timeouts);
    return DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::RemoveDhcpResult(IDhcpResultNotify *pResultNotify)
{
    isRenewAction = false;
    if (pResultNotify == nullptr) {
        WIFI_LOGE("RemoveDhcpResult error, pResultNotify is nullptr!");
        return DHCP_OPT_FAILED;
    }

    std::unique_lock<std::mutex> lock(mResultNotifyMutex);
    for (auto &itemNotify : m_mapDhcpResultNotify) {
        auto iterReq = itemNotify.second.begin();
        while (iterReq != itemNotify.second.end()) {
            if ((*iterReq == nullptr) || ((*iterReq)->pResultNotify == nullptr)) {
                WIFI_LOGE("DhcpClientServiceImpl::RemoveDhcpResult error, *iterReq or pResultNotify is nullptr!");
                continue;
            }
            if ((*iterReq)->pResultNotify == pResultNotify) {
                delete *iterReq;
                *iterReq = nullptr;
                iterReq = itemNotify.second.erase(iterReq);
            } else {
                ++iterReq;
            }
        }
    }
    WIFI_LOGI("RemoveDhcpResul success!");
    return DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::GetDhcpInfo(const std::string &ifname, DhcpServiceInfo &dhcp)
{
    if (ifname.empty()) {
        WIFI_LOGE("DhcpClientServiceImpl::GetDhcpInfo() error, ifname is empty!");
        return DHCP_OPT_FAILED;
    }
    pthread_mutex_lock(&m_DhcpResultInfoMutex);
    auto iter = DhcpClientServiceImpl::m_mapDhcpInfo.find(ifname);
    if (iter != DhcpClientServiceImpl::m_mapDhcpInfo.end()) {
        dhcp = iter->second;
    } else {
        WIFI_LOGE("GetDhcpInfo() failed, m_mapDhcpInfo no find ifname:%{public}s.", ifname.c_str());
    }
    pthread_mutex_unlock(&m_DhcpResultInfoMutex);
    return DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::RenewDhcpClient(const std::string &ifname)
{
    WIFI_LOGI("enter DhcpClientServiceImpl::RenewDhcpClient(), ifname:%{public}s isRenewAction:%{public}d.",
        ifname.c_str(), isRenewAction);
    int nStatus = GetDhcpStatus(ifname);
    if (nStatus != 1) {
        WIFI_LOGW("RenewDhcpClient() dhcp client service not started, now start ifname:%{public}s.", ifname.c_str());
        /* Start dhcp client service */
        pthread_mutex_lock(&m_DhcpResultInfoMutex);
        isRenewAction = true;
        bool enableIPv6 = DhcpClientServiceImpl::m_mapDhcpInfo[ifname].enableIPv6;
        pthread_mutex_unlock(&m_DhcpResultInfoMutex);
        return StartDhcpClient(ifname, enableIPv6);
    }

    /* Send dhcp renew packet : kill -USR2 <pid> */
    pid_t pid = GetDhcpClientProPid(ifname);
    if (pid <= 0) {
        WIFI_LOGW("RenewDhcpClient() dhcp client process pid:%{public}d error, ifname:%{public}s!",
            pid, ifname.c_str());
        return DHCP_OPT_FAILED;
    }

    if (kill(pid, SIGUSR2) == -1) {
        WIFI_LOGE("RenewDhcpClient() kill [%{public}d] failed:%{public}d, ifname:%{public}s!",
            pid, errno, ifname.c_str());
        return DHCP_OPT_FAILED;
    }
    isRenewAction = true;
    WIFI_LOGI("RenewDhcpClient() kill [%{public}d] success, ifname:%{public}s.", pid, ifname.c_str());
    return DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::ReleaseDhcpClient(const std::string &ifname)
{
    WIFI_LOGI("enter DhcpClientServiceImpl::ReleaseDhcpClient()...ifname:%{public}s.", ifname.c_str());
    int nStatus = GetDhcpStatus(ifname);
    if (nStatus != 1) {
        WIFI_LOGE("ReleaseDhcpClient() failed, dhcp client service not started, ifname:%{public}s!", ifname.c_str());
        return DHCP_OPT_FAILED;
    }

    /* Send dhcp release packet : kill -USR1 <pid> */
    pid_t pid = GetDhcpClientProPid(ifname);
    if (pid <= 0) {
        WIFI_LOGW("ReleaseDhcpClient() dhcp client process pid:%{public}d error, ifname:%{public}s!",
            pid, ifname.c_str());
        return DHCP_OPT_FAILED;
    }

    if (kill(pid, SIGUSR1) == -1) {
        WIFI_LOGE("ReleaseDhcpClient() kill [%{public}d] failed:%{public}d, ifname:%{public}s!",
            pid, errno, ifname.c_str());
        return DHCP_OPT_FAILED;
    }
    WIFI_LOGI("ReleaseDhcpClient() kill [%{public}d] success, ifname:%{public}s.", pid, ifname.c_str());
    return DHCP_OPT_SUCCESS;
}
}  // namespace Wifi
}  // namespace OHOS
