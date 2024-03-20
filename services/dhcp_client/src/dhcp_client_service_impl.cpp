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
#ifndef OHOS_ARCH_LITE
#include <file_ex.h>
#endif
#include <unistd.h>
#include <csignal>
#include <sys/prctl.h>
#ifndef OHOS_ARCH_LITE
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#include "dhcp_client_death_recipient.h"
#endif
#include "dhcp_function.h"
#include "dhcp_define.h"
#include "dhcp_errcode.h"
#include "dhcp_logger.h"
#ifndef OHOS_ARCH_LITE
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "accesstoken_kit.h"
#endif

DEFINE_DHCPLOG_DHCP_LABEL("DhcpClientServiceImpl");

namespace OHOS {
namespace Wifi {
std::mutex DhcpClientServiceImpl::g_instanceLock;

#ifdef OHOS_ARCH_LITE
std::shared_ptr<DhcpClientServiceImpl> DhcpClientServiceImpl::g_instance = nullptr;
std::shared_ptr<DhcpClientServiceImpl> DhcpClientServiceImpl::GetInstance()
{
    if (g_instance == nullptr) {
        std::lock_guard<std::mutex> autoLock(g_instanceLock);
        if (g_instance == nullptr) {
            std::shared_ptr<DhcpClientServiceImpl> service = std::make_shared<DhcpClientServiceImpl>();
            g_instance = service;
        }
    }
    return g_instance;
}
#else
sptr<DhcpClientServiceImpl> DhcpClientServiceImpl::g_instance = nullptr;
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(DhcpClientServiceImpl::GetInstance().GetRefPtr());
sptr<DhcpClientServiceImpl> DhcpClientServiceImpl::GetInstance()
{
    if (g_instance == nullptr) {
        std::lock_guard<std::mutex> autoLock(g_instanceLock);
        if (g_instance == nullptr) {
            DHCP_LOGI("new DhcpClientServiceImpl GetInstance()");
            sptr<DhcpClientServiceImpl> service = new (std::nothrow) DhcpClientServiceImpl;
            g_instance = service;
        }
    }
    return g_instance;
}
#endif

DhcpClientServiceImpl::DhcpClientServiceImpl()
#ifndef OHOS_ARCH_LITE
    : SystemAbility(DHCP_CLIENT_ABILITY_ID, true), mPublishFlag(false),
    mState(ClientServiceRunningState::STATE_NOT_START)
#endif
{
    DHCP_LOGI("enter DhcpClientServiceImpl()");
    m_mapClientService.clear();
    m_mapDhcpResult.clear();
    m_mapClientCallBack.clear();
    CreateDirs(DHCP_WORK_DIR.c_str(), DIR_DEFAULT_MODE);
}

DhcpClientServiceImpl::~DhcpClientServiceImpl()
{
    DHCP_LOGI("enter ~DhcpClientServiceImpl()");
    auto iter = m_mapClientService.begin();
    while(iter != m_mapClientService.end()) {
        if ((iter->second).pipv6Client != nullptr) {
            delete (iter->second).pipv6Client;
            (iter->second).pipv6Client = nullptr; 
        }
        if ((iter->second).pStaStateMachine != nullptr) {
            delete (iter->second).pStaStateMachine;
            (iter->second).pStaStateMachine = nullptr;   
        }
        iter++;
    }
}

void DhcpClientServiceImpl::OnStart()
{
    DHCP_LOGI("enter Client OnStart");
    if (mState == ClientServiceRunningState::STATE_RUNNING) {
        DHCP_LOGW("Service has already started.");
        return;
    }
    if (!Init()) {
        DHCP_LOGE("Failed to init dhcp client service");
        OnStop();
        return;
    }
    mState = ClientServiceRunningState::STATE_RUNNING;
    DHCP_LOGI("Client Service has started.");
}

void DhcpClientServiceImpl::OnStop()
{
    mPublishFlag = false;
    DHCP_LOGI("OnStop dhcp client service!");
}

bool DhcpClientServiceImpl::Init()
{
    DHCP_LOGI("enter client Init");
    if (!mPublishFlag) {
#ifdef OHOS_ARCH_LITE
        bool ret = true;
#else
        bool ret = Publish(DhcpClientServiceImpl::GetInstance());
#endif
        if (!ret) {
            DHCP_LOGE("Failed to publish dhcp client service!");
            return false;
        }
        mPublishFlag = true;
    }
    return true;
}

#ifndef OHOS_ARCH_LITE
void DhcpClientServiceImpl::StartServiceAbility(int sleepS)
{
    DHCP_LOGI("enter StartServiceAbility()");
    sptr<ISystemAbilityManager> serviceManager;
    int retryTimeout = MAXRETRYTIMEOUT;
    while (retryTimeout > 0) {
        --retryTimeout;
        if (sleepS > 0) {
            sleep(sleepS);
        }

        SystemAbilityManagerClient::GetInstance().DestroySystemAbilityManagerObject();
        serviceManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (serviceManager == nullptr) {
            DHCP_LOGI("serviceManager is nullptr, continue");
            continue;
        }
        OHOS::sptr<OHOS::Wifi::DhcpClientServiceImpl> clientServiceImpl =
            OHOS::Wifi::DhcpClientServiceImpl::GetInstance();
        int result = serviceManager->AddSystemAbility(DHCP_CLIENT_ABILITY_ID, clientServiceImpl);
        if (result != 0) {
            DHCP_LOGE("AddSystemAbility AddSystemAbility error:%{public}d", result);
            continue;
        }
        DHCP_LOGI("AddSystemAbility break");
        break;
    }

    if (serviceManager == nullptr) {
        DHCP_LOGE("serviceManager == nullptr");
        return;
    }

    auto abilityObjext = serviceManager->AsObject();
    if (abilityObjext == nullptr) {
        DHCP_LOGE("AsObject() == nullptr");
        return;
    }

    bool ret = abilityObjext->AddDeathRecipient(new DhcpClientDeathRecipient());
    if (ret == false) {
        DHCP_LOGE("DhcpClientServiceImpl AddDeathRecipient == false");
        return;
    }
    DHCP_LOGI("StartServiceAbility over!");
}
#endif

#ifdef OHOS_ARCH_LITE
ErrCode DhcpClientServiceImpl::RegisterDhcpClientCallBack(const std::string& ifname,
    const std::shared_ptr<IDhcpClientCallBack> &clientCallback)
#else
ErrCode DhcpClientServiceImpl::RegisterDhcpClientCallBack(const std::string& ifname,
    const sptr<IDhcpClientCallBack> &clientCallback)
#endif
{
    if (!IsNativeProcess()) {
        DHCP_LOGE("RegisterDhcpClientCallBack:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    std::lock_guard<std::mutex> autoLock(m_clientCallBackMutex);
    auto iter = m_mapClientCallBack.find(ifname);
    if (iter != m_mapClientCallBack.end()) {
        (iter->second) = clientCallback;
        DHCP_LOGI("RegisterDhcpClientCallBack find ifname update clientCallback, ifname:%{public}s", ifname.c_str());
    } else {
#ifdef OHOS_ARCH_LITE
        std::shared_ptr<IDhcpClientCallBack> mclientCallback = clientCallback;
#else
        sptr<IDhcpClientCallBack> mclientCallback = clientCallback;
#endif
        m_mapClientCallBack.emplace(std::make_pair(ifname, mclientCallback));
        DHCP_LOGI("RegisterDhcpClientCallBack add ifname and mclientCallback, ifname:%{public}s", ifname.c_str());
    }
    return DHCP_E_SUCCESS;
}

ErrCode DhcpClientServiceImpl::StartDhcpClient(const std::string& ifname, bool bIpv6)
{
    DHCP_LOGI("StartDhcpClient ifName:%{public}s bIpv6:%{public}d", ifname.c_str(), bIpv6);
    if (!IsNativeProcess()) {
        DHCP_LOGE("StartDhcpClient:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    std::lock_guard<std::mutex> autoLock(m_clientServiceMutex);
    auto iter = m_mapClientService.find(ifname);
    if (iter != m_mapClientService.end()) {
        return StartOldClient(ifname, bIpv6, iter->second);
    } else {
        return StartNewClient(ifname, bIpv6);
    }
}

ErrCode DhcpClientServiceImpl::StartOldClient(const std::string& ifname, bool bIpv6, DhcpClient &dhcpClient)
{
    DHCP_LOGI("StartOldClient ifname:%{public}s bIpv6:%{public}d", ifname.c_str(), bIpv6);
    if (dhcpClient.pStaStateMachine == nullptr) {
        DHCP_LOGE("StartOldClient pStaStateMachine is null!");
        return DHCP_E_FAILED;
    }
    dhcpClient.pStaStateMachine->StartIpv4Type(ifname, bIpv6, ACTION_START_OLD);
    if (bIpv6) {
        if (dhcpClient.pipv6Client == nullptr) {
            DHCP_LOGE("StartOldClient pipv6Client is null!");
            DhcpIpv6Client *pipv6Client  = new (std::nothrow)DhcpIpv6Client(ifname);
            if (pipv6Client == nullptr) {
                DHCP_LOGE("StartOldClient new DhcpIpv6Client failed!, ifname:%{public}s", ifname.c_str());
                return DHCP_E_FAILED;
            }
            dhcpClient.pipv6Client = pipv6Client;
            DHCP_LOGI("StartOldClient new DhcpIpv6Client, ifname:%{public}s, bIpv6:%{public}d", ifname.c_str(), bIpv6);
            pipv6Client->Reset();
            pipv6Client->SetCallback(std::bind(&DhcpClientServiceImpl::DhcpIpv6ResulCallback, this,
            std::placeholders::_1, std::placeholders::_2));
        }
        dhcpClient.pipv6Client->StartIpv6Thread(ifname, bIpv6);
    }
    return DHCP_E_SUCCESS;
}

ErrCode DhcpClientServiceImpl::StartNewClient(const std::string& ifname, bool bIpv6)
{
    DHCP_LOGI("StartNewClient ifname:%{public}s, bIpv6:%{public}d", ifname.c_str(), bIpv6);
    DhcpClient client;
    if (bIpv6) {
        DhcpIpv6Client *pipv6Client  = new (std::nothrow)DhcpIpv6Client(ifname);
        if (pipv6Client == nullptr) {
            DHCP_LOGE("StartNewClient new DhcpIpv6Client failed!, ifname:%{public}s", ifname.c_str());
            return DHCP_E_FAILED;
        }
        client.pipv6Client = pipv6Client;
        DHCP_LOGI("StartNewClient new DhcpIpv6Client, ifname:%{public}s, bIpv6:%{public}d", ifname.c_str(), bIpv6);
        pipv6Client->Reset();
        pipv6Client->SetCallback(std::bind(&DhcpClientServiceImpl::DhcpIpv6ResulCallback, this, std::placeholders::_1,
            std::placeholders::_2));
        pipv6Client->StartIpv6Thread(ifname, bIpv6);
    }
    DhcpClientStateMachine *pStaState = new (std::nothrow)DhcpClientStateMachine(ifname);
    if (pStaState == nullptr) {
        DHCP_LOGE("StartNewClient new DhcpClientStateMachine failed!, ifname:%{public}s", ifname.c_str());
        return DHCP_E_FAILED;
    }
    client.ifName = ifname;
    client.isIpv6 = bIpv6;
    client.pStaStateMachine = pStaState;
    m_mapClientService.emplace(std::make_pair(ifname, client));
    DHCP_LOGI("StartNewClient new DhcpClientStateMachine, ifname:%{public}s, bIpv6:%{public}d", ifname.c_str(), bIpv6);
    pStaState->StartIpv4Type(ifname, bIpv6, ACTION_START_NEW);
    return DHCP_E_SUCCESS;
}

ErrCode DhcpClientServiceImpl::StopDhcpClient(const std::string& ifname, bool bIpv6)
{
    DHCP_LOGI("StopDhcpClient ifName:%{public}s, bIpv6:%{public}d", ifname.c_str(), bIpv6);
    if (!IsNativeProcess()) {
        DHCP_LOGE("StopDhcpClient:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    std::lock_guard<std::mutex> autoLock(m_clientServiceMutex);
    auto iter2 = m_mapClientService.find(ifname);
    if (iter2 != m_mapClientService.end()) {
        if ((iter2->second).pStaStateMachine != nullptr && (!bIpv6)) {
            DHCP_LOGI("StopDhcpClient pStaStateMachine StopIpv4, ifname:%{public}s, bIpv6:%{public}d", ifname.c_str(),
                bIpv6);
            (iter2->second).pStaStateMachine->StopIpv4();
#ifndef OHOS_ARCH_LITE
            (iter2->second).pStaStateMachine->StopGetIpTimer();
#endif
        }
        if ((iter2->second).pipv6Client != nullptr && bIpv6) {
            DHCP_LOGI("StopDhcpClient pipv6Client DhcpIPV6Stop, ifname:%{public}s, bIpv6:%{public}d", ifname.c_str(),
                bIpv6);
            (iter2->second).pipv6Client->DhcpIPV6Stop();
        }
    }
    return DHCP_E_SUCCESS;
}

ErrCode DhcpClientServiceImpl::RenewDhcpClient(const std::string& ifname)
{
    DHCP_LOGI("RenewDhcpClient ifName:%{public}s", ifname.c_str());
    if (!IsNativeProcess()) {
        DHCP_LOGE("RenewDhcpClient:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    std::lock_guard<std::mutex> autoLock(m_clientServiceMutex);
    auto iter = m_mapClientService.find(ifname);
    if (iter != m_mapClientService.end()) {
        if ((iter->second).pStaStateMachine != nullptr) {
            DHCP_LOGI("RenewDhcpClient StartIpv4Type, ifname:%{public}s, bIpv6:%{public}d", ifname.c_str(),
                (iter->second).isIpv6);
            (iter->second).pStaStateMachine->StartIpv4Type(ifname, (iter->second).isIpv6, ACTION_RENEW);
        } else {
            (iter->second).pStaStateMachine = new (std::nothrow)DhcpClientStateMachine(ifname);
            if ((iter->second).pStaStateMachine == nullptr) {
                DHCP_LOGE("RenewDhcpClient new pStaStateMachine failed!, ifname:%{public}s", ifname.c_str());
                return DHCP_E_FAILED;
            }
            DHCP_LOGE("RenewDhcpClient new pStaStateMachine, ifname:%{public}s, bIpv6:%{public}d", ifname.c_str(),
                (iter->second).isIpv6);
            (iter->second).pStaStateMachine->StartIpv4Type(ifname, (iter->second).isIpv6, ACTION_RENEW);
        }

        if (((iter->second).pipv6Client != nullptr) && ((iter->second).isIpv6)) {
            DHCP_LOGI("RenewDhcpClient not supported!");
        }
    }
    return DHCP_E_SUCCESS;
}

int DhcpClientServiceImpl::DhcpIpv4ResultSuccess(const std::vector<std::string> &splits)
{
    /* Result format - ifname,time,cliIp,lease,servIp,subnet,dns1,dns2,router1,router2,vendor */
    std::string ifname = splits[OHOS::Wifi::DHCP_NUM_ZERO];
    OHOS::Wifi::DhcpResult result;
    result.iptype = 0;
    result.isOptSuc = true;
    result.uGetTime = (uint32_t)time(NULL);
    result.uAddTime = atoi(splits[OHOS::Wifi::DHCP_NUM_ONE].c_str());
    result.strYourCli   = splits[OHOS::Wifi::DHCP_NUM_TWO];
    result.uLeaseTime   = atoi(splits[OHOS::Wifi::DHCP_NUM_THREE].c_str());
    result.strServer    = splits[OHOS::Wifi::DHCP_NUM_FOUR];
    result.strSubnet    = splits[OHOS::Wifi::DHCP_NUM_FIVE];
    result.strDns1      = splits[OHOS::Wifi::DHCP_NUM_SIX];
    result.strDns2      = splits[OHOS::Wifi::DHCP_NUM_SEVEN];
    result.strRouter1   = splits[OHOS::Wifi::DHCP_NUM_EIGHT];
    result.strRouter2   = splits[OHOS::Wifi::DHCP_NUM_NINE];
    result.strVendor    = splits[OHOS::Wifi::DHCP_NUM_TEN];
    DHCP_LOGI("DhcpIpv4ResultSuccess %{public}s, %{public}d, opt:%{public}d, cli:%{private}s, server:%{private}s, "
        "Subnet:%{private}s, Dns1:%{private}s, Dns2:%{private}s, Router1:%{private}s, Router2:%{private}s, "
        "strVendor:%{public}s, uLeaseTime:%{public}u, uAddTime:%{public}u, uGetTime:%{public}u.",
        ifname.c_str(), result.iptype, result.isOptSuc, result.strYourCli.c_str(), result.strServer.c_str(),
        result.strSubnet.c_str(), result.strDns1.c_str(), result.strDns2.c_str(), result.strRouter1.c_str(),
        result.strRouter2.c_str(), result.strVendor.c_str(), result.uLeaseTime, result.uAddTime, result.uGetTime);

    std::lock_guard<std::mutex> autoLock(m_dhcpResultMutex);
    if (CheckDhcpResultExist(ifname, result)) {
        DHCP_LOGI("DhcpIpv4ResultSuccess DhcpResult %{public}s equal new addtime %{public}u, no need update.",
        ifname.c_str(), result.uAddTime);
        return OHOS::Wifi::DHCP_OPT_SUCCESS;
    }
    DHCP_LOGI("DhcpIpv4ResultSuccess DhcpResult %{public}s no equal new addtime %{public}u, need update...",
        ifname.c_str(), result.uAddTime);
#ifdef OHOS_ARCH_LITE
    std::shared_ptr<OHOS::Wifi::DhcpClientServiceImpl> clientImpl = OHOS::Wifi::DhcpClientServiceImpl::GetInstance();
#else
    OHOS::sptr<OHOS::Wifi::DhcpClientServiceImpl> clientImpl = OHOS::Wifi::DhcpClientServiceImpl::GetInstance();
#endif
    PushDhcpResult(ifname, result);
    auto iter = m_mapClientCallBack.find(ifname);
    if (iter == m_mapClientCallBack.end()) {
        DHCP_LOGE("DhcpIpv4ResultSuccess m_mapClientCallBack not find callback!");
        return OHOS::Wifi::DHCP_OPT_FAILED;
    }

    if ((iter->second) == nullptr) {
        DHCP_LOGE("DhcpIpv4ResultSuccess  mclientCallback is nullptr!");
        return OHOS::Wifi::DHCP_OPT_FAILED;
    }
    (iter->second)->OnIpSuccessChanged(DHCP_OPT_SUCCESS, ifname, result);
    DHCP_LOGI("DhcpIpv4ResultSuccess OnIpSuccessChanged!");
    return OHOS::Wifi::DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::DhcpIpv4ResultFail(const std::vector<std::string> &splits)
{
    std::string ifname = splits[OHOS::Wifi::DHCP_NUM_ZERO];
    OHOS::Wifi::DhcpResult result;
    result.iptype = 0;
    result.isOptSuc = false;
    result.uGetTime = (uint32_t)time(NULL);
    result.uAddTime = atoi(splits[OHOS::Wifi::DHCP_NUM_ONE].c_str());

    std::lock_guard<std::mutex> autoLock(m_dhcpResultMutex);
    PushDhcpResult(ifname, result);
    DHCP_LOGI("DhcpIpv4ResultFail ifname:%{public}s result.isOptSuc:false!", ifname.c_str());
    
    auto iter = m_mapClientCallBack.find(ifname);
    if (iter == m_mapClientCallBack.end()) {
        DHCP_LOGE("DhcpIpv4ResultFail m_mapClientCallBack not find callback!");
        return OHOS::Wifi::DHCP_OPT_FAILED;
    }
    if ((iter->second) == nullptr) {
        DHCP_LOGE("DhcpIpv4ResultFail mclientCallback == nullptr!");
        return OHOS::Wifi::DHCP_OPT_FAILED;
    }
    
    ActionMode action = ACTION_INVALID;
    auto iterlient = m_mapClientService.find(ifname);
    if (iterlient != m_mapClientService.end() && ((iterlient->second).pStaStateMachine != nullptr)) {
        action = (iterlient->second).pStaStateMachine->GetAction();
    }
    
    (action == ACTION_RENEW) ? ((iter->second)->OnIpFailChanged(DHCP_OPT_RENEW_FAILED, ifname.c_str(),
        "get dhcp renew result failed!")) :
        ((iter->second)->OnIpFailChanged(DHCP_OPT_FAILED, ifname.c_str(), "get dhcp ip result failed!"));
    DHCP_LOGI("DhcpIpv4ResultFail OnIpFailChanged!, action:%{public}d", action);
    return OHOS::Wifi::DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::DhcpIpv4ResultTimeOut(const std::string &ifname)
{
    std::lock_guard<std::mutex> autoLock(m_dhcpResultMutex);
    DHCP_LOGI("DhcpIpv4ResultTimeOut ifname:%{public}s", ifname.c_str());
    auto iter = m_mapClientCallBack.find(ifname);
    if (iter == m_mapClientCallBack.end()) {
        DHCP_LOGE("DhcpIpv4ResultTimeOut m_mapClientCallBack not find callback!");
        return OHOS::Wifi::DHCP_OPT_FAILED;
    }
    if ((iter->second) == nullptr) {
        DHCP_LOGE("DhcpIpv4ResultTimeOut mclientCallback == nullptr!");
        return OHOS::Wifi::DHCP_OPT_FAILED;
    }
    ActionMode action = ACTION_INVALID;
    auto iterlient = m_mapClientService.find(ifname);
    if (iterlient != m_mapClientService.end() && ((iterlient->second).pStaStateMachine != nullptr)) {
        action = (iterlient->second).pStaStateMachine->GetAction();
    }
    
    (action == ACTION_RENEW) ? ((iter->second)->OnIpFailChanged(DHCP_OPT_RENEW_TIMEOUT, ifname.c_str(),
        "get dhcp renew result timeout!")) :
        ((iter->second)->OnIpFailChanged(DHCP_OPT_TIMEOUT, ifname.c_str(), "get dhcp result timeout!"));
    DHCP_LOGI("DhcpIpv4ResultTimeOut OnIpFailChanged Timeout!, action:%{public}d", action);
    return OHOS::Wifi::DHCP_OPT_SUCCESS;
}

void DhcpClientServiceImpl::DhcpIpv6ResulCallback(const std::string ifname, DhcpIpv6Info &info)
{
    if (strlen(info.globalIpv6Addr) == 0 || strlen(info.routeAddr) == 0 || !IsGlobalIPv6Address(info.globalIpv6Addr)) {
        DHCP_LOGE("DhcpIpv6ResulCallback invalid, ipaddr:%{private}s, route:%{private}s",
            info.globalIpv6Addr, info.routeAddr);
        return;
    }
    OHOS::Wifi::DhcpResult result;
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

    std::lock_guard<std::mutex> autoLock(m_dhcpResultMutex);
    PushDhcpResult(ifname, result);
    DHCP_LOGI("DhcpIpv6ResulCallback %{public}s, %{public}d, opt:%{public}d, cli:%{private}s, server:%{private}s, "
        "Subnet:%{private}s, Dns1:%{private}s, Dns2:%{private}s, Router1:%{private}s, Router2:%{private}s, "
        "strVendor:%{public}s, uLeaseTime:%{public}u, uAddTime:%{public}u, uGetTime:%{public}u.",
        ifname.c_str(), result.iptype, result.isOptSuc, result.strYourCli.c_str(), result.strServer.c_str(),
        result.strSubnet.c_str(), result.strDns1.c_str(), result.strDns2.c_str(), result.strRouter1.c_str(),
        result.strRouter2.c_str(), result.strVendor.c_str(), result.uLeaseTime, result.uAddTime, result.uGetTime);
    
    auto iter = m_mapClientCallBack.find(ifname);
    if (iter == m_mapClientCallBack.end()) {
        DHCP_LOGE("DhcpIpv6ResulCallback m_mapClientCallBack not find callback!");
        return;
    }
    if ((iter->second) == nullptr) {
        DHCP_LOGE("DhcpIpv6ResulCallback mclientCallback == nullptr!");
        return;
    }
    (iter->second)->OnIpSuccessChanged(PUBLISH_CODE_SUCCESS, ifname, result);
    DHCP_LOGI("DhcpIpv6ResulCallback OnIpSuccessChanged");
}

void DhcpClientServiceImpl::PushDhcpResult(const std::string &ifname, OHOS::Wifi::DhcpResult &result)
{
    auto iterResult = m_mapDhcpResult.find(ifname);
    if (iterResult != m_mapDhcpResult.end()) {
        for (int i = 0; i < iterResult->second.size(); i++) {
            if (iterResult->second[i].iptype != result.iptype) {
                continue;
            }
            if (iterResult->second[i].iptype == 0) { // 0-ipv4 
                if (iterResult->second[i].uAddTime != result.uAddTime) {
                    iterResult->second[i] = result;
                    DHCP_LOGI("PushDhcpResult update ipv4 result, ifname:%{public}s", ifname.c_str());
                }
            } else { // 1-ipv6
                DHCP_LOGI("PushDhcpResult update ipv6 result, ifname:%{public}s", ifname.c_str());
                iterResult->second[i] = result;
            }
            return;
        }
        DHCP_LOGI("PushDhcpResult ifname add new result, ifname:%{public}s", ifname.c_str());
        iterResult->second.push_back(result);
    } else {
        std::vector<OHOS::Wifi::DhcpResult> results;
        results.push_back(result);
        m_mapDhcpResult.emplace(std::make_pair(ifname, results));
        DHCP_LOGI("PushDhcpResult add new ifname result, ifname:%{public}s", ifname.c_str());
    }
}

bool DhcpClientServiceImpl::CheckDhcpResultExist(const std::string &ifname, OHOS::Wifi::DhcpResult &result)
{
    bool exist = false;
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
    return exist;
}

bool DhcpClientServiceImpl::IsRemoteDied(void)
{
    DHCP_LOGI("IsRemoteDied");
    return true;
}

bool DhcpClientServiceImpl::IsNativeProcess()
{
#ifndef DTFUZZ_TEST
    return true;
#endif
#ifndef OHOS_ARCH_LITE
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    Security::AccessToken::ATokenTypeEnum callingType =
        Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (callingType == Security::AccessToken::TOKEN_NATIVE) {
        return true;
    }
    DHCP_LOGE("The caller tokenId:%{public}d, callingType:%{public}d is not a native process.", tokenId, callingType);
    return false;
#else
    return true;
#endif
}

bool DhcpClientServiceImpl::IsGlobalIPv6Address(std::string ipAddress)
{
    const char* ipAddr = ipAddress.c_str();
    int first = ipAddr[0]-'0';
    DHCP_LOGI("first = %{public}d", first);
    if (first == NUMBER_TWO || first == NUMBER_THREE) {
        return true;
    }
    return false;
}

}
}