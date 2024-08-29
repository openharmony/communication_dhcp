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

#include "dhcp_server_service_impl.h"
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
#include "dhcp_server_death_recipient.h"
#endif
#include "dhcp_define.h"
#include "dhcp_errcode.h"
#include "dhcp_logger.h"
#include "dhcp_dhcpd.h"
#include "securec.h"
#include "dhcp_function.h"
#include "dhcp_permission_utils.h"
#ifndef OHOS_ARCH_LITE
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "accesstoken_kit.h"
#endif
#include <sstream>

DEFINE_DHCPLOG_DHCP_LABEL("DhcpServerServiceImpl");

namespace OHOS {
namespace DHCP {

std::mutex DhcpServerServiceImpl::g_instanceLock;
#ifdef OHOS_ARCH_LITE
std::shared_ptr<DhcpServerServiceImpl> DhcpServerServiceImpl::g_instance = nullptr;
std::shared_ptr<DhcpServerServiceImpl> DhcpServerServiceImpl::GetInstance()
{
    if (g_instance == nullptr) {
        std::lock_guard<std::mutex> autoLock(g_instanceLock);
        if (g_instance == nullptr) {
            std::shared_ptr<DhcpServerServiceImpl> service = std::make_shared<DhcpServerServiceImpl>();
            g_instance = service;
        }
    }
    return g_instance;
}
#else
sptr<DhcpServerServiceImpl> DhcpServerServiceImpl::g_instance;
std::map<std::string, DhcpServerInfo> DhcpServerServiceImpl::m_mapDhcpServer;
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(DhcpServerServiceImpl::GetInstance().GetRefPtr());
sptr<DhcpServerServiceImpl> DhcpServerServiceImpl::GetInstance()
{
    if (g_instance == nullptr) {
        std::lock_guard<std::mutex> autoLock(g_instanceLock);
        if (g_instance == nullptr) {
            sptr<DhcpServerServiceImpl> service = new (std::nothrow) DhcpServerServiceImpl;
            g_instance = service;
        }
    }  
    return g_instance;
}
#endif

DhcpServerServiceImpl::DhcpServerServiceImpl()
#ifndef OHOS_ARCH_LITE
    : SystemAbility(DHCP_SERVER_ABILITY_ID, true), mPublishFlag(false),
        mState(ServerServiceRunningState::STATE_NOT_START)
#endif
{}

DhcpServerServiceImpl::~DhcpServerServiceImpl()
{}

void DhcpServerServiceImpl::OnStart()
{
    DHCP_LOGI("enter Server OnStart");
    if (mState == ServerServiceRunningState::STATE_RUNNING) {
        DHCP_LOGW("Service has already started.");
        return;
    }
    if (!Init()) {
        DHCP_LOGE("Failed to init dhcp server service");
        OnStop();
        return;
    }
    mState = ServerServiceRunningState::STATE_RUNNING;
    DHCP_LOGI("Server Service has started.");
}

void DhcpServerServiceImpl::OnStop()
{
    mPublishFlag = false;
    DHCP_LOGI("OnStop dhcp server service!");
}

bool DhcpServerServiceImpl::Init()
{
    DHCP_LOGI("enter server Init");
    if (!mPublishFlag) {
#ifdef OHOS_ARCH_LITE
        bool ret = true;
#else
        bool ret = Publish(DhcpServerServiceImpl::GetInstance());
#endif
        if (!ret) {
            DHCP_LOGE("Failed to publish dhcp server service!");
            return false;
        }
        DHCP_LOGI("success to publish dhcp server service!");
        mPublishFlag = true;
    }
    return true;
}

#ifndef OHOS_ARCH_LITE
void DhcpServerServiceImpl::StartServiceAbility(int sleepS)
{
    DHCP_LOGI("DhcpServerServiceImpl::StartServiceAbility");
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
            DHCP_LOGE("DhcpServerServiceImpl serviceManager is  nullptr, continue");
            continue;
        }
        OHOS::sptr<OHOS::DHCP::DhcpServerServiceImpl> serverServiceImpl =
            OHOS::DHCP::DhcpServerServiceImpl::GetInstance();
        int result = serviceManager->AddSystemAbility(DHCP_SERVER_ABILITY_ID, serverServiceImpl);
        if (result != 0) {
            DHCP_LOGE("DhcpServerServiceImpl AddSystemAbility error:%{public}d", result);
            continue;
        }
        DHCP_LOGI("DhcpServerServiceImpl AddSystemAbility break");
        break;
    }

    if (serviceManager == nullptr) {
        DHCP_LOGE("DhcpServerServiceImpl serviceManager == nullptr");
        return;
    }

    auto abilityObjext = serviceManager->AsObject();
    if (abilityObjext == nullptr) {
        DHCP_LOGE("DhcpServerServiceImpl AsObject() == nullptr");
        return;
    }

    bool ret = abilityObjext->AddDeathRecipient(new DhcpServerDeathRecipient());
    if (ret == false) {
        DHCP_LOGE("DhcpServerServiceImpl AddDeathRecipient == false");
    } else {
        DHCP_LOGI("DhcpServer DhcpServerServiceImpl StartServiceAbility ok");
    }
}
#endif

#ifdef OHOS_ARCH_LITE
ErrCode DhcpServerServiceImpl::RegisterDhcpServerCallBack(const std::string& ifname,
    const std::shared_ptr<IDhcpServerCallBack> &serverCallback)
#else
ErrCode DhcpServerServiceImpl::RegisterDhcpServerCallBack(const std::string& ifname,
    const sptr<IDhcpServerCallBack> &serverCallback)
#endif
{
    DHCP_LOGI("RegisterDhcpServerCallBack");
    if (!DhcpPermissionUtils::VerifyIsNativeProcess()) {
        DHCP_LOGE("RegisterDhcpServerCallBack:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (!DhcpPermissionUtils::VerifyDhcpNetworkPermission("ohos.permission.NETWORK_DHCP")) {
        DHCP_LOGE("RegisterDhcpServerCallBack:VerifyDhcpNetworkPermission PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    std::lock_guard<std::mutex> autoLock(m_serverCallBackMutex);
    auto iter = m_mapServerCallBack.find(ifname);
    if (iter != m_mapServerCallBack.end()) {
        (iter->second) = serverCallback;
        DHCP_LOGI("RegisterDhcpServerCallBack m_mapServerCallBack find one update, ifname:%{public}s", ifname.c_str());
    } else {
#ifdef OHOS_ARCH_LITE
        std::shared_ptr<IDhcpServerCallBack> callback = serverCallback;
#else
        sptr<IDhcpServerCallBack> callback = serverCallback;
#endif
        m_mapServerCallBack.emplace(std::make_pair(ifname, callback));
        DHCP_LOGI("RegisterDhcpServerCallBack m_mapServerCallBack add one new, ifname:%{public}s", ifname.c_str());
    }
    return DHCP_E_SUCCESS;
}

ErrCode DhcpServerServiceImpl::StartDhcpServer(const std::string& ifname)
{
    DHCP_LOGI("StartDhcpServer ifname:%{public}s", ifname.c_str());
    if (!DhcpPermissionUtils::VerifyIsNativeProcess()) {
        DHCP_LOGE("StartDhcpServer:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (!DhcpPermissionUtils::VerifyDhcpNetworkPermission("ohos.permission.NETWORK_DHCP")) {
        DHCP_LOGE("StartDhcpServer:VerifyDhcpNetworkPermission PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (ifname.empty()) {
        DHCP_LOGE("StartDhcpServer error, ifname is empty!");
        return DHCP_E_FAILED;
    }
    /* Add the specified interface. */
    if (AddSpecifiedInterface(ifname) != DHCP_OPT_SUCCESS) {
        return DHCP_E_FAILED;
    }

    if (CreateDefaultConfigFile(DHCP_SERVER_CONFIG_FILE) != DHCP_OPT_SUCCESS) {
        return DHCP_E_FAILED;
    }

    std::string localIp, netmask, ipRange;
    if (DhcpFunction::GetLocalIp(ifname, localIp, netmask) != DHCP_OPT_SUCCESS) {
        DHCP_LOGE("ifname:%{public}s get ip mask failed.", ifname.c_str());
        return DHCP_E_FAILED;
    }
    if (GetUsingIpRange(ifname, ipRange) != DHCP_OPT_SUCCESS) {
        DHCP_LOGE("ifname:%{public}s get ip range failed.", ifname.c_str());
        return DHCP_E_FAILED;
    }
    DHCP_LOGD("localIp:%{public}s netmask:%{public}s  ipRange:%{public}s.", localIp.c_str(), netmask.c_str(),
        ipRange.c_str());

    int ret = RegisterDeviceConnectCallBack(DeviceConnectCallBack);
    ret = StartDhcpServerMain(ifname, netmask, ipRange, localIp);
    std::lock_guard<std::mutex> autoLock(m_serverCallBackMutex);
    auto iter = m_mapServerCallBack.find(ifname);
    if (iter != m_mapServerCallBack.end()) {
        if ((iter->second) != nullptr) {
            if (ret == static_cast<int>(DHCP_E_SUCCESS)) {
                (iter->second)->OnServerStatusChanged(static_cast<int>(DHCP_SERVER_ON));
            } else {
                (iter->second)->OnServerStatusChanged(static_cast<int>(DHCP_SERVER_OFF));
            }
        }
    }
    return ErrCode(ret);
}

void DhcpServerServiceImpl::DeviceInfoCallBack(const std::string & ifname)
{
    DHCP_LOGI("DeviceInfoCallBack ifname:%{public}s.", ifname.c_str());
    DHCP_LOGI("DealServerSuccess ifname:%{public}s.", ifname.c_str());
    std::vector<std::string> leases;
    std::vector<DhcpStationInfo> stationInfos;
    GetDhcpClientInfos(ifname, leases);
    ConvertLeasesToStationInfos(leases, stationInfos);
    auto iter = m_mapServerCallBack.find(ifname);
    if (iter != m_mapServerCallBack.end()) {
        if ((iter->second) != nullptr) {
            (iter->second)->OnServerSuccess(ifname, stationInfos);
            return;
        } else {
            DHCP_LOGE("callbackFunc is null, ifname:%{public}s.", ifname.c_str());
            return;
        }
    } else {
        DHCP_LOGE("can't find ifname:%{public}s.", ifname.c_str());
        return;
    }
}

void DhcpServerServiceImpl::ConvertLeasesToStationInfos(std::vector<std::string> &leases,
    std::vector<DhcpStationInfo>& stationInfos)
{
    DHCP_LOGI("ConvertLeasesToStationInfos ");
    for (const std::string& lease : leases) {
        DhcpStationInfo info;
        std::string leaseTime;
        std::string bindingTime;
        std::string pendingTime;
        std::string pendingInterval;
        std::string bindingMode;
        std::string bindingStatus;
        std::istringstream iss(lease);
        if (!(iss >> info.macAddr >> info.ipAddr >> leaseTime >> bindingTime >> pendingTime >> pendingInterval >>
            bindingMode >> bindingStatus >> info.deviceName)) {
            DHCP_LOGE("ConvertLeasesToStationInfos iss failed, continue!");
            continue;
        }
        DHCP_LOGI("stationInfos deviceName:%{public}s", info.deviceName);
        stationInfos.push_back(info);
    }
}

void DeviceConnectCallBack(const char* ifname)
{
    DHCP_LOGI("DeviceConnectCallBack ifname:%{public}s.", ifname);
    if (ifname == nullptr) {
        DHCP_LOGE("DeviceConnectCallBack ifname is nullptr!");
        return;
    }
    auto instance = DhcpServerServiceImpl::GetInstance();
    if (instance == nullptr) {
        DHCP_LOGE("DeviceConnectCallBack instance is nullptr!");
        return;
    }
    instance->DeviceInfoCallBack(ifname);
}

ErrCode DhcpServerServiceImpl::StopDhcpServer(const std::string& ifname)
{
    if (!DhcpPermissionUtils::VerifyIsNativeProcess()) {
        DHCP_LOGE("StopDhcpServer:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (!DhcpPermissionUtils::VerifyDhcpNetworkPermission("ohos.permission.NETWORK_DHCP")) {
        DHCP_LOGE("StopDhcpServer:VerifyDhcpNetworkPermission PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (ifname.empty()) {
        DHCP_LOGE("StopDhcpServer() error, ifname is empty!");
        return DHCP_E_FAILED;
    }

    auto iterRangeMap = m_mapInfDhcpRange.find(ifname);
    if (iterRangeMap != m_mapInfDhcpRange.end()) {
        m_mapInfDhcpRange.erase(iterRangeMap);
    }
    if (RemoveAllDhcpRange(ifname) != DHCP_E_SUCCESS) {
        return DHCP_E_FAILED;
    }
    StopDhcpServerMain();
    /* Del the specified interface. */
    if (DelSpecifiedInterface(ifname) != DHCP_OPT_SUCCESS) {
        return DHCP_E_FAILED;
    }
    std::lock_guard<std::mutex> autoLock(m_serverCallBackMutex);
    auto iter = m_mapServerCallBack.find(ifname);
    if (iter != m_mapServerCallBack.end()) {
        if ((iter->second) != nullptr) {
            (iter->second)->OnServerStatusChanged(static_cast<int>(DHCP_SERVER_OFF));
        }
    }
    return DHCP_E_SUCCESS;
}

ErrCode DhcpServerServiceImpl::PutDhcpRange(const std::string& tagName, const DhcpRange& range)
{
    if (!DhcpPermissionUtils::VerifyIsNativeProcess()) {
        DHCP_LOGE("PutDhcpRange:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (!DhcpPermissionUtils::VerifyDhcpNetworkPermission("ohos.permission.NETWORK_DHCP")) {
        DHCP_LOGE("PutDhcpRange:VerifyDhcpNetworkPermission PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (tagName.empty()) {
        DHCP_LOGE("PutDhcpRange param error, tagName is empty!");
        return DHCP_E_FAILED;
    }
    if (!CheckIpAddrRange(range)) {
        DHCP_LOGE("PutDhcpRange tag:%{public}s check range failed.", tagName.c_str());
        return DHCP_E_FAILED;
    }

    DHCP_LOGI("PutDhcpRange tag:%{public}s.", tagName.c_str());

    /* add dhcp range */
    auto iterRangeMap = m_mapTagDhcpRange.find(tagName);
    if (iterRangeMap != m_mapTagDhcpRange.end()) {
        int nSize = (int)iterRangeMap->second.size();
        if (nSize > 1) {
            DHCP_LOGE("PutDhcpRange failed, %{public}s range size:%{public}d error!", tagName.c_str(), nSize);
            return DHCP_E_FAILED;
        } else if (nSize == 0) {
            DHCP_LOGI("PutDhcpRange m_mapTagDhcpRange find tagName:%{public}s, need push_back.", tagName.c_str());
            iterRangeMap->second.push_back(range);
            return DHCP_E_SUCCESS;
        } else {
            for (auto tagRange : iterRangeMap->second) {
                if ((tagRange.iptype != range.iptype) ||
                    (tagRange.strStartip != range.strStartip) || (tagRange.strEndip != range.strEndip)) {
                    continue;
                }
                DHCP_LOGW("PutDhcpRange success, %{public}s range already exist", tagName.c_str());
                return DHCP_E_SUCCESS;
            }
            DHCP_LOGE("PutDhcpRange failed, %{public}s range size:%{public}d already exist!", tagName.c_str(), nSize);
            return DHCP_E_FAILED;
        }
    } else {
        std::list<DhcpRange> listDhcpRange;
        listDhcpRange.push_back(range);
        m_mapTagDhcpRange.emplace(std::make_pair(tagName, listDhcpRange));
        DHCP_LOGI("PutDhcpRange m_mapTagDhcpRange no find tagName:%{public}s, need emplace.", tagName.c_str());
        return DHCP_E_SUCCESS;
    }
    return DHCP_E_SUCCESS;
}

ErrCode DhcpServerServiceImpl::RemoveDhcpRange(const std::string& tagName, const DhcpRange& range)
{
    if (!DhcpPermissionUtils::VerifyIsNativeProcess()) {
        DHCP_LOGE("RemoveDhcpRange:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (!DhcpPermissionUtils::VerifyDhcpNetworkPermission("ohos.permission.NETWORK_DHCP")) {
        DHCP_LOGE("RemoveDhcpRange:VerifyDhcpNetworkPermission PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (tagName.empty()) {
        DHCP_LOGE("RemoveDhcpRange param error, tagName is empty!");
        return DHCP_E_FAILED;
    }

    /* remove dhcp range */
    auto iterRangeMap = m_mapTagDhcpRange.find(tagName);
    if (iterRangeMap != m_mapTagDhcpRange.end()) {
        auto iterRange = m_mapTagDhcpRange[tagName].begin();
        while (iterRange != m_mapTagDhcpRange[tagName].end()) {
            if ((iterRange->iptype == range.iptype) && (iterRange->strStartip == range.strStartip) &&
                (iterRange->strEndip == range.strEndip)) {
                m_mapTagDhcpRange[tagName].erase(iterRange++);
                DHCP_LOGI("RemoveDhcpRange find tagName:%{public}s, "
                          "range.iptype:%{public}d,strStartip:%{private}s,strEndip:%{private}s, erase.",
                    tagName.c_str(),
                    range.iptype,
                    range.strStartip.c_str(),
                    range.strEndip.c_str());
                return DHCP_E_SUCCESS;
            }
            iterRange++;
        }
        DHCP_LOGE("RemoveDhcpRange find tagName:%{public}s, second no find range, erase failed!", tagName.c_str());
    } else {
        DHCP_LOGE("RemoveDhcpRange no find tagName:%{public}s, erase failed!", tagName.c_str());
    }

    return DHCP_E_SUCCESS;
}

ErrCode DhcpServerServiceImpl::RemoveAllDhcpRange(const std::string& tagName)
{
    if (!DhcpPermissionUtils::VerifyIsNativeProcess()) {
        DHCP_LOGE("RemoveAllDhcpRange:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (!DhcpPermissionUtils::VerifyDhcpNetworkPermission("ohos.permission.NETWORK_DHCP")) {
        DHCP_LOGE("RemoveAllDhcpRange:VerifyDhcpNetworkPermission PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (tagName.empty()) {
        DHCP_LOGE("RemoveAllDhcpRange param error, tagName is empty!");
        return DHCP_E_FAILED;
    }

    /* remove all dhcp range */
    auto iterRangeMap = m_mapTagDhcpRange.find(tagName);
    if (iterRangeMap != m_mapTagDhcpRange.end()) {
        m_mapTagDhcpRange.erase(iterRangeMap);
        DHCP_LOGI("RemoveAllDhcpRange find tagName:%{public}s, erase success.", tagName.c_str());
    } else {
        DHCP_LOGI("RemoveAllDhcpRange no find tagName:%{public}s, not need erase!", tagName.c_str());
    }

    return DHCP_E_SUCCESS;
}

ErrCode DhcpServerServiceImpl::SetDhcpRange(const std::string& ifname, const DhcpRange& range)
{
    if (!DhcpPermissionUtils::VerifyIsNativeProcess()) {
        DHCP_LOGE("SetDhcpRange:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (!DhcpPermissionUtils::VerifyDhcpNetworkPermission("ohos.permission.NETWORK_DHCP")) {
        DHCP_LOGE("SetDhcpRange:VerifyDhcpNetworkPermission PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    /* put dhcp range */
    if (PutDhcpRange(ifname, range) != DHCP_E_SUCCESS) {
        DHCP_LOGE("SetDhcpRange PutDhcpRange failed, ifname:%{public}s.", ifname.c_str());
        return DHCP_E_FAILED;
    }

    /* check same network */
    if (DhcpFunction::CheckRangeNetwork(ifname, range.strStartip, range.strEndip) != DHCP_OPT_SUCCESS) {
        DHCP_LOGE("SetDhcpRange CheckRangeNetwork failed, ifname:%{public}s.", ifname.c_str());
        RemoveDhcpRange(ifname, range);
        return DHCP_E_FAILED;
    }

    /* add dhcp range */
    auto iterRangeMap = m_mapInfDhcpRange.find(ifname);
    if (iterRangeMap != m_mapInfDhcpRange.end()) {
        int nSize = (int)iterRangeMap->second.size();
        if (nSize > 1) {
            DHCP_LOGE("SetDhcpRange failed, %{public}s range size:%{public}d error!", ifname.c_str(), nSize);
            RemoveDhcpRange(ifname, range);
            return DHCP_E_FAILED;
        }
        if (nSize == 1) {
            DHCP_LOGW("SetDhcpRange %{public}s range size:%{public}d already exist.", ifname.c_str(), nSize);
            iterRangeMap->second.clear();
        }
        DHCP_LOGI("SetDhcpRange m_mapInfDhcpRange find ifname:%{public}s, need push_back.", ifname.c_str());
        iterRangeMap->second.push_back(range);
    } else {
        std::list<DhcpRange> listDhcpRange;
        listDhcpRange.push_back(range);
        m_mapInfDhcpRange.emplace(std::make_pair(ifname, listDhcpRange));
        DHCP_LOGI("SetDhcpRange m_mapInfDhcpRange no find ifname:%{public}s, need emplace.", ifname.c_str());
    }

    if (CheckAndUpdateConf(ifname) != DHCP_E_SUCCESS) {
        DHCP_LOGE("SetDhcpRange() CheckAndUpdateConf failed, ifname:%{public}s.", ifname.c_str());
        RemoveDhcpRange(ifname, range);
        return DHCP_E_FAILED;
    }

    return DHCP_E_SUCCESS;
}

ErrCode DhcpServerServiceImpl::SetDhcpName(const std::string& ifname, const std::string& tagName)
{
    if (!DhcpPermissionUtils::VerifyIsNativeProcess()) {
        DHCP_LOGE("SetDhcpName:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (!DhcpPermissionUtils::VerifyDhcpNetworkPermission("ohos.permission.NETWORK_DHCP")) {
        DHCP_LOGE("SetDhcpName:VerifyDhcpNetworkPermission PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (ifname.empty() || tagName.empty()) {
        DHCP_LOGE("SetDhcpName failed, ifname or tagName is empty!");
        return DHCP_E_FAILED;
    }
    return SetDhcpNameExt(ifname, tagName);
}

ErrCode DhcpServerServiceImpl::SetDhcpNameExt(const std::string& ifname, const std::string& tagName)
{
    auto iterTag = m_mapTagDhcpRange.find(tagName);
    if (iterTag == m_mapTagDhcpRange.end()) {
        DHCP_LOGE("SetDhcpName tag m_mapTagDhcpRange no find tagName:%{public}s.", tagName.c_str());
        return DHCP_E_FAILED;
    }

    int nSize = (int)iterTag->second.size();
    if (nSize != 1) {
        DHCP_LOGE("SetDhcpName tag %{public}s range size:%{public}d error.", tagName.c_str(), nSize);
        return DHCP_E_FAILED;
    }

    /* check same network */
    for (auto iterTagValue : iterTag->second) {
        if (DhcpFunction::CheckRangeNetwork(ifname, iterTagValue.strStartip, iterTagValue.strEndip) !=
            DHCP_OPT_SUCCESS) {
            DHCP_LOGE("SetDhcpName tag CheckRangeNetwork failed, ifname:%{public}s.", ifname.c_str());
            return DHCP_E_FAILED;
        }
    }

    auto iterRangeMap = m_mapInfDhcpRange.find(ifname);
    if (iterRangeMap != m_mapInfDhcpRange.end()) {
        nSize = (int)iterRangeMap->second.size();
        if (nSize > 1) {
            DHCP_LOGE("SetDhcpName tag failed, %{public}s range size:%{public}d error!", ifname.c_str(), nSize);
            return DHCP_E_FAILED;
        }
        if (nSize == 1) {
            DHCP_LOGW("SetDhcpName tag %{public}s range size:%{public}d already exist.", ifname.c_str(), nSize);
            iterRangeMap->second.clear();
        }
        DHCP_LOGI("SetDhcpName tag m_mapInfDhcpRange find ifname:%{public}s, need push_back.", ifname.c_str());
        for (auto iterTagValue : iterTag->second) {
            iterRangeMap->second.push_back(iterTagValue);
        }
    } else {
        m_mapInfDhcpRange.emplace(std::make_pair(ifname, iterTag->second));
        DHCP_LOGI("SetDhcpName tag no find %{public}s, need emplace %{public}s.", ifname.c_str(), tagName.c_str());
    }

    /* update or reload interface config file */
    if (CheckAndUpdateConf(ifname) != DHCP_E_SUCCESS) {
        DHCP_LOGE("SetDhcpName tag CheckAndUpdateConf failed, ifname:%{public}s.", ifname.c_str());
        return DHCP_E_FAILED;
    }
    return DHCP_E_SUCCESS;
}

ErrCode DhcpServerServiceImpl::GetDhcpClientInfos(const std::string& ifname, std::vector<std::string>& leases)
{
    if (!DhcpPermissionUtils::VerifyIsNativeProcess()) {
        DHCP_LOGE("GetDhcpClientInfos:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (!DhcpPermissionUtils::VerifyDhcpNetworkPermission("ohos.permission.NETWORK_DHCP")) {
        DHCP_LOGE("GetDhcpClientInfos:VerifyDhcpNetworkPermission PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (ifname.empty()) {
        DHCP_LOGE("DhcpServerService::GetDhcpClientInfos error, ifname is empty!");
        return DHCP_E_FAILED;
    }

    std::string strFile = DHCP_SERVER_LEASES_FILE + "." + ifname;
    if (!DhcpFunction::IsExistFile(strFile)) {
        DHCP_LOGE("GetDhcpClientInfos() failed, dhcp leasefile:%{public}s no exist!", strFile.c_str());
        return DHCP_E_FAILED;
    }
    leases.clear();
    std::ifstream inFile;

    inFile.open(strFile);
    std::string strTemp = "";
    char tmpLineData[FILE_LINE_MAX_SIZE] = {0};
    while (inFile.getline(tmpLineData, sizeof(tmpLineData))) {
        strTemp = tmpLineData;
        if (!strTemp.empty()) {
            leases.push_back(strTemp);
        }
    }
    inFile.close();
    DHCP_LOGI("GetDhcpClientInfos leases.size:%{public}d.", (int)leases.size());
    return DHCP_E_SUCCESS;
}

ErrCode DhcpServerServiceImpl::UpdateLeasesTime(const std::string& leaseTime)
{
    DHCP_LOGI("UpdateLeasesTime");
    if (!DhcpPermissionUtils::VerifyIsNativeProcess()) {
        DHCP_LOGE("UpdateLeasesTime:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (!DhcpPermissionUtils::VerifyDhcpNetworkPermission("ohos.permission.NETWORK_DHCP")) {
        DHCP_LOGE("UpdateLeasesTime:VerifyDhcpNetworkPermission PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    std::string strData = "leaseTime=" + leaseTime + "\n";
    std::string strFile = DHCP_SERVER_CONFIG_FILE;
    if (!DhcpFunction::IsExistFile(strFile)) {
        DhcpFunction::CreateFile(strFile, strData);
    } else {
        DhcpFunction::RemoveFile(strFile);
        DhcpFunction::CreateFile(strFile, strData);
    }
    
    return DHCP_E_SUCCESS;
}

bool DhcpServerServiceImpl::IsRemoteDied(void)
{
    DHCP_LOGE("IsRemoteDied");
    return true;
}

int DhcpServerServiceImpl::CheckAndUpdateConf(const std::string &ifname)
{
    if (ifname.empty()) {
        DHCP_LOGE("CheckAndUpdateConf error, ifname is empty!");
        return DHCP_OPT_ERROR;
    }

    auto iterRangeMap = m_mapInfDhcpRange.find(ifname);
    if ((iterRangeMap == m_mapInfDhcpRange.end()) || (iterRangeMap->second).empty()) {
        return DHCP_OPT_SUCCESS;
    }
    int nSize = (int)iterRangeMap->second.size();
    if (nSize > 1) {
        DHCP_LOGE("CheckAndUpdateConf failed, %{public}s range size:%{public}d error!", ifname.c_str(), nSize);
        return DHCP_OPT_FAILED;
    }

    for (auto iterRange : iterRangeMap->second) {
        if (((iterRange.iptype != 0) && (iterRange.iptype != 1)) || (iterRange.leaseHours <= 0) ||
            (iterRange.strStartip.size() == 0) || (iterRange.strEndip.size() == 0)) {
            DHCP_LOGE("CheckAndUpdateConf failed, "
                      "iptype:%{public}d,leaseHours:%{public}d,strStartip:%{private}s,strEndip:%{private}s error!",
                iterRange.iptype, iterRange.leaseHours, iterRange.strStartip.c_str(), iterRange.strEndip.c_str());
            return DHCP_OPT_FAILED;
        }
    }

    return DHCP_OPT_SUCCESS;
}

bool DhcpServerServiceImpl::CheckIpAddrRange(const DhcpRange &range)
{
    if (((range.iptype != 0) && (range.iptype != 1)) || range.strStartip.empty() || range.strEndip.empty()) {
        DHCP_LOGE("CheckIpAddrRange range.iptype:%{public}d,strStartip:%{private}s,strEndip:%{private}s error!",
            range.iptype, range.strStartip.c_str(), range.strEndip.c_str());
        return false;
    }

    if (range.iptype == 0) {
        uint32_t uStartIp = 0;
        if (!DhcpFunction::Ip4StrConToInt(range.strStartip, uStartIp)) {
            DHCP_LOGE("CheckIpAddrRange Ip4StrConToInt failed, range.iptype:%{public}d,strStartip:%{private}s!",
                range.iptype, range.strStartip.c_str());
            return false;
        }
        uint32_t uEndIp = 0;
        if (!DhcpFunction::Ip4StrConToInt(range.strEndip, uEndIp)) {
            DHCP_LOGE("CheckIpAddrRange Ip4StrConToInt failed, range.iptype:%{public}d,strEndip:%{private}s!",
                range.iptype, range.strEndip.c_str());
            return false;
        }
        /* check ip4 start and end ip */
        if (uStartIp >= uEndIp) {
            DHCP_LOGE("CheckIpAddrRange failed, start:%{private}u not less end:%{private}u!", uStartIp, uEndIp);
            return false;
        }
    } else {
        uint8_t uStartIp6[sizeof(struct in6_addr)] = {0};
        if (!DhcpFunction::Ip6StrConToChar(range.strStartip, uStartIp6, sizeof(struct in6_addr))) {
            return false;
        }
        uint8_t uEndIp6[sizeof(struct in6_addr)] = {0};
        if (!DhcpFunction::Ip6StrConToChar(range.strEndip, uEndIp6, sizeof(struct in6_addr))) {
            return false;
        }
        /* check ip6 start and end ip */
    }

    return true;
}

int DhcpServerServiceImpl::AddSpecifiedInterface(const std::string& ifname)
{
    if (ifname.empty()) {
        DHCP_LOGE("AddSpecifiedInterface param error, ifname is empty!");
        return DHCP_OPT_ERROR;
    }

    if (m_setInterfaces.find(ifname) == m_setInterfaces.end()) {
        m_setInterfaces.insert(ifname);
        DHCP_LOGI("AddSpecifiedInterface started interfaces add %{public}s success.", ifname.c_str());
    }
    return DHCP_OPT_SUCCESS;
}

int DhcpServerServiceImpl::GetUsingIpRange(const std::string ifname, std::string& ipRange)
{
    if (ifname.empty()) {
        DHCP_LOGE("GetUsingIpRange param error, ifname is empty!");
        return DHCP_OPT_ERROR;
    }

    auto iterRangeMap = m_mapInfDhcpRange.find(ifname);
    if (iterRangeMap == m_mapInfDhcpRange.end()) {
        DHCP_LOGE("GetUsingIpRange failed, inf range map no find %{public}s!", ifname.c_str());
        return DHCP_OPT_FAILED;
    }
    int nSize = (int)iterRangeMap->second.size();
    if (nSize != 1) {
        DHCP_LOGE("GetUsingIpRange failed, %{public}s range size:%{public}d error!", ifname.c_str(), nSize);
        return DHCP_OPT_FAILED;
    }

    for (auto iterRange : iterRangeMap->second) {
        if (((iterRange.iptype != 0) && (iterRange.iptype != 1)) || (iterRange.leaseHours <= 0) ||
            (iterRange.strStartip.size() == 0) || (iterRange.strEndip.size() == 0)) {
            DHCP_LOGE("GetUsingIpRange type:%{public}d,lease:%{public}d,start:%{private}s,end:%{private}s error!",
                iterRange.iptype, iterRange.leaseHours, iterRange.strStartip.c_str(), iterRange.strEndip.c_str());
            return DHCP_OPT_FAILED;
        }
        ipRange.clear();
        ipRange = iterRange.strStartip + "," + iterRange.strEndip;
        return DHCP_OPT_SUCCESS;
    }
    DHCP_LOGE("GetUsingIpRange failed, %{public}s range size:%{public}d", ifname.c_str(), nSize);
    return DHCP_OPT_FAILED;
}

int DhcpServerServiceImpl::CreateDefaultConfigFile(const std::string strFile)
{
    if (strFile.empty()) {
        DHCP_LOGE("CreateDefaultConfigFile param error, strFile is empty!");
        return DHCP_OPT_ERROR;
    }
    

    if (!DhcpFunction::IsExistFile(strFile)) {
        DHCP_LOGI("CreateDefaultConfigFile!");
        DhcpFunction::CreateDirs(DHCP_SERVER_CONFIG_DIR);
        std::string strData = "leaseTime=" + std::to_string(LEASETIME_DEFAULT * ONE_HOURS_SEC) + "\n";
        DhcpFunction::CreateFile(strFile, strData);
    }
    return DHCP_OPT_SUCCESS;
}

int DhcpServerServiceImpl::StopServer(const pid_t &serverPid)
{
    UnregisterSignal();
    if (kill(serverPid, SIGTERM) == -1) {
        if (ESRCH == errno) {
            /* Normal. The subprocess is dead. The SIGCHLD signal triggers the stop hotspot. */
            DHCP_LOGI("StopServer() kill [%{public}d] success, pro pid no exist, pro:%{public}s.",
                serverPid, DHCP_SERVER_FILE.c_str());
            return DHCP_OPT_SUCCESS;
        }
        DHCP_LOGE("StopServer() kill [%{public}d] failed, errno:%{public}d!", serverPid, errno);
        return DHCP_OPT_FAILED;
    }
    if (DhcpFunction::WaitProcessExit(serverPid) == -1) {
        DHCP_LOGE("StopServer() waitpid [%{public}d] failed, errno:%{public}d!", serverPid, errno);
        return DHCP_OPT_FAILED;
    }
    DHCP_LOGI("StopServer() waitpid [%{public}d] success, pro:%{public}s!", serverPid, DHCP_SERVER_FILE.c_str());
    return DHCP_OPT_SUCCESS;
}

int DhcpServerServiceImpl::DelSpecifiedInterface(const std::string& ifname)
{
    if (ifname.empty()) {
        DHCP_LOGE("DelSpecifiedInterface param error, ifname is empty!");
        return DHCP_OPT_ERROR;
    }

    auto iterInterfaces = m_setInterfaces.find(ifname);
    if (iterInterfaces != m_setInterfaces.end()) {
        m_setInterfaces.erase(iterInterfaces);
        DHCP_LOGI("DelSpecifiedInterface started interfaces del %{public}s success.", ifname.c_str());
    }
    return DHCP_OPT_SUCCESS;
}

void DhcpServerServiceImpl::UnregisterSignal() const
{
    struct sigaction newAction {};

    if (sigemptyset(&newAction.sa_mask) == -1) {
        DHCP_LOGE("UnregisterSignal() failed, sigemptyset error:%{public}d!", errno);
    }

    newAction.sa_handler = SIG_DFL;
    newAction.sa_flags = SA_RESTART;
    newAction.sa_restorer = nullptr;

    if (sigaction(SIGCHLD, &newAction, nullptr) == -1) {
        DHCP_LOGE("UnregisterSignal() sigaction SIGCHLD error:%{public}d!", errno);
    }
}

ErrCode DhcpServerServiceImpl::DeleteLeaseFile(const std::string& ifname)
{
    std::string strFile = DHCP_SERVER_LEASES_FILE + "." + ifname;
    if (!DhcpFunction::IsExistFile(strFile)) {
        DHCP_LOGE("DeleteLeaseFile failed, dhcp leasefile:%{public}s no exist!", strFile.c_str());
        return DHCP_E_FAILED;
    }
    if (!DhcpFunction::RemoveFile(strFile)) {
        DHCP_LOGE("DeleteLeaseFile RemoveFile failed, leasefile:%{public}s", strFile.c_str());
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("DeleteLeaseFile RemoveFile ok");
    return DHCP_E_SUCCESS;
}
}
}