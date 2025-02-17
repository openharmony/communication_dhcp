/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#ifndef OHOS_DHCP_CLIENT_STATEMACHINE_H
#define OHOS_DHCP_CLIENT_STATEMACHINE_H

#include <thread>
#include <string>
#include <stdint.h>
#include <sys/types.h>
#include "dhcp_arp_checker.h"
#include "dhcp_client_def.h"
#include "dhcp_ipv6_client.h"
#include "dhcp_thread.h"

#ifndef OHOS_ARCH_LITE
#include "common_timer_errors.h"
#include "timer.h"
#endif

namespace OHOS {
namespace DHCP {
class  DhcpClientStateMachine{
public:
    DhcpClientStateMachine(std::string ifname);
    virtual ~DhcpClientStateMachine();
private:
    int InitSpecifiedClientCfg(const std::string &ifname, bool isIpv6);
    int GetClientNetworkInfo(void);
    int SetIpv4State(int state);
    int PublishDhcpResultEvent(const char *ifname, const int code, struct DhcpIpResult *result);
    int GetPacketHeaderInfo(struct DhcpPacket *packet, uint8_t type);
    int GetPacketCommonInfo(struct DhcpPacket *packet);
    int AddClientIdToOpts(struct DhcpPacket *packet);
    int AddHostNameToOpts(struct DhcpPacket *packet);
    int AddStrToOpts(struct DhcpPacket *packet, int option, std::string &value);
    int DhcpDiscover(uint32_t transid, uint32_t requestip);
    int DhcpRequest(uint32_t transid, uint32_t reqip, uint32_t servip);
    int DhcpReboot(uint32_t transid, uint32_t reqip);
    int DhcpDecline(uint32_t transid, uint32_t clientIp, uint32_t serverIp);
    int GetDHCPServerHostName(const struct DhcpPacket *packet, struct DhcpIpResult *result);
    int ParseNetworkVendorInfo(const struct DhcpPacket *packet, struct DhcpIpResult *result);
    int GetPacketReadSockFd(void);
    int GetSigReadSockFd(void);
    int DhcpRenew(uint32_t transid, uint32_t clientip, uint32_t serverip);
    int DhcpRelease(uint32_t clientip, uint32_t serverip);
    int InitConfig(const std::string &ifname, bool isIpv6);
    void SendReboot(uint32_t targetIp, time_t timestamp);
    void AddParamaterRequestList(struct DhcpPacket *packet);
    void DhcpResponseHandle(time_t timestamp, int sockFd);
    int DhcpResponseDataCheck(time_t timestamp, int sockFd, uint8_t &u8Message, struct DhcpPacket &packet);
    void DhcpAckOrNakPacketHandle(uint8_t type, struct DhcpPacket *packet, time_t timestamp);
    void ParseDhcpAckPacket(const struct DhcpPacket *packet, time_t timestamp);
    void ParseDhcpNakPacket(const struct DhcpPacket *packet, time_t timestamp);
    void DhcpInit(void);
    void ModifyKernelFile(const char* filePath, const char* num);
    bool InitSocketFd(int &sockFdRaw, int &sockFdkernel);
    void SetSocketMode(uint32_t mode);
    void ParseNetworkServerIdInfo(const struct DhcpPacket *packet, struct DhcpIpResult *result);
    void ParseNetworkInfo(const struct DhcpPacket *packet, struct DhcpIpResult *result);
    void ParseNetworkDnsInfo(const struct DhcpPacket *packet, struct DhcpIpResult *result);
    void SetIpv4DefaultDns(struct DhcpIpResult *result);
    void ParseNetworkDnsValue(struct DhcpIpResult *result, uint32_t uData, size_t &len, int &count);
    void DhcpOfferPacketHandle(uint8_t type, const struct DhcpPacket *packet, time_t timestamp);
    void DhcpRequestHandle(time_t timestamp);
    void Rebinding(time_t timestamp);
    void Requesting(time_t timestamp);
    void Renewing(time_t timestamp);
    void Reboot(time_t timestamp);
    void Declining(time_t timestamp);
    void AddParamaterRebootList(struct DhcpPacket *packet);
    void InitSelecting(time_t timestamp);
    bool SignalReceiver(void);
    void RunGetIPThreadFunc(const DhcpClientStateMachine &instance);
    void FormatString(struct DhcpIpResult *result);
    uint32_t GetRandomId(void);
    uint32_t GetDhcpTransID(void);
    void IpConflictDetect();
    void FastArpDetect();
    void SlowArpDetect(time_t timestamp);
    void SlowArpDetectCallback(bool isReachable);
    void SlowArpTimeoutCallback();
    bool IsArpReachable(uint32_t timeoutMillis, std::string ipAddress);
    void SaveIpInfoInLocalFile(const DhcpIpResult ipResult);
    int32_t GetCachedDhcpResult(std::string targetBssid, IpInfoCached &ipCached);
    void TryCachedIp();
    void SetDefaultNetMask(struct DhcpIpResult *result);
#ifndef OHOS_ARCH_LITE
    void GetDhcpOffer(DhcpPacket *getPacket, int64_t timestamp);
#endif

public:
#ifndef OHOS_ARCH_LITE
    void StartTimer(TimerType type, uint32_t &timerId, int64_t interval, bool once);
    void StopTimer(uint32_t &timerId);
    void GetIpTimerCallback();
    void RenewDelayCallback();
    void RebindDelayCallback();
    void RemainingDelayCallback();
#endif
    int StartIpv4Type(const std::string &ifname, bool isIpv6, ActionMode action);
    int InitStartIpv4Thread(const std::string &ifname, bool isIpv6);
    void StartIpv4(void);
    int ExecDhcpRelease(void);
    int ExecDhcpRenew(void);
    int ExitIpv4(void);
    int StopIpv4(void);
    int InitSignalHandle();
    int CloseSignalHandle();
    ActionMode GetAction(void);
    void SetConfiguration(const RouterCfg routerCfg);
    void ScheduleLeaseTimers(bool isCachedIp);
    void CloseAllRenewTimer();
    int SendStopSignal();
    void SetSecondsElapsed(struct DhcpPacket *packet);
    bool IsPcDevice();
private:
    int m_dhcp4State;
    int m_sockFd;
    int m_sigSockFds[NUMBER_TWO];
    int m_resendTimer;
    uint32_t m_sentPacketNum;
    int64_t m_timeoutTimestamp;
    int64_t m_renewalTimestamp;
    int64_t m_renewalTimestampBoot;
    uint32_t m_leaseTime;
    uint32_t m_renewalSec;
    uint32_t m_rebindSec;
    uint32_t m_requestedIp4;
    uint32_t m_serverIp4;
    uint32_t m_socketMode;
    uint32_t m_transID;
    DhcpClientCfg m_cltCnf;
    std::atomic<bool> threadExit_{true};
    std::string m_ifName;  //对象服务的网卡名称
    std::unique_ptr<DhcpThread> ipv4Thread_ = nullptr;
    ActionMode m_action;
#ifndef OHOS_ARCH_LITE
    std::mutex getIpTimerMutex;
    uint32_t getIpTimerId;
    uint32_t renewDelayTimerId;
    uint32_t rebindDelayTimerId;
    uint32_t remainingDelayTimerId;
    uint32_t m_slowArpTaskId;
#endif
    std::string m_arpDectionTargetIp;
    RouterCfg m_routerCfg;
    uint32_t m_conflictCount;
    DhcpIpResult m_dhcpIpResult;
    DhcpArpChecker m_dhcpArpChecker;
    std::function<void(bool isReachable)> m_slowArpCallback;
    bool m_slowArpDetecting;
    int64_t firstSendPacketTime_;
    uint32_t slowArpTimeoutTimerId_;
};

typedef struct{
    std::string ifName;
    bool isIpv6;
    DhcpClientStateMachine *pStaStateMachine;
    DhcpIpv6Client *pipv6Client;
}DhcpClient;
}  // namespace DHCP
}  // namespace OHOS
#endif