/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include <string>
#include "dhcpclientfun_fuzzer.h"
#include "dhcp_client_state_machine.h"
#include "dhcp_ipv6_client.h"
#include "dhcp_socket.h"
#include "securec.h"
#include <linux/rtnetlink.h>
#include <netinet/icmp6.h>

namespace OHOS {
namespace DHCP {
std::string g_ifname = "wlan0";
constexpr size_t DHCP_SLEEP_2 = 2;
constexpr int TWO = 2;
constexpr int THREE = 3;
constexpr size_t U32_AT_SIZE_ZERO = 4;
std::unique_ptr<OHOS::DHCP::DhcpClientStateMachine> dhcpClient =
    std::make_unique<OHOS::DHCP::DhcpClientStateMachine>(g_ifname);
std::unique_ptr<OHOS::DHCP::DhcpIpv6Client> ipv6Client = std::make_unique<OHOS::DHCP::DhcpIpv6Client>("wlan0");

bool DhcpClientStateMachineFunFuzzerTest(const uint8_t *data, size_t size)
{
    if (dhcpClient == nullptr) {
        return false;
    }
    time_t curTimestamp = time(nullptr);
    if (curTimestamp == static_cast<time_t>(-1)) {
        return false;
    }
    dhcpClient->DhcpRequestHandle(curTimestamp);
    sleep(DHCP_SLEEP_2);
    dhcpClient->DhcpResponseHandle(curTimestamp);
    return true;
}

bool DhcpIpv6FunFuzzerTest(const uint8_t *data, size_t size)
{
    if (ipv6Client == nullptr) {
        return false;
    }
    if (data == nullptr) {
        return false;
    }
    if (size <= 0) {
        return false;
    }
    ipv6Client->handleKernelEvent(data, static_cast<int>(size));
    return true;
}

/* Dhcp Ipv6 Client */
void IsRunningFuzzerTest(const uint8_t *data, size_t size)
{
    ipv6Client->IsRunning();
}

void SetCallbackFuzzerTest(const uint8_t *data, size_t size)
{
    std::function<void(const std::string ifname, DhcpIpv6Info &info)> callback;
    ipv6Client->SetCallback(callback);
}

void StartIpv6ThreadFuzzerTest(const uint8_t *data, size_t size)
{
    std::string ifname = "wlan1";
    bool isIpv6 = true;
    ipv6Client->StartIpv6Thread(ifname, isIpv6);
}

void Ipv6AddrScope2TypeFuzzerTest(const uint8_t *data, size_t size)
{
    unsigned int scope = static_cast<unsigned int>(data[0]);
    ipv6Client->ipv6AddrScope2Type(scope);
}

void GetAddrTypeFuzzerTest(const uint8_t *data, size_t size)
{
    ipv6Client->getAddrType(nullptr);

    struct in6_addr addr;
    ipv6Client->getAddrType(&addr);

    inet_pton(AF_INET6, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", &addr);
    ipv6Client->getAddrType(&addr);

    inet_pton(AF_INET6, "ff02:0000:0000:0000:0000:0000:0000:0001", &addr);
    ipv6Client->getAddrType(&addr);

    inet_pton(AF_INET6, "fe80::", &addr);
    ipv6Client->getAddrType(&addr);

    inet_pton(AF_INET6, "fec0::", &addr);
    ipv6Client->getAddrType(&addr);

    inet_pton(AF_INET6, "::", &addr);
    ipv6Client->getAddrType(&addr);

    inet_pton(AF_INET6, "::1", &addr);
    ipv6Client->getAddrType(&addr);

    inet_pton(AF_INET6, "::ffff:192.0.2.128", &addr);
    ipv6Client->getAddrType(&addr);

    inet_pton(AF_INET6, "::ffff:192.0.2.128", &addr);
    ipv6Client->getAddrType(&addr);
}

void GetAddrScopeFuzzerTest(const uint8_t *data, size_t size)
{
    ipv6Client->getAddrType(nullptr);

    struct in6_addr addr;
    ipv6Client->getAddrScope(&addr);
}

void GetIpv6PrefixFuzzerTest(const uint8_t *data, size_t size)
{
    char ipv6Addr[DHCP_INET6_ADDRSTRLEN] = "1122:2233:3344:0000:0000:4433:3322:2211";
    char ipv6PrefixBuf[DHCP_INET6_ADDRSTRLEN] = {0};
    uint8_t prefixLen = static_cast<uint8_t>(data[0]);
    ipv6Client->GetIpv6Prefix(nullptr, nullptr, prefixLen);
    ipv6Client->GetIpv6Prefix(ipv6Addr, ipv6PrefixBuf, prefixLen);
}

void GetIpFromS6AddressFuzzerTest(const uint8_t *data, size_t size)
{
    int family = static_cast<int>(data[0]);
    int buflen = static_cast<int>(data[0]);
    ipv6Client->GetIpFromS6Address(nullptr, family, nullptr, buflen);

    struct in6_addr addr;
    char buf[INET6_ADDRSTRLEN] = {0};
    ipv6Client->GetIpFromS6Address(&addr, family, buf, buflen);
}

void OnIpv6AddressAddEventFuzzerTest(const uint8_t *data, size_t size)
{
    int prefixLen = static_cast<int>(data[0]);
    int ifaIndex = static_cast<int>(data[0]);
    ipv6Client->onIpv6AddressAddEvent(nullptr, prefixLen, ifaIndex);

    struct in6_addr data1;
    ipv6Client->onIpv6AddressAddEvent(&data1, prefixLen, ifaIndex);
}

void AddIpv6AddressFuzzerTest(const uint8_t *data, size_t size)
{
    int len = static_cast<int>(data[0]);
    ipv6Client->AddIpv6Address(nullptr, len);
}

void OnIpv6DnsAddEventFuzzerTest(const uint8_t *data, size_t size)
{
    int len = static_cast<int>(data[0]);
    int ifaIndex = static_cast<int>(data[0]);
    ipv6Client->onIpv6DnsAddEvent(nullptr, len, ifaIndex);

    struct nd_opt_hdr data1;
    ipv6Client->onIpv6DnsAddEvent(&data1, len, ifaIndex);
}

void OnIpv6RouteAddEventFuzzerTest(const uint8_t *data, size_t size)
{
    char *gateway = reinterpret_cast<char *>(const_cast<uint8_t *>(data));
    char *dst = reinterpret_cast<char *>(const_cast<uint8_t *>(data));
    int ifaIndex = static_cast<int>(data[0]);
    ipv6Client->onIpv6RouteAddEvent(gateway, dst, ifaIndex);
}

void CreateKernelSocketFuzzerTest(const uint8_t *data, size_t size)
{
    ipv6Client->createKernelSocket();
}

void ResetFuzzerTest(const uint8_t *data, size_t size)
{
    ipv6Client->Reset();
}

void GetIpv6RouteAddrFuzzerTest(const uint8_t *data, size_t size)
{
    ipv6Client->getIpv6RouteAddr();
}

void DhcpIPV6StopFuzzerTest(const uint8_t *data, size_t size)
{
    ipv6Client->DhcpIPV6Stop();
}

void Ipv6TimerCallbackFuzzerTest(const uint8_t *data, size_t size)
{
    ipv6Client->Ipv6TimerCallback();
}

void StartIpv6TimerFuzzerTest(const uint8_t *data, size_t size)
{
    ipv6Client->StartIpv6Timer();
}

void StopIpv6TimerFuzzerTest(const uint8_t *data, size_t size)
{
    ipv6Client->StopIpv6Timer();
}

/* Dhcp Ipv6 Event */
void SetSocketFilterFuzzerTest(const uint8_t *data, size_t size)
{
    ipv6Client->setSocketFilter(nullptr);

    struct sockaddr_nl addr;
    ipv6Client->setSocketFilter(&addr);
}

void ParseNdUserOptMessageFuzzerTest(const uint8_t *data, size_t size)
{
    int len = static_cast<int>(data[0]);
    ipv6Client->parseNdUserOptMessage(nullptr, len);

    struct nduseroptmsg data1;
    ipv6Client->parseNdUserOptMessage(&data1, len);
}

void ParseNDRouteMessageFuzzerTest(const uint8_t *data, size_t size)
{
    ipv6Client->parseNDRouteMessage(nullptr);

    struct nlmsghdr msg;
    ipv6Client->parseNDRouteMessage(&msg);
}

void ParseNewneighMessageFuzzerTest(const uint8_t *data, size_t size)
{
    ipv6Client->parseNewneighMessage(0);
}

void FillRouteDataFuzzerTest(const uint8_t *data, size_t size)
{
    int len = static_cast<int>(data[0]);
    ipv6Client->fillRouteData(nullptr, len);
    const int nlmsgHdrsize = 16;
    char buff[nlmsgHdrsize];
    ipv6Client->fillRouteData(buff, len);
}

void HandleKernelEventFuzzerTest(const uint8_t *data, size_t size)
{
    int len = static_cast<int>(data[0]);
    ipv6Client->handleKernelEvent(nullptr, len);
}

/* Dhcp Socket */
void CreateKernelSocketFuzzerTest1(const uint8_t *data, size_t size)
{
    int sockFd = static_cast<int>(data[0]);
    CreateKernelSocket(&sockFd);
}

void BindRawSocketFuzzerTest(const uint8_t *data, size_t size)
{
    int rawFd = static_cast<int>(data[0]);
    int ifaceIndex = static_cast<int>(data[0]);
    uint8_t ifaceAddr[6] = {0};
    BindRawSocket(rawFd, ifaceIndex, ifaceAddr);
}

void BindKernelSocketFuzzerTest(const uint8_t *data, size_t size)
{
    int sockFd = static_cast<int>(data[0]);
    char ifaceName[5] = {0};
    uint32_t sockIp = static_cast<uint32_t>(data[0]);
    int sockPort = static_cast<int>(data[0]);
    bool bCast = true;
    BindKernelSocket(sockFd, ifaceName, sockIp, sockPort, bCast);
}

void SendDhcpPacketFuzzerTest(const uint8_t *data, size_t size)
{
    struct DhcpPacket *sendPacket = nullptr;
    uint32_t srcIp = static_cast<uint32_t>(data[0]);
    uint32_t destIp = static_cast<uint32_t>(data[0]);
    SendDhcpPacket(sendPacket, srcIp, destIp);
}

void CheckReadBytesFuzzerTest(const uint8_t *data, size_t size)
{
    int count = static_cast<int>(data[0]);
    int totLen = static_cast<int>(data[0]);
    CheckReadBytes(count, totLen);
}

void CheckUdpPacketFuzzerTest(const uint8_t *data, size_t size)
{
    int totLen = static_cast<int>(data[0]);
    CheckUdpPacket(nullptr, totLen);

    struct UdpDhcpPacket pPacket;
    CheckUdpPacket(&pPacket, totLen);

    pPacket.ip.protocol = 0;
    pPacket.ip.version = 0;
    CheckUdpPacket(&pPacket, totLen);

    pPacket.ip.ihl = 0;
    CheckUdpPacket(&pPacket, totLen);

    pPacket.udp.dest = 0;
    CheckUdpPacket(&pPacket, totLen);

    pPacket.udp.len = 0;
    CheckUdpPacket(&pPacket, totLen);
}

void CheckPacketIpSumFuzzerTest(const uint8_t *data, size_t size)
{
    int bytes = static_cast<int>(data[0]);
    CheckPacketIpSum(nullptr, bytes);

    struct UdpDhcpPacket pPacket;
    pPacket.ip.check = static_cast<uint16_t>(data[0]);
    CheckPacketIpSum(&pPacket, bytes);
}

void CheckPacketUdpSumFuzzerTest(const uint8_t *data, size_t size)
{
    int bytes = static_cast<int>(data[0]);
    CheckPacketUdpSum(nullptr, bytes);

    struct UdpDhcpPacket pPacket;
    pPacket.udp.check = static_cast<uint16_t>(data[0]);
    pPacket.udp.len = static_cast<uint16_t>(data[0]);
    pPacket.ip.saddr = static_cast<uint32_t>(data[0]);
    pPacket.ip.daddr = static_cast<uint32_t>(data[0]);
    CheckPacketUdpSum(&pPacket, bytes);
}

void GetDhcpRawPacketFuzzerTest(const uint8_t *data, size_t size)
{
    int rawFd = static_cast<int>(data[0]);
    GetDhcpRawPacket(nullptr, rawFd);

    struct DhcpPacket getPacket;
    getPacket.cookie = static_cast<int32_t>(data[0]);
    GetDhcpRawPacket(&getPacket, rawFd);
}

/* Dhcp Client State Machine */
void CloseSignalHandleFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->m_sigSockFds[0] = 0;
    dhcpClient->m_sigSockFds[1] = 1;
    dhcpClient->CloseSignalHandle();
}

void RunGetIPThreadFuncFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->m_cltCnf.getMode = 0;
    DhcpClientStateMachine machine("wlan0");
    dhcpClient->RunGetIPThreadFunc(machine);
}

void InitConfigFuzzerTest(const uint8_t *data, size_t size)
{
    std::string ifname = std::string(reinterpret_cast<const char *>(data), size);
    bool isIpv6 = (static_cast<int>(data[0]) % TWO) ? true : false;
    dhcpClient->InitConfig(ifname, isIpv6);
}

void InitSpecifiedClientCfgFuzzerTest(const uint8_t *data, size_t size)
{
    std::string ifname = std::string(reinterpret_cast<const char *>(data), size);
    bool isIpv6 = (static_cast<int>(data[0]) % TWO) ? true : false;
    dhcpClient->InitSpecifiedClientCfg(ifname, isIpv6);
}

void GetClientNetworkInfoFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->GetClientNetworkInfo();
}

void ExitIpv4FuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->ExitIpv4();
}

void StopIpv4FuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->getIpTimerId = static_cast<uint32_t>(data[0]);
    dhcpClient->m_slowArpTaskId = 1;
    dhcpClient->StopIpv4();
}

void GetActionFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->m_action = ActionMode::ACTION_START_NEW;
    dhcpClient->GetAction();
}

void DhcpInitFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->DhcpInit();
}

void DhcpStopFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->m_dhcp4State = 1;
    dhcpClient->DhcpStop();
}

void InitSocketFdFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->m_sockFd = -1;
    dhcpClient->InitSocketFd();

    dhcpClient->m_sockFd = 1;
    dhcpClient->m_socketMode = SOCKET_MODE_RAW;
    dhcpClient->InitSocketFd();

    dhcpClient->m_socketMode = SOCKET_MODE_KERNEL;
    dhcpClient->InitSocketFd();
}

void GetPacketReadSockFdFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->m_sockFd = 1;
    dhcpClient->GetPacketReadSockFd();
}

void GetSigReadSockFdFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->m_sigSockFds[0] = 1;
    dhcpClient->GetSigReadSockFd();
}

void GetDhcpTransIDFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->m_transID = 1;
    dhcpClient->GetDhcpTransID();
}

void SetSocketModeFuzzerTest(const uint8_t *data, size_t size)
{
    uint32_t mode = static_cast<uint32_t>(data[0]);
    dhcpClient->SetSocketMode(mode);
}

void ExecDhcpRenewFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->m_dhcp4State = DHCP_STATE_INIT;
    dhcpClient->ExecDhcpRenew();

    dhcpClient->m_dhcp4State = DHCP_STATE_SELECTING;
    dhcpClient->ExecDhcpRenew();

    dhcpClient->m_dhcp4State = DHCP_STATE_REQUESTING;
    dhcpClient->ExecDhcpRenew();

    dhcpClient->m_dhcp4State = DHCP_STATE_RELEASED;
    dhcpClient->ExecDhcpRenew();

    dhcpClient->m_dhcp4State = DHCP_STATE_RENEWED;
    dhcpClient->ExecDhcpRenew();

    dhcpClient->m_dhcp4State = DHCP_STATE_BOUND;
    dhcpClient->ExecDhcpRenew();

    dhcpClient->m_dhcp4State = DHCP_STATE_RENEWING;
    dhcpClient->ExecDhcpRenew();

    dhcpClient->m_dhcp4State = DHCP_STATE_REBINDING;
    dhcpClient->ExecDhcpRenew();
}

void ExecDhcpReleaseFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->ExecDhcpRelease();

    dhcpClient->m_dhcp4State = DHCP_STATE_BOUND;
    dhcpClient->ExecDhcpRelease();
}

void GetRandomIdFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->GetRandomId();
}

void InitSelectingFuzzerTest(const uint8_t *data, size_t size)
{
    time_t timestamp = 1;
    dhcpClient->m_transID = static_cast<uint32_t>(data[0]);
    dhcpClient->m_requestedIp4 = static_cast<uint32_t>(data[0]);
    dhcpClient->InitSelecting(timestamp);

    dhcpClient->m_sentPacketNum = TIMEOUT_TIMES_MAX + 1;
    dhcpClient->InitSelecting(timestamp);
}

void DhcpRebootFuzzerTest(const uint8_t *data, size_t size)
{
    uint32_t transid = static_cast<uint32_t>(data[0]);
    uint32_t reqip = static_cast<uint32_t>(data[0]);
    dhcpClient->DhcpReboot(transid, reqip);
}

void SendRebootFuzzerTest(const uint8_t *data, size_t size)
{
    uint32_t targetIp = static_cast<uint32_t>(data[0]);
    time_t timestamp = 1;
    dhcpClient->m_sentPacketNum = 1;
    dhcpClient->SendReboot(targetIp, timestamp);

    dhcpClient->m_sentPacketNum = TWO;
    dhcpClient->SendReboot(targetIp, timestamp);
}

void RebootFuzzerTest(const uint8_t *data, size_t size)
{
    time_t timestamp = 1;
    dhcpClient->Reboot(timestamp);
}

void RequestingFuzzerTest(const uint8_t *data, size_t size)
{
    time_t timestamp = 1;
    dhcpClient->m_sentPacketNum = TIMEOUT_TIMES_MAX + 1;
    dhcpClient->Requesting(timestamp);

    dhcpClient->m_sentPacketNum = TWO;
    dhcpClient->m_dhcp4State = DHCP_STATE_RENEWED;
    dhcpClient->Requesting(timestamp);

    dhcpClient->m_dhcp4State = DHCP_STATE_RELEASED;
    dhcpClient->Requesting(timestamp);
}

void RenewingFuzzerTest(const uint8_t *data, size_t size)
{
    time_t timestamp = 1;
    dhcpClient->m_dhcp4State = DHCP_STATE_RENEWING;
    dhcpClient->Renewing(timestamp);

    dhcpClient->m_dhcp4State = DHCP_STATE_RELEASED;
    dhcpClient->Renewing(timestamp);
}

void RebindingFuzzerTest(const uint8_t *data, size_t size)
{
    time_t timestamp = 1;
    dhcpClient->m_dhcp4State = DHCP_STATE_REBINDING;
    dhcpClient->Rebinding(timestamp);

    dhcpClient->m_dhcp4State = DHCP_STATE_RELEASED;
    dhcpClient->Rebinding(timestamp);
}

void DecliningFuzzerTest(const uint8_t *data, size_t size)
{
    time_t timestamp = 1;
    dhcpClient->Declining(timestamp);

    dhcpClient->m_conflictCount = THREE;
    dhcpClient->Declining(timestamp);
}

void DhcpRequestHandleFuzzerTest(const uint8_t *data, size_t size)
{
    time_t timestamp = 1;
    dhcpClient->m_dhcp4State = static_cast<int>(data[0]);
    dhcpClient->DhcpRequestHandle(timestamp);
}

void DhcpOfferPacketHandleFuzzerTest(const uint8_t *data, size_t size)
{
    uint8_t type = static_cast<uint8_t>(data[0]);
    struct DhcpPacket packet;
    time_t timestam = 1;
    dhcpClient->DhcpOfferPacketHandle(type, nullptr, timestam);
    dhcpClient->DhcpOfferPacketHandle(type, &packet, timestam);
}

void ParseNetworkServerIdInfoFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->ParseNetworkServerIdInfo(nullptr, nullptr);

    struct DhcpPacket packet;
    struct DhcpIpResult result;
    dhcpClient->ParseNetworkServerIdInfo(&packet, &result);
}

void ParseNetworkDnsInfoFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->ParseNetworkDnsInfo(nullptr, nullptr);

    struct DhcpPacket packet;
    struct DhcpIpResult result;
    dhcpClient->ParseNetworkDnsInfo(&packet, &result);
}

void ParseNetworkDnsValueFuzzerTest(const uint8_t *data, size_t size)
{
    struct DhcpIpResult result;
    uint32_t uData = static_cast<uint32_t>(data[0]);
    size_t len = static_cast<size_t>(data[0]);
    int count = static_cast<int>(data[0]);
    dhcpClient->ParseNetworkDnsValue(nullptr, uData, len, count);
    dhcpClient->ParseNetworkDnsValue(&result, uData, len, count);
}

void ParseNetworkInfoFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->ParseNetworkInfo(nullptr, nullptr);

    struct DhcpPacket packet;
    struct DhcpIpResult result;
    dhcpClient->ParseNetworkInfo(&packet, &result);
}

void FormatStringFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->FormatString(nullptr);

    struct DhcpIpResult result;
    memset_s(result.strYiaddr, sizeof(result.strYiaddr), 0, sizeof(result.strYiaddr));
    dhcpClient->FormatString(&result);

    memset_s(result.strOptServerId, sizeof(result.strOptServerId), 0, sizeof(result.strOptServerId));
    dhcpClient->FormatString(&result);

    memset_s(result.strOptSubnet, sizeof(result.strOptSubnet), 0, sizeof(result.strOptSubnet));
    dhcpClient->FormatString(&result);

    memset_s(result.strOptDns1, sizeof(result.strOptDns1), 0, sizeof(result.strOptDns1));
    dhcpClient->FormatString(&result);

    memset_s(result.strOptDns2, sizeof(result.strOptDns2), 0, sizeof(result.strOptDns2));
    dhcpClient->FormatString(&result);

    memset_s(result.strOptRouter1, sizeof(result.strOptRouter1), 0, sizeof(result.strOptRouter1));
    dhcpClient->FormatString(&result);

    memset_s(result.strOptRouter2, sizeof(result.strOptRouter2), 0, sizeof(result.strOptRouter2));
    dhcpClient->FormatString(&result);

    memset_s(result.strOptVendor, sizeof(result.strOptVendor), 0, sizeof(result.strOptVendor));
    dhcpClient->FormatString(&result);
}

void GetDHCPServerHostNameFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->GetDHCPServerHostName(nullptr, nullptr);

    struct DhcpPacket packet;
    struct DhcpIpResult result;
    dhcpClient->GetDHCPServerHostName(&packet, &result);
}

void ParseNetworkVendorInfoFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->ParseNetworkVendorInfo(nullptr, nullptr);

    struct DhcpPacket packet;
    struct DhcpIpResult result;
    dhcpClient->ParseNetworkVendorInfo(&packet, &result);
}

void DhcpAckOrNakPacketHandleFuzzerTest(const uint8_t *data, size_t size)
{
    uint8_t type = static_cast<uint8_t>(data[0]);
    struct DhcpPacket packet;
    time_t timestamp = 1;
    dhcpClient->DhcpAckOrNakPacketHandle(type, nullptr, timestamp);
    dhcpClient->DhcpAckOrNakPacketHandle(type, &packet, timestamp);
}

void ParseDhcpAckPacketFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->ParseDhcpAckPacket(nullptr, 1);

    struct DhcpPacket packet;
    time_t timestamp = 1;
    dhcpClient->ParseDhcpAckPacket(&packet, timestamp);
}

void ParseDhcpNakPacketFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->ParseDhcpNakPacket(nullptr, 1);

    struct DhcpPacket packet;
    time_t timestamp = 1;
    dhcpClient->ParseDhcpNakPacket(&packet, timestamp);
}

void GetDhcpOfferFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->GetDhcpOffer(nullptr, 1);

    struct DhcpPacket packet;
    dhcpClient->GetDhcpOffer(&packet, 1);
}

void DhcpResponseHandleFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->DhcpResponseHandle(1);
}

void SignalReceiverFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->SignalReceiver();
}

void SetIpv4StateFuzzerTest(const uint8_t *data, size_t size)
{
    int state = static_cast<int>(data[0]);
    dhcpClient->SetIpv4State(state);
}

void PublishDhcpResultEventFuzzerTest(const uint8_t *data, size_t size)
{
    char ifname[3] = {0};
    int code = static_cast<int>(data[0]);
    struct DhcpIpResult result;
    dhcpClient->PublishDhcpResultEvent(nullptr, code, &result);
    dhcpClient->PublishDhcpResultEvent(ifname, code, nullptr);
    dhcpClient->PublishDhcpResultEvent(ifname, code, &result);
}

void GetPacketHeaderInfoFuzzerTest(const uint8_t *data, size_t size)
{
    struct DhcpPacket packet;
    uint8_t type = static_cast<uint8_t>(data[0]);
    dhcpClient->GetPacketHeaderInfo(&packet, type);
}

void GetPacketCommonInfoFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->GetPacketCommonInfo(nullptr);

    struct DhcpPacket packet;
    memset_s(&packet, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket));
    packet.options[0] = END_OPTION;
    dhcpClient->GetPacketCommonInfo(&packet);
}

void AddClientIdToOptsFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->AddClientIdToOpts(nullptr);

    struct DhcpPacket packet;
    memset_s(&packet, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket));
    packet.options[0] = END_OPTION;
    dhcpClient->AddClientIdToOpts(&packet);
}

void AddHostNameToOptsFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->AddHostNameToOpts(nullptr);

    struct DhcpPacket packet;
    memset_s(&packet, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket));
    packet.options[0] = END_OPTION;
    dhcpClient->AddHostNameToOpts(&packet);
}

void AddStrToOptsFuzzerTest(const uint8_t *data, size_t size)
{
    struct DhcpPacket packet;
    memset_s(&packet, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket));
    packet.options[0] = END_OPTION;
    int option = 2;
    std::string value = "wlan1";
    dhcpClient->AddStrToOpts(&packet, option, value);
}

void DhcpDiscoverFuzzerTest(const uint8_t *data, size_t size)
{
    uint32_t transid = static_cast<uint32_t>(data[0]);
    uint32_t requestip = static_cast<uint32_t>(data[0]);
    dhcpClient->DhcpDiscover(transid, requestip);
}

void DhcpRequestFuzzerTest(const uint8_t *data, size_t size)
{
    uint32_t transid = static_cast<uint32_t>(data[0]);
    uint32_t reqip = static_cast<uint32_t>(data[0]);
    uint32_t servip = static_cast<uint32_t>(data[0]);
    dhcpClient->DhcpRequest(transid, reqip, servip);
}

void DhcpRenewFuzzerTest(const uint8_t *data, size_t size)
{
    uint32_t transId = static_cast<uint32_t>(data[0]);
    uint32_t clientIp = static_cast<uint32_t>(data[0]);
    uint32_t serverIp = static_cast<uint32_t>(data[0]);
    dhcpClient->DhcpRenew(transId, clientIp, serverIp);
}

void DhcpReleaseFuzzerTest(const uint8_t *data, size_t size)
{
    uint32_t clientIp = static_cast<uint32_t>(data[0]);
    uint32_t serverIp = static_cast<uint32_t>(data[0]);
    dhcpClient->DhcpRelease(clientIp, serverIp);
}

void DhcpDeclineFuzzerTest(const uint8_t *data, size_t size)
{
    uint32_t transId = static_cast<uint32_t>(data[0]);
    uint32_t clientIp = static_cast<uint32_t>(data[0]);
    uint32_t serverIp = static_cast<uint32_t>(data[0]);
    dhcpClient->DhcpDecline(transId, clientIp, serverIp);
}

void IpConflictDetectFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->IpConflictDetect();
}

void FastArpDetectFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->FastArpDetect();
}

void SlowArpDetectCallbackFuzzerTest(const uint8_t *data, size_t size)
{
    bool isReachable = true;
    dhcpClient->SlowArpDetectCallback(isReachable);

    isReachable = false;
    dhcpClient->SlowArpDetectCallback(isReachable);
}

void SlowArpDetectFuzzerTest(const uint8_t *data, size_t size)
{
    time_t timestamp = 1;
    dhcpClient->m_sentPacketNum = THREE;
    dhcpClient->SlowArpDetect(timestamp);

    dhcpClient->m_sentPacketNum = TWO;
    dhcpClient->SlowArpDetect(timestamp);

    dhcpClient->m_sentPacketNum = 0;
    dhcpClient->SlowArpDetect(timestamp);
}

void IsArpReachableFuzzerTest(const uint8_t *data, size_t size)
{
    uint32_t timeoutMillis = static_cast<uint32_t>(data[0]);
    std::string ipAddress = std::string(reinterpret_cast<const char *>(data), size);
    dhcpClient->IsArpReachable(timeoutMillis, ipAddress);
}

void GetCachedDhcpResultFuzzerTest(const uint8_t *data, size_t size)
{
    std::string targetBssid = std::string(reinterpret_cast<const char *>(data), size);
    struct IpInfoCached ipcached;
    dhcpClient->GetCachedDhcpResult(targetBssid, ipcached);
}

void SaveIpInfoInLocalFileFuzzerTest(const uint8_t *data, size_t size)
{
    struct DhcpIpResult ipResult;
    dhcpClient->SaveIpInfoInLocalFile(ipResult);
}

void TryCachedIpFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->TryCachedIp();
}

void SetConfigurationFuzzerTest(const uint8_t *data, size_t size)
{
    struct RouterCfg routerCfg;
    dhcpClient->SetConfiguration(routerCfg);
}

void GetIpTimerCallbackFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->GetIpTimerCallback();

    dhcpClient->m_action = ACTION_RENEW_T1;
    dhcpClient->GetIpTimerCallback();

    dhcpClient->m_action = ACTION_RENEW_T3;
    dhcpClient->GetIpTimerCallback();

    dhcpClient->m_action = ACTION_START_NEW;
    dhcpClient->GetIpTimerCallback();
}

void StartTimerFuzzerTest(const uint8_t *data, size_t size)
{
    uint32_t timerId = static_cast<uint32_t>(data[0]);
    TimerType type = TimerType::TIMER_REBIND_DELAY;
    int64_t interval = static_cast<int64_t>(data[0]);
    bool once = (static_cast<int>(data[0]) % TWO) ? true : false;
    dhcpClient->StartTimer(type, timerId, interval, once);

    type = TimerType::TIMER_REMAINING_DELAY;
    dhcpClient->StartTimer(type, timerId, interval, once);

    type = TimerType::TIMER_RENEW_DELAY;
    dhcpClient->StartTimer(type, timerId, interval, once);
}

void StopTimerFuzzerTest(const uint8_t *data, size_t size)
{
    uint32_t timerId = static_cast<uint32_t>(data[0]);
    dhcpClient->StopTimer(timerId);
}

void RenewDelayCallbackFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->RenewDelayCallback();
}

void RebindDelayCallbackFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->RebindDelayCallback();
}

void RemainingDelayCallbackFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->RemainingDelayCallback();
}

void SendStopSignalFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->SendStopSignal();
}

void CloseAllRenewTimerFuzzerTest(const uint8_t *data, size_t size)
{
    dhcpClient->CloseAllRenewTimer();
}

void DhcpIpv6ClientFuzzerTest(const uint8_t *data, size_t size)
{
    IsRunningFuzzerTest(data, size);
    SetCallbackFuzzerTest(data, size);
    StartIpv6ThreadFuzzerTest(data, size);
    Ipv6AddrScope2TypeFuzzerTest(data, size);
    GetAddrTypeFuzzerTest(data, size);
    GetAddrScopeFuzzerTest(data, size);
    GetIpv6PrefixFuzzerTest(data, size);
    GetIpFromS6AddressFuzzerTest(data, size);
    OnIpv6AddressAddEventFuzzerTest(data, size);
    AddIpv6AddressFuzzerTest(data, size);
    OnIpv6DnsAddEventFuzzerTest(data, size);
    OnIpv6RouteAddEventFuzzerTest(data, size);
    CreateKernelSocketFuzzerTest(data, size);
    ResetFuzzerTest(data, size);
    GetIpv6RouteAddrFuzzerTest(data, size);
    DhcpIPV6StopFuzzerTest(data, size);
    Ipv6TimerCallbackFuzzerTest(data, size);
    StartIpv6TimerFuzzerTest(data, size);
    StopIpv6TimerFuzzerTest(data, size);
}

void DhcpIpv6EventFuzzerTest(const uint8_t *data, size_t size)
{
    SetSocketFilterFuzzerTest(data, size);
    ParseNdUserOptMessageFuzzerTest(data, size);
    ParseNDRouteMessageFuzzerTest(data, size);
    ParseNewneighMessageFuzzerTest(data, size);
    FillRouteDataFuzzerTest(data, size);
    HandleKernelEventFuzzerTest(data, size);
}

void DhcpSocketFuzzerTest(const uint8_t *data, size_t size)
{
    CreateKernelSocketFuzzerTest1(data, size);
    BindRawSocketFuzzerTest(data, size);
    BindKernelSocketFuzzerTest(data, size);
    SendDhcpPacketFuzzerTest(data, size);
    CheckReadBytesFuzzerTest(data, size);
    CheckUdpPacketFuzzerTest(data, size);
    CheckPacketIpSumFuzzerTest(data, size);
    CheckPacketUdpSumFuzzerTest(data, size);
    GetDhcpRawPacketFuzzerTest(data, size);
}

void DhcpClientStateMachineFuzzerTest(const uint8_t *data, size_t size)
{
    CloseSignalHandleFuzzerTest(data, size);
    RunGetIPThreadFuncFuzzerTest(data, size);
    InitConfigFuzzerTest(data, size);
    InitSpecifiedClientCfgFuzzerTest(data, size);
    GetClientNetworkInfoFuzzerTest(data, size);
    ExitIpv4FuzzerTest(data, size);
    StopIpv4FuzzerTest(data, size);
    GetActionFuzzerTest(data, size);
    DhcpInitFuzzerTest(data, size);
    DhcpStopFuzzerTest(data, size);
    InitSocketFdFuzzerTest(data, size);
    GetPacketReadSockFdFuzzerTest(data, size);
    GetSigReadSockFdFuzzerTest(data, size);
    GetDhcpTransIDFuzzerTest(data, size);
    SetSocketModeFuzzerTest(data, size);
    ExecDhcpRenewFuzzerTest(data, size);
    ExecDhcpReleaseFuzzerTest(data, size);
    GetRandomIdFuzzerTest(data, size);
    InitSelectingFuzzerTest(data, size);
    DhcpRebootFuzzerTest(data, size);
    SendRebootFuzzerTest(data, size);
    RebootFuzzerTest(data, size);
    RequestingFuzzerTest(data, size);
    RenewingFuzzerTest(data, size);
    RebindingFuzzerTest(data, size);
    DecliningFuzzerTest(data, size);
    DhcpRequestHandleFuzzerTest(data, size);
    DhcpOfferPacketHandleFuzzerTest(data, size);
    ParseNetworkServerIdInfoFuzzerTest(data, size);
    ParseNetworkDnsInfoFuzzerTest(data, size);
    ParseNetworkDnsValueFuzzerTest(data, size);
    ParseNetworkInfoFuzzerTest(data, size);
    FormatStringFuzzerTest(data, size);
    GetDHCPServerHostNameFuzzerTest(data, size);
    ParseNetworkVendorInfoFuzzerTest(data, size);
    DhcpAckOrNakPacketHandleFuzzerTest(data, size);
    ParseDhcpAckPacketFuzzerTest(data, size);
    ParseDhcpNakPacketFuzzerTest(data, size);
    GetDhcpOfferFuzzerTest(data, size);
    DhcpResponseHandleFuzzerTest(data, size);
    SignalReceiverFuzzerTest(data, size);
    SetIpv4StateFuzzerTest(data, size);
    PublishDhcpResultEventFuzzerTest(data, size);
}

void DhcpClientStateMachineExFuzzerTest(const uint8_t *data, size_t size)
{
    GetPacketHeaderInfoFuzzerTest(data, size);
    GetPacketCommonInfoFuzzerTest(data, size);
    AddClientIdToOptsFuzzerTest(data, size);
    AddHostNameToOptsFuzzerTest(data, size);
    AddStrToOptsFuzzerTest(data, size);
    DhcpDiscoverFuzzerTest(data, size);
    DhcpRequestFuzzerTest(data, size);
    DhcpRenewFuzzerTest(data, size);
    DhcpReleaseFuzzerTest(data, size);
    DhcpDeclineFuzzerTest(data, size);
    IpConflictDetectFuzzerTest(data, size);
    FastArpDetectFuzzerTest(data, size);
    SlowArpDetectCallbackFuzzerTest(data, size);
    SlowArpDetectFuzzerTest(data, size);
    IsArpReachableFuzzerTest(data, size);
    GetCachedDhcpResultFuzzerTest(data, size);
    SaveIpInfoInLocalFileFuzzerTest(data, size);
    TryCachedIpFuzzerTest(data, size);
    SetConfigurationFuzzerTest(data, size);
    GetIpTimerCallbackFuzzerTest(data, size);
    StartTimerFuzzerTest(data, size);
    StopTimerFuzzerTest(data, size);
    RenewDelayCallbackFuzzerTest(data, size);
    RebindDelayCallbackFuzzerTest(data, size);
    RemainingDelayCallbackFuzzerTest(data, size);
    SendStopSignalFuzzerTest(data, size);
    CloseAllRenewTimerFuzzerTest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::DHCP::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    DhcpClientStateMachineFunFuzzerTest(data, size);
    DhcpIpv6FunFuzzerTest(data, size);
    DhcpIpv6ClientFuzzerTest(data, size);
    DhcpIpv6EventFuzzerTest(data, size);
    DhcpSocketFuzzerTest(data, size);
    DhcpClientStateMachineFuzzerTest(data, size);
    DhcpClientStateMachineExFuzzerTest(data, size);
    return 0;
}
} // namespace DHCP
} // namespace OHOS