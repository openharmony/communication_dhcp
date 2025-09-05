/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "dhcp_arp_checker.h"

#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <mutex>
#include <net/if_arp.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <regex>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>

#include "securec.h"
#include "dhcp_common_utils.h"
#include "dhcp_logger.h"

#ifdef DHCP_MOCK_TEST
#include "mock_system_func.h"
#endif
namespace OHOS {
namespace DHCP {
DEFINE_DHCPLOG_DHCP_LABEL("DhcpArpChecker");
constexpr const char *DHCP_ARP_CHECKER_THREAD = "DHCP_ARP_CHECKER_THREAD";
constexpr int32_t MAX_LENGTH = 1500;
constexpr int32_t OPT_SUCC = 0;
constexpr int32_t OPT_FAIL = -1;

// MAC address format constants
constexpr int32_t MAC_ADDR_STRING_LENGTH = 17; // "xx:xx:xx:xx:xx:xx"
constexpr uint8_t MAC_BROADCAST_VALUE = 0xFF;  // Broadcast MAC value

// MAC address component indices
constexpr int32_t MAC_ADDR_BYTE_0 = 0;
constexpr int32_t MAC_ADDR_BYTE_1 = 1;
constexpr int32_t MAC_ADDR_BYTE_2 = 2;
constexpr int32_t MAC_ADDR_BYTE_3 = 3;
constexpr int32_t MAC_ADDR_BYTE_4 = 4;
constexpr int32_t MAC_ADDR_BYTE_5 = 5;

// Global state tracking: record ongoing bind attempts to prevent concurrent access
static std::mutex g_interfaceAttemptMutex;
static std::unordered_set<std::string> g_ongoingAttempts;

// Timeout and progress constants
constexpr int64_t MIN_PROGRESS_MS = 1; // Minimum progress to prevent infinite loops
constexpr int32_t TIMEOUT_EXPIRED = 0; // Value indicating timeout has expired

// Socket and interface initialization constants
constexpr int32_t INVALID_SOCKET_FD = -1;  // Invalid socket file descriptor
constexpr uint32_t INVALID_INTERFACE_INDEX = 0;  // Invalid interface index
constexpr uint16_t INVALID_PROTOCOL = 0;  // Invalid protocol

DhcpArpChecker::DhcpArpChecker() : m_isSocketCreated(false), m_socketFd(INVALID_SOCKET_FD),
    m_ifaceIndex(INVALID_INTERFACE_INDEX), m_protocol(INVALID_PROTOCOL)
{
    DHCP_LOGI("DhcpArpChecker()");
    dhcpArpCheckerThread_ = std::make_unique<DhcpThread>(DHCP_ARP_CHECKER_THREAD);
}

DhcpArpChecker::~DhcpArpChecker()
{
    DHCP_LOGI("~DhcpArpChecker()");
    Stop();
    if (dhcpArpCheckerThread_) {
        dhcpArpCheckerThread_.reset();
    }
}

bool DhcpArpChecker::Start(std::string& ifname, std::string& hwAddr, std::string& senderIp, std::string& targetIp)
{
    // Input parameter validation
    if (ifname.empty() || hwAddr.empty() || senderIp.empty() || targetIp.empty()) {
        DHCP_LOGE("Start: invalid input parameters");
        return false;
    }

    if (m_isSocketCreated) {
        Stop();
    }

    // Parse and validate MAC address
    if (!ParseAndValidateMacAddress(hwAddr)) {
        return false;
    }

    // Create socket with timeout protection
    if (!CreateSocketWithTimeout(ifname)) {
        return false;
    }

    // Validate and set IP addresses
    return ValidateAndSetIpAddresses(senderIp, targetIp);
}

bool DhcpArpChecker::ParseAndValidateMacAddress(const std::string& hwAddr)
{
    // Simple length check
    if (hwAddr.length() != MAC_ADDR_STRING_LENGTH) {
        DHCP_LOGE("invalid hwAddr length:%{private}s", hwAddr.c_str());
        return false;
    }

    // Use regex for comprehensive format validation
    // Pattern: exactly 6 hex pairs separated by colons
    std::regex macPattern("^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$");
    if (!std::regex_match(hwAddr, macPattern)) {
        DHCP_LOGE("invalid hwAddr format:%{private}s", hwAddr.c_str());
        return false;
    }

    // Parse MAC address using sscanf_s (simpler than manual parsing)
    unsigned int macValues[ETH_ALEN];
    if (sscanf_s(hwAddr.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
        &macValues[MAC_ADDR_BYTE_0], &macValues[MAC_ADDR_BYTE_1], &macValues[MAC_ADDR_BYTE_2],
        &macValues[MAC_ADDR_BYTE_3], &macValues[MAC_ADDR_BYTE_4], &macValues[MAC_ADDR_BYTE_5]) != ETH_ALEN) {
        DHCP_LOGE("invalid hwAddr parsing failed:%{private}s", hwAddr.c_str());
        return false;
    }

    // Store MAC address (values already validated by regex)
    for (int i = 0; i < ETH_ALEN; i++) {
        m_localMacAddr[i] = static_cast<uint8_t>(macValues[i]);
    }
    
    // Set broadcast address
    if (memset_s(m_l2Broadcast, ETH_ALEN, MAC_BROADCAST_VALUE, ETH_ALEN) != EOK) {
        DHCP_LOGE("DhcpArpChecker memset fail");
        return false;
    }
    
    return true;
}

bool DhcpArpChecker::CreateSocketWithTimeout(const std::string& ifname)
{
    // Safety check: verify if interface is safe before starting
    if (!IsInterfaceSafe(ifname.c_str())) {
        DHCP_LOGE("interface is not safe: %{public}s", ifname.c_str());
        return false;
    }

    auto func = [this, ifname]() {
        return this->CreateSocket(ifname.c_str(), ETH_P_ARP);
    };

    // Use shorter timeout to detect bind stuck
    constexpr int32_t BIND_DETECTION_TIMEOUT_MS = 3000;  // 3 seconds detection timeout
    auto ret = dhcpArpCheckerThread_->PostSyncTimeOutTask(func, BIND_DETECTION_TIMEOUT_MS);
    if (ret == false) {
        DHCP_LOGE("DhcpArpChecker CreateSocket timeout in %{public}dms, bind blocked", BIND_DETECTION_TIMEOUT_MS);
        // Timeout occurred, bind is blocked, the attempt record will remain to prevent new attempts
        return false;
    }
    return true;
}

bool DhcpArpChecker::ValidateAndSetIpAddresses(const std::string& senderIp, const std::string& targetIp)
{
    // Validate IP address validity
    if (inet_aton(senderIp.c_str(), &m_localIpAddr) == 0) {
        DHCP_LOGE("invalid sender IP address: %{private}s", senderIp.c_str());
        return false;
    }

    if (inet_aton(targetIp.c_str(), &m_targetIpAddr) == 0) {
        DHCP_LOGE("invalid target IP address: %{private}s", targetIp.c_str());
        return false;
    }
    return true;
}

void DhcpArpChecker::Stop()
{
    if (!m_isSocketCreated) {
        return;
    }
    CloseSocket();
}

bool DhcpArpChecker::SetArpPacket(ArpPacket& arpPacket, bool isFillSenderIp)
{
    arpPacket.ar_hrd = htons(ARPHRD_ETHER);
    arpPacket.ar_pro = htons(ETH_P_IP);
    arpPacket.ar_hln = ETH_ALEN;
    arpPacket.ar_pln = IPV4_ALEN;
    arpPacket.ar_op = htons(ARPOP_REQUEST);
    if (memcpy_s(arpPacket.ar_sha, ETH_ALEN, m_localMacAddr, ETH_ALEN) != EOK) {
        DHCP_LOGE("DoArpCheck memcpy fail");
        return false;
    }
    if (isFillSenderIp) {
        if (memcpy_s(arpPacket.ar_spa, IPV4_ALEN, &m_localIpAddr, sizeof(m_localIpAddr)) != EOK) {
            DHCP_LOGE("DoArpCheck memcpy fail");
            return false;
        }
    } else {
        if (memset_s(arpPacket.ar_spa, IPV4_ALEN, 0, IPV4_ALEN) != EOK) {
            DHCP_LOGE("DoArpCheck memset fail");
            return false;
        }
    }
    if (memset_s(arpPacket.ar_tha, ETH_ALEN, 0, ETH_ALEN) != EOK) {
        DHCP_LOGE("DoArpCheck memset fail");
        return false;
    }
    if (memcpy_s(arpPacket.ar_tpa, IPV4_ALEN, &m_targetIpAddr, sizeof(m_targetIpAddr)) != EOK) {
        DHCP_LOGE("DoArpCheck memcpy fail");
        return false;
    }
    return true;
}

bool DhcpArpChecker::DoArpCheck(int32_t timeoutMillis, bool isFillSenderIp, uint64_t &timeCost)
{
    if (!m_isSocketCreated) {
        DHCP_LOGE("DoArpCheck failed, socket not created");
        return false;
    }

    struct ArpPacket arpPacket;
    if (!SetArpPacket(arpPacket, isFillSenderIp)) {
        return false;
    }

    if (SendData(reinterpret_cast<uint8_t *>(&arpPacket), sizeof(arpPacket), m_l2Broadcast) != 0) {
        return false;
    }

    return WaitForArpReply(timeoutMillis, timeCost);
}

bool DhcpArpChecker::WaitForArpReply(int32_t timeoutMillis, uint64_t &timeCost)
{
    timeCost = 0;
    int32_t leftMillis = timeoutMillis;
    uint8_t recvBuff[MAX_LENGTH];

    // Add overall timeout tracking to prevent infinite loop
    std::chrono::steady_clock::time_point overallStartTime = std::chrono::steady_clock::now();

    while (leftMillis > 0) {
        std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
        int32_t readLen = RecvData(recvBuff, sizeof(recvBuff), leftMillis);

        if (!UpdateTimeoutCounters(startTime, overallStartTime, timeoutMillis, leftMillis, "DoArpCheck")) {
            break; // Timeout reached
        }

        if (readLen < 0) {
            DHCP_LOGE("readLen < 0, stop arp");
            return false;
        }

        if (IsValidArpReply(recvBuff, readLen)) {
            int64_t overallElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - overallStartTime).count();
            timeCost = static_cast<uint64_t>(overallElapsed);
            return true;
        }
    }
    return false;
}

bool DhcpArpChecker::UpdateTimeoutCounters(const std::chrono::steady_clock::time_point& startTime,
                                           const std::chrono::steady_clock::time_point& overallStartTime,
                                           int32_t timeoutMillis, int32_t& leftMillis, const char* context)
{
    // Always calculate elapsed time after each operation
    std::chrono::steady_clock::time_point current = std::chrono::steady_clock::now();
    int64_t elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current - startTime).count();
    if (elapsed <= 0) {
        elapsed = MIN_PROGRESS_MS;  // Force at least 1ms progress
    }

    // Prevent integer overflow: check if elapsed exceeds leftMillis
    if (elapsed > leftMillis) {
        leftMillis = TIMEOUT_EXPIRED;  // Set to 0 directly, exit loop
    } else {
        leftMillis -= static_cast<int32_t>(elapsed);
    }

    // Double check overall timeout to prevent any edge cases
    int64_t overallElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        current - overallStartTime).count();
    if (overallElapsed >= timeoutMillis) {
        DHCP_LOGW("%{public}s overall timeout reached", context ? context : "Operation");
        return false;
    }
    return true;
}

bool DhcpArpChecker::IsValidArpReply(uint8_t* recvBuff, int32_t readLen)
{
    if (readLen < static_cast<int32_t>(sizeof(struct ArpPacket))) {
        return false;
    }

    // Safety check: ensure received data is large enough to avoid buffer overflow
    if (readLen < static_cast<int32_t>(sizeof(struct ArpPacket)) || readLen > MAX_LENGTH) {
        DHCP_LOGW("Invalid packet size: %{public}d, expected >= %{public}zu",
                  readLen, sizeof(struct ArpPacket));
        return false;
    }

    struct ArpPacket *respPacket = reinterpret_cast<struct ArpPacket*>(recvBuff);
    return (ntohs(respPacket->ar_hrd) == ARPHRD_ETHER &&
            ntohs(respPacket->ar_pro) == ETH_P_IP &&
            respPacket->ar_hln == ETH_ALEN &&
            respPacket->ar_pln == IPV4_ALEN &&
            ntohs(respPacket->ar_op) == ARPOP_REPLY &&
            memcmp(respPacket->ar_sha, m_localMacAddr, ETH_ALEN) != 0 &&
            memcmp(respPacket->ar_spa, &m_targetIpAddr, IPV4_ALEN) == 0);
}

void DhcpArpChecker::GetGwMacAddrList(int32_t timeoutMillis, bool isFillSenderIp, std::vector<std::string>& gwMacLists)
{
    gwMacLists.clear();
    if (!m_isSocketCreated) {
        DHCP_LOGE("GetGwMacAddrList failed, socket not created");
        return;
    }

    struct ArpPacket arpPacket;
    if (!SetArpPacket(arpPacket, isFillSenderIp)) {
        DHCP_LOGE("GetGwMacAddrList SetArpPacket failed");
        return;
    }

    if (SendData(reinterpret_cast<uint8_t *>(&arpPacket), sizeof(arpPacket), m_l2Broadcast) != 0) {
        DHCP_LOGE("GetGwMacAddrList SendData failed");
        return;
    }

    CollectGwMacAddresses(timeoutMillis, gwMacLists);
}

void DhcpArpChecker::CollectGwMacAddresses(int32_t timeoutMillis, std::vector<std::string>& gwMacLists)
{
    int32_t leftMillis = timeoutMillis;
    uint8_t recvBuff[MAX_LENGTH];

    // Add overall timeout tracking to prevent infinite loop
    std::chrono::steady_clock::time_point overallStartTime = std::chrono::steady_clock::now();

    while (leftMillis > 0) {
        std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
        int32_t readLen = RecvData(recvBuff, sizeof(recvBuff), leftMillis);

        ProcessReceivedPacket(recvBuff, readLen, gwMacLists);

        if (!UpdateTimeoutCounters(startTime, overallStartTime, timeoutMillis, leftMillis, "GetGwMacAddrList")) {
            break; // Timeout reached
        }
    }
}

void DhcpArpChecker::ProcessReceivedPacket(uint8_t* recvBuff, int32_t readLen, std::vector<std::string>& gwMacLists)
{
    if (readLen >= static_cast<int32_t>(sizeof(struct ArpPacket)) && readLen <= MAX_LENGTH) {
        struct ArpPacket *respPacket = reinterpret_cast<struct ArpPacket*>(recvBuff);
        if (ntohs(respPacket->ar_hrd) == ARPHRD_ETHER &&
            ntohs(respPacket->ar_pro) == ETH_P_IP &&
            respPacket->ar_hln == ETH_ALEN &&
            respPacket->ar_pln == IPV4_ALEN &&
            ntohs(respPacket->ar_op) == ARPOP_REPLY &&
            memcmp(respPacket->ar_sha, m_localMacAddr, ETH_ALEN) != 0 &&
            memcmp(respPacket->ar_spa, &m_targetIpAddr, IPV4_ALEN) == 0) {
            std::string gwMacAddr = MacArray2Str(respPacket->ar_sha, ETH_ALEN);
            SaveGwMacAddr(gwMacAddr, gwMacLists);
        }
    } else if (readLen > MAX_LENGTH) {
        DHCP_LOGW("GetGwMacAddrList: packet too large: %{public}d", readLen);
    }
}

void DhcpArpChecker::SaveGwMacAddr(std::string gwMacAddr, std::vector<std::string>& gwMacLists)
{
    auto it = std::find(gwMacLists.begin(), gwMacLists.end(), gwMacAddr);
    if (!gwMacAddr.empty() && (it == gwMacLists.end())) {
        gwMacLists.push_back(gwMacAddr);
    }
}

int32_t DhcpArpChecker::CreateSocket(const char *iface, uint16_t protocol)
{
    if (iface == nullptr) {
        DHCP_LOGE("iface is null");
        return OPT_FAIL;
    }

    int32_t ifaceIndex = GetInterfaceIndex(iface);
    if (ifaceIndex <= 0) {
        return OPT_FAIL;
    }

    int32_t socketFd = CreateRawSocket(protocol);
    if (socketFd < 0) {
        return OPT_FAIL;
    }

    if (BindSocketToInterface(socketFd, ifaceIndex, protocol, iface) != OPT_SUCC) {
        (void)close(socketFd);
        return OPT_FAIL;
    }

    // Success, update socket state
    m_socketFd = socketFd;
    m_ifaceIndex = ifaceIndex;
    m_protocol = protocol;
    m_isSocketCreated = true;
    return OPT_SUCC;
}

int32_t DhcpArpChecker::GetInterfaceIndex(const char *iface)
{
    int32_t ifaceIndex = static_cast<int32_t>(if_nametoindex(iface));
    if (ifaceIndex == 0) {
        DHCP_LOGE("get iface index fail: %{public}s", iface);
        return -1;
    }
    if (ifaceIndex > INTEGER_MAX) {
        DHCP_LOGE("ifaceIndex > max interger, fail:%{public}s ifaceIndex:%{public}d", iface, ifaceIndex);
        return -1;
    }
    return ifaceIndex;
}

int32_t DhcpArpChecker::CreateRawSocket(uint16_t protocol)
{
    int32_t socketFd = socket(PF_PACKET, SOCK_DGRAM, htons(protocol));
    if (socketFd < 0) {
        DHCP_LOGE("create socket fail");
        return -1;
    }

    if (!SetNonBlock(socketFd)) {  // SetNonBlock returns true on success, false on failure
        DHCP_LOGE("set non block fail");
        (void)close(socketFd);
        return -1;
    }
    return socketFd;
}

int32_t DhcpArpChecker::BindSocketToInterface(int32_t socketFd, int32_t ifaceIndex,
                                              uint16_t protocol, const char *iface)
{
    struct sockaddr_ll rawAddr;
    rawAddr.sll_ifindex = ifaceIndex;
    rawAddr.sll_protocol = htons(protocol);
    rawAddr.sll_family = AF_PACKET;

    // Record attempt here, just before the actual bind operation
    RecordInterfaceAttempt(iface);

    // Simple direct bind, may get stuck but we accept this risk
    DHCP_LOGI("Attempting bind on interface %{public}s (may block)", iface);
    int32_t ret = bind(socketFd, reinterpret_cast<struct sockaddr *>(&rawAddr), sizeof(rawAddr));
    if (ret != 0) {
        DHCP_LOGE("bind failed on interface %{public}s, errno=%{public}d", iface, errno);
        // bind failed, clear attempt record
        {
            std::lock_guard<std::mutex> lock(g_interfaceAttemptMutex);
            std::string ifname(iface);
            g_ongoingAttempts.erase(ifname);
        }
        return OPT_FAIL;
    }

    DHCP_LOGI("bind successful on interface %{public}s", iface);

    // Success, clear attempt record
    {
        std::lock_guard<std::mutex> lock(g_interfaceAttemptMutex);
        std::string ifname(iface);
        g_ongoingAttempts.erase(ifname);
    }
    return OPT_SUCC;
}

int32_t DhcpArpChecker::SendData(uint8_t *buff, int32_t count, uint8_t *destHwaddr)
{
    if (buff == nullptr || destHwaddr == nullptr) {
        DHCP_LOGE("buff or dest hwaddr is null");
        return OPT_FAIL;
    }

    if (m_socketFd <= INVALID_SOCKET_FD || m_ifaceIndex == INVALID_INTERFACE_INDEX) {
        DHCP_LOGE("invalid socket fd");
        return OPT_FAIL;
    }

    struct sockaddr_ll rawAddr;
    (void)memset_s(&rawAddr, sizeof(rawAddr), 0, sizeof(rawAddr));
    rawAddr.sll_ifindex = m_ifaceIndex;
    rawAddr.sll_protocol = htons(m_protocol);
    rawAddr.sll_family = AF_PACKET;
    if (memcpy_s(rawAddr.sll_addr, sizeof(rawAddr.sll_addr), destHwaddr, ETH_ALEN) != EOK) {
        DHCP_LOGE("Send: memcpy fail");
        return OPT_FAIL;
    }

    int32_t ret;
    do {
        ret = sendto(m_socketFd, buff, count, 0, reinterpret_cast<struct sockaddr *>(&rawAddr), sizeof(rawAddr));
        if (ret == -1) {
            DHCP_LOGE("Send: sendto fail");
            if (errno != EINTR) {
                break;
            }
        }
    } while (ret == -1);
    return ret > 0 ? OPT_SUCC : OPT_FAIL;
}

int32_t DhcpArpChecker::RecvData(uint8_t *buff, int32_t count, int32_t timeoutMillis)
{
    DHCP_LOGI("RecvData timeoutMillis:%{public}d", timeoutMillis);

    // Enhanced parameter validation
    if (buff == nullptr || count <= 0) {
        DHCP_LOGE("RecvData: invalid parameters");
        return -1;
    }

    if (m_socketFd <= INVALID_SOCKET_FD) {
        DHCP_LOGE("invalid socket fd");
        return -1;
    }

    // Check if socket is still valid
    if (!m_isSocketCreated) {
        DHCP_LOGE("socket not in created state");
        return -1;
    }

    pollfd fds[1];
    fds[0].fd = m_socketFd;
    fds[0].events = POLLIN;
    if (poll(fds, 1, timeoutMillis) <= 0) {
        DHCP_LOGW("RecvData poll timeout or error");
        return 0;
    }
    DHCP_LOGI("RecvData poll finished");
    int32_t nBytes;
    do {
        nBytes = read(m_socketFd, buff, count);
        if (nBytes == -1) {
            if (errno != EINTR) {
                break;
            }
        }
    } while (nBytes == -1);
    return nBytes < 0 ? 0 : nBytes;
}

int32_t DhcpArpChecker::CloseSocket(void)
{
    int32_t ret = OPT_FAIL;
    if (m_socketFd >= 0) {
        ret = close(m_socketFd);
        if (ret != OPT_SUCC) {
            DHCP_LOGE("close fail.");
        }
    }
    m_socketFd = -1;
    m_ifaceIndex = 0;
    m_protocol = 0;
    m_isSocketCreated = false;
    DHCP_LOGI("close success.");
    return ret;
}

bool DhcpArpChecker::SetNonBlock(int32_t fd)
{
    int32_t ret = fcntl(fd, F_GETFL);
    if (ret < 0) {
        return false;
    }

    uint32_t flags = (static_cast<uint32_t>(ret) | O_NONBLOCK);
    return fcntl(fd, F_SETFL, flags) == 0;  // fcntl returns 0 on success, -1 on failure
}

bool DhcpArpChecker::IsInterfaceSafe(const char *iface)
{
    if (iface == nullptr) {
        return false;
    }

    std::lock_guard<std::mutex> lock(g_interfaceAttemptMutex);
    std::string ifname(iface);

    // Check if there's an incomplete bind attempt in progress
    auto it = g_ongoingAttempts.find(ifname);
    if (it != g_ongoingAttempts.end()) {
        // There's an ongoing attempt, refuse new attempts
        DHCP_LOGW("Interface %{public}s has a bind attempt in progress, refusing new attempt", iface);
        return false;
    }
    return true; // Safe, can attempt
}

void DhcpArpChecker::RecordInterfaceAttempt(const char *iface)
{
    if (iface == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_interfaceAttemptMutex);
    std::string ifname(iface);
    g_ongoingAttempts.insert(ifname);
}

void DhcpArpChecker::ClearGlobalState()
{
    std::lock_guard<std::mutex> lock(g_interfaceAttemptMutex);
    g_ongoingAttempts.clear();
    DHCP_LOGI("Global state cleared for testing");
}

}
}