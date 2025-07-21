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
#include <net/if_arp.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "securec.h"
#include "dhcp_common_utils.h"
#include "dhcp_logger.h"

namespace OHOS {
namespace DHCP {
DEFINE_DHCPLOG_DHCP_LABEL("DhcpArpChecker");
constexpr const char *DHCP_ARP_CHECKER_THREAD = "DHCP_ARP_CHECKER_THREAD";
constexpr int32_t MIN_WAIT_TIME_MS_THREAD = 2000;
constexpr int32_t Time_OUT_BUFFER = 1000;
constexpr int32_t MAX_LENGTH = 1500;
constexpr int32_t OPT_SUCC = 0;
constexpr int32_t OPT_FAIL = -1;

DhcpArpChecker::DhcpArpChecker() : m_isSocketCreated(false), m_socketFd(-1), m_ifaceIndex(0), m_protocol(0)
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
    if (m_isSocketCreated) {
        Stop();
    }
    uint8_t mac[ETH_ALEN + sizeof(uint32_t)];
    if (sscanf_s(hwAddr.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
        &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != ETH_ALEN) {  // mac address
        DHCP_LOGE("invalid hwAddr:%{private}s", hwAddr.c_str());
        if (memset_s(mac, sizeof(mac), 0, sizeof(mac)) != EOK) {
            DHCP_LOGE("ArpChecker memset fail");
        }
    }
    auto func = [this, ifname]() {
        return this->CreateSocket(ifname.c_str(), ETH_P_ARP);
    };
    auto ret = dhcpArpCheckerThread_->PostSyncTimeOutTask(func, MIN_WAIT_TIME_MS_THREAD);
    if (ret == false) {
        DHCP_LOGE("DhcpArpChecker CreateSocket failed");
        m_isSocketCreated = false;
        return false;
    }
    m_isSocketCreated = true;
    inet_aton(senderIp.c_str(), &m_localIpAddr);
    if (memcpy_s(m_localMacAddr, ETH_ALEN, mac, ETH_ALEN) != EOK) {
        DHCP_LOGE("DhcpArpChecker memcpy fail");
        return false;
    }
    if (memset_s(m_l2Broadcast, ETH_ALEN, 0xFF, ETH_ALEN) != EOK) {
        DHCP_LOGE("DhcpArpChecker memset fail");
        return false;
    }
    inet_aton(targetIp.c_str(), &m_targetIpAddr);
    return true;
}

void DhcpArpChecker::Stop()
{
    if (!m_isSocketCreated) {
        return;
    }
    auto func = [this]() {
        return this->CloseSocket();
    };
    dhcpArpCheckerThread_->PostSyncTimeOutTask(func, MIN_WAIT_TIME_MS_THREAD);
    m_isSocketCreated = false;
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
    auto func = [this, timeoutMillis, isFillSenderIp, &timeCost]() {
        struct ArpPacket arpPacket;
        if (!SetArpPacket(arpPacket, isFillSenderIp)) {
            DHCP_LOGE("SetArpPacket failed");
            return OPT_FAIL;
        }

        if (SendData(reinterpret_cast<uint8_t *>(&arpPacket), sizeof(arpPacket), m_l2Broadcast) != 0) {
            return OPT_FAIL;
        }
        timeCost = 0;
        int32_t readLen = 0;
        int64_t elapsed = 0;
        int32_t leftMillis = timeoutMillis;
        uint8_t recvBuff[MAX_LENGTH];
        std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
        while (leftMillis > 0) {
            readLen = RecvData(recvBuff, sizeof(recvBuff), leftMillis);
            if (readLen < 0) {
                DHCP_LOGE("readLen < 0, stop arp");
                return OPT_FAIL;
            }
            if (readLen < static_cast<int32_t>(sizeof(struct ArpPacket))) {
                std::chrono::steady_clock::time_point current = std::chrono::steady_clock::now();
                elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current - startTime).count();
                leftMillis -= static_cast<int32_t>(elapsed);
                continue;
            }
            struct ArpPacket *respPacket = reinterpret_cast<struct ArpPacket*>(recvBuff);
            if (ntohs(respPacket->ar_hrd) == ARPHRD_ETHER &&
                ntohs(respPacket->ar_pro) == ETH_P_IP &&
                respPacket->ar_hln == ETH_ALEN &&
                respPacket->ar_pln == IPV4_ALEN &&
                ntohs(respPacket->ar_op) == ARPOP_REPLY &&
                memcmp(respPacket->ar_sha, m_localMacAddr, ETH_ALEN) != 0 &&
                memcmp(respPacket->ar_spa, &m_targetIpAddr, IPV4_ALEN) == 0) {
                std::chrono::steady_clock::time_point current = std::chrono::steady_clock::now();
                timeCost = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(current - startTime).count());
                return OPT_SUCC;
            }
        }
        return OPT_FAIL;
    };
    return dhcpArpCheckerThread_->PostSyncTimeOutTask(func, std::max(MIN_WAIT_TIME_MS_THREAD,
        timeoutMillis + Time_OUT_BUFFER);
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
    int32_t readLen = 0;
    int32_t leftMillis = timeoutMillis;
    uint8_t recvBuff[MAX_LENGTH];
    std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
    while (leftMillis > 0) {
        readLen = RecvData(recvBuff, sizeof(recvBuff), leftMillis);
        if (readLen >= static_cast<int32_t>(sizeof(struct ArpPacket))) {
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
        }
        std::chrono::steady_clock::time_point current = std::chrono::steady_clock::now();
        int64_t elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current - startTime).count();
        leftMillis -= static_cast<int32_t>(elapsed);
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

    int32_t ifaceIndex = static_cast<int32_t>(if_nametoindex(iface));
    if (ifaceIndex == 0) {
        DHCP_LOGE("get iface index fail: %{public}s", iface);
        return OPT_FAIL;
    }
    if (ifaceIndex > INTEGER_MAX) {
        DHCP_LOGE("ifaceIndex > max interger, fail:%{public}s ifaceIndex:%{public}d", iface, ifaceIndex);
        return OPT_FAIL;
    }
    int32_t socketFd = socket(PF_PACKET, SOCK_DGRAM, htons(protocol));
    if (socketFd < 0) {
        DHCP_LOGE("create socket fail");
        return OPT_FAIL;
    }

    if (SetNonBlock(socketFd)) {
        DHCP_LOGE("set non block fail");
        (void)close(socketFd);
        return OPT_FAIL;
    }

    struct sockaddr_ll rawAddr;
    rawAddr.sll_ifindex = ifaceIndex;
    rawAddr.sll_protocol = htons(protocol);
    rawAddr.sll_family = AF_PACKET;

    int32_t ret = bind(socketFd, reinterpret_cast<struct sockaddr *>(&rawAddr), sizeof(rawAddr));
    if (ret != 0) {
        DHCP_LOGE("bind fail");
        (void)close(socketFd);
        return OPT_FAIL;
    }
    m_socketFd = socketFd;
    m_ifaceIndex = ifaceIndex;
    m_protocol = protocol;
    return OPT_SUCC;
}

int32_t DhcpArpChecker::SendData(uint8_t *buff, int32_t count, uint8_t *destHwaddr)
{
    if (buff == nullptr || destHwaddr == nullptr) {
        DHCP_LOGE("buff or dest hwaddr is null");
        return OPT_FAIL;
    }

    if (m_socketFd < 0 || m_ifaceIndex == 0) {
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
    DHCP_LOGI("RecvData poll start");
    if (m_socketFd < 0) {
        DHCP_LOGE("invalid socket fd");
        return -1;
    }

    pollfd fds[1];
    fds[0].fd = m_socketFd;
    fds[0].events = POLLIN;
    if (poll(fds, 1, timeoutMillis) <= 0) {
        DHCP_LOGW("RecvData poll timeout");
        return 0;
    }
    DHCP_LOGI("RecvData poll end");
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
    return ret;
}

bool DhcpArpChecker::SetNonBlock(int32_t fd)
{
    int32_t ret = fcntl(fd, F_GETFL);
    if (ret < 0) {
        return false;
    }

    uint32_t flags = (static_cast<uint32_t>(ret) | O_NONBLOCK);
    return fcntl(fd, F_SETFL, flags);
}
}
}