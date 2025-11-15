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

#ifndef OHOS_DHCP_ARP_CHECKER_H
#define OHOS_DHCP_ARP_CHECKER_H

#include <arpa/inet.h>
#include <chrono>
#include <netinet/if_ether.h>
#include <string>
#include <mutex>
#include "dhcp_thread.h"

namespace OHOS {
namespace DHCP {
constexpr int32_t IPV4_ALEN = 4;
constexpr int32_t INTEGER_MAX = 0x7FFFFFFF;

struct ArpPacket {
    uint16_t ar_hrd; // hardware type
    uint16_t ar_pro; // protocol type
    uint8_t ar_hln; // length of hardware address
    uint8_t ar_pln; // length of protocol address
    uint16_t ar_op; // opcode
    uint8_t ar_sha[ETH_ALEN]; // sender hardware address
    uint8_t ar_spa[IPV4_ALEN]; // sender protocol address
    uint8_t ar_tha[ETH_ALEN]; // target hardware address
    uint8_t ar_tpa[IPV4_ALEN]; // target protocol address
} __attribute__ ((__packed__));

class DhcpArpChecker {
public:
    DhcpArpChecker();
    ~DhcpArpChecker();
    bool Start(std::string& ifname, std::string& hwAddr, std::string& senderIp, std::string& targetIp);
    void Stop();
    bool DoArpCheck(int32_t timeoutMillis, bool isFillSenderIp, uint64_t &timeCost);
    void GetGwMacAddrList(int32_t timeoutMillis, bool isFillSenderIp, std::vector<std::string>& gwMacLists);
    
    // Static method for testing to clear global state
    static void ClearGlobalState();

private:
    bool SetArpPacket(ArpPacket& arpPacket, bool isFillSenderIp);
    int32_t CreateSocket(const char *iface, uint16_t protocol);
    int32_t SendData(uint8_t *buff, int32_t count, uint8_t *destHwaddr);
    int32_t RecvData(uint8_t *buff, int32_t count, int32_t timeoutMillis);
    int32_t CloseSocket(void);
    bool SetNonBlock(int32_t fd);
    bool IsInterfaceSafe(const char *iface);
    void RecordInterfaceAttempt(const char *iface);
    void SaveGwMacAddr(std::string gwMacAddr, std::vector<std::string>& gwMacLists);
    
    // Helper functions for Start()
    bool ParseAndValidateMacAddress(const std::string& hwAddr);
    bool CreateSocketWithTimeout(const std::string& ifname);
    bool ValidateAndSetIpAddresses(const std::string& senderIp, const std::string& targetIp);
    
    // Helper functions for DoArpCheck()
    bool WaitForArpReply(int32_t timeoutMillis, uint64_t &timeCost);
    bool UpdateTimeoutCounters(const std::chrono::steady_clock::time_point& startTime,
                              const std::chrono::steady_clock::time_point& overallStartTime,
                              int32_t timeoutMillis, int32_t& leftMillis, const char* context = nullptr);
    bool IsValidArpReply(uint8_t* recvBuff, int32_t readLen);
    
    // Helper functions for GetGwMacAddrList()
    void CollectGwMacAddresses(int32_t timeoutMillis, std::vector<std::string>& gwMacLists);
    void ProcessReceivedPacket(uint8_t* recvBuff, int32_t readLen, std::vector<std::string>& gwMacLists);
    
    // Helper functions for CreateSocket()
    int32_t GetInterfaceIndex(const char *iface);
    int32_t CreateRawSocket(uint16_t protocol);
    int32_t BindSocketToInterface(int32_t socketFd, int32_t ifaceIndex, uint16_t protocol, const char *iface);
private:
    std::unique_ptr<DhcpThread> dhcpArpCheckerThread_ = nullptr;
    std::mutex arpMutex_;
    bool m_isSocketCreated;
    struct in_addr m_localIpAddr;
    struct in_addr m_targetIpAddr;
    uint8_t m_localMacAddr[ETH_ALEN];
    uint8_t m_l2Broadcast[ETH_ALEN];
    int32_t m_socketFd;
    uint16_t m_ifaceIndex;
    uint16_t m_protocol;
};
}
}
#endif
