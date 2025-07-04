/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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


#include "dhcp_arp_checker_fuzzer.h"
#include "dhcp_arp_checker.h"
#include "dhcp_fuzz_common_func.h"
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include "securec.h"
#include "dhcp_arp_checker.h"

using namespace std;
namespace OHOS {
namespace DHCP {

constexpr size_t MIN_U32_SIZE = sizeof(uint32_t);
constexpr size_t MIN_U16_SIZE = sizeof(uint16_t);
constexpr int32_t DEFAULT_TIMEOUT_MILLIS = 1000;
constexpr size_t MIN_ETH_ALEN = ETH_ALEN;

std::shared_ptr<DhcpArpChecker> pDhcpArpChecker = std::make_shared<DhcpArpChecker>();

void TestStart(const uint8_t* data, size_t size)
{
    if (size < MIN_U32_SIZE) {
        return;
    }
    size_t pos = 0;
    uint32_t ifnameLen = U32_AT(data);
    pos += MIN_U32_SIZE;
    if (pos + ifnameLen > size) {
        return;
    }
    string ifname(reinterpret_cast<const char*>(data + pos), ifnameLen);
    pos += ifnameLen;
    
    if (pos + MIN_U32_SIZE > size) {
        return;
    }
    uint32_t hwAddrLen = U32_AT(data + pos);
    pos += MIN_U32_SIZE;
    if (pos + hwAddrLen > size) {
        return;
    }
    string hwAddr(reinterpret_cast<const char*>(data + pos), hwAddrLen);
    pos += hwAddrLen;
    
    if (pos + MIN_U32_SIZE > size) {
        return;
    }
    uint32_t senderIpLen = U32_AT(data + pos);
    pos += MIN_U32_SIZE;
    if (pos + senderIpLen > size) {
        return;
    }
    string senderIp(reinterpret_cast<const char*>(data + pos), senderIpLen);
    pos += senderIpLen;
    
    if (pos + MIN_U32_SIZE > size) {
        return;
    }
    uint32_t targetIpLen = U32_AT(data + pos);
    pos += MIN_U32_SIZE;
    if (pos + targetIpLen > size) {
        return;
    }
    string targetIp(reinterpret_cast<const char*>(data + pos), targetIpLen);
    
    pDhcpArpChecker->Start(ifname, hwAddr, senderIp, targetIp);
}

void TestStop(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    pDhcpArpChecker->Stop();
}

void TestSetArpPacket(const uint8_t* data, size_t size)
{
    ArpPacket arpPacket;
    bool isFillSenderIp = (size >= 1) ? (data[0] != 0) : false;
    pDhcpArpChecker->SetArpPacket(arpPacket, isFillSenderIp);
}

void TestDoArpCheck(const uint8_t* data, size_t size)
{
    int32_t timeoutMillis = (size >= MIN_U32_SIZE) ? static_cast<int32_t>(U32_AT(data)) : DEFAULT_TIMEOUT_MILLIS;
    bool isFillSenderIp = (size >= MIN_U32_SIZE + 1) ? (data[MIN_U32_SIZE] != 0) : false;
    uint64_t timeCost = 0;
    pDhcpArpChecker->DoArpCheck(timeoutMillis, isFillSenderIp, timeCost);
}

void TestGetGwMacAddrList(const uint8_t* data, size_t size)
{
    int32_t timeoutMillis = (size >= MIN_U32_SIZE) ? static_cast<int32_t>(U32_AT(data)) : DEFAULT_TIMEOUT_MILLIS;
    bool isFillSenderIp = (size >= MIN_U32_SIZE + 1) ? (data[MIN_U32_SIZE] != 0) : false;
    vector<string> gwMacLists;
    pDhcpArpChecker->GetGwMacAddrList(timeoutMillis, isFillSenderIp, gwMacLists);
}

void TestSaveGwMacAddr(const uint8_t* data, size_t size)
{
    if (size < MIN_U32_SIZE) {
        return;
    }
    size_t pos = 0;
    uint32_t gwMacAddrLen = U32_AT(data);
    pos += MIN_U32_SIZE;
    if (pos + gwMacAddrLen > size) {
        return;
    }
    string gwMacAddr(reinterpret_cast<const char*>(data + pos), gwMacAddrLen);
    vector<string> gwMacLists;
    pDhcpArpChecker->SaveGwMacAddr(gwMacAddr, gwMacLists);
}

void TestCreateSocket(const uint8_t* data, size_t size)
{
    if (size < MIN_U32_SIZE) {
        return;
    }
    size_t pos = 0;
    uint32_t ifaceLen = U32_AT(data);
    pos += MIN_U32_SIZE;
    if (pos + ifaceLen > size) {
        return;
    }
    string iface(reinterpret_cast<const char*>(data + pos), ifaceLen);
    uint16_t protocol = (size >= pos + MIN_U16_SIZE) ? static_cast<uint16_t>(U16_AT(data + pos)) : ETH_P_ARP;
    pDhcpArpChecker->CreateSocket(iface.c_str(), protocol);
}

void TestSendData(const uint8_t* data, size_t size)
{
    if (size < MIN_U32_SIZE) {
        return;
    }
    size_t pos = 0;
    uint32_t count = U32_AT(data);
    pos += MIN_U32_SIZE;
    if (pos + count > size) {
        return;
    }
    uint8_t* buff = const_cast<uint8_t*>(data + pos);
    pos += count;
    uint8_t destHwaddr[MIN_ETH_ALEN] = {0};
    if (pos + MIN_ETH_ALEN <= size) {
        if (memcpy_s(destHwaddr, MIN_ETH_ALEN, data + pos, MIN_ETH_ALEN) != 0) {
            return;
        }
    }
    pDhcpArpChecker->SendData(buff, count, destHwaddr);
}

void TestRecvData(const uint8_t* data, size_t size)
{
    if (size < MIN_U32_SIZE) {
        return;
    }
    size_t pos = 0;
    uint32_t count = U32_AT(data);
    pos += MIN_U32_SIZE;
    if (pos + count > size) {
        return;
    }
    uint8_t* buff = const_cast<uint8_t*>(data + pos);
    pos += count;
    int32_t timeoutMillis = (size >= pos + MIN_U32_SIZE) ?
        static_cast<int32_t>(U32_AT(data + pos)) : DEFAULT_TIMEOUT_MILLIS;
    pDhcpArpChecker->RecvData(buff, count, timeoutMillis);
}

void TestCloseSocket(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    pDhcpArpChecker->CloseSocket();
}

void TestSetNonBlock(const uint8_t* data, size_t size)
{
    int32_t fd = (size >= MIN_U32_SIZE) ? static_cast<int32_t>(U32_AT(data)) : 0;
    pDhcpArpChecker->SetNonBlock(fd);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= MIN_U32_SIZE)) {
        return 0;
    }
    
    TestStart(data, size);
    TestStop(data, size);
    TestSetArpPacket(data, size);
    TestDoArpCheck(data, size);
    TestGetGwMacAddrList(data, size);
    TestSaveGwMacAddr(data, size);
    TestCreateSocket(data, size);
    TestSendData(data, size);
    TestRecvData(data, size);
    TestCloseSocket(data, size);
    TestSetNonBlock(data, size);
    
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS