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
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstddef>
#include <cstdint>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "securec.h"
#include "dhcp_logger.h"
#include "dhcp_function.h"
#include "dhcp_ipv6_client.h"
#include "dhcp_ipv6_dns_repository.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Ref;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;
DEFINE_DHCPLOG_DHCP_LABEL("DnsServerRepositoryTest");
using namespace OHOS::DHCP;
class DnsServerRepositoryTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        mRepository = new DnsServerRepository(minLifetime_);
    }
    virtual void TearDown()
    {
        delete mRepository;
        mRepository = nullptr;
    }
    DnsServerRepository* mRepository;
    const int minLifetime_ = 1000;
};


HWTEST_F(DnsServerRepositoryTest, TestAddServersWithValidLifetime, TestSize.Level1) {
    DHCP_LOGI("TestAddServersWithValidLifetime enter!");
    std::vector<std::string> addresses = {"2001:db8::1", "2001:db8::2"};
    bool result = mRepository->AddServers(2000, addresses);
    EXPECT_TRUE(result);
}

HWTEST_F(DnsServerRepositoryTest, TestAddServersWithZeroLifetime, TestSize.Level1) {
    DHCP_LOGI("TestAddServersWithZeroLifetime enter!");
    std::vector<std::string> addresses = {"2001:db8::1"};
    mRepository->AddServers(2000, addresses);
    bool result = mRepository->AddServers(0, addresses);
    EXPECT_TRUE(result);
}

HWTEST_F(DnsServerRepositoryTest, TestAddServersWithInvalidLifetime, TestSize.Level1) {
    DHCP_LOGI("TestAddServersWithInvalidLifetime enter!");
    std::vector<std::string> addresses = {"2001:db8::1"};
    bool result = mRepository->AddServers(500, addresses);
    EXPECT_FALSE(result);
}

HWTEST_F(DnsServerRepositoryTest, TestSetCurrentServers, TestSize.Level1) {
    DHCP_LOGI("TestSetCurrentServers enter!");
    DhcpIpv6Info ipv6Info;
    std::vector<std::string> addresses = {"2001:db8::1", "2001:db8::2"};
    mRepository->currentServers_ = std::unordered_set<std::string>(addresses.begin(), addresses.end());
    bool result = mRepository->SetCurrentServers(ipv6Info);
    EXPECT_TRUE(result);
}

HWTEST_F(DnsServerRepositoryTest, TestUpdateExistingEntry, TestSize.Level1) {
    DHCP_LOGI("TestUpdateExistingEntry enter!");
    std::string address = "2001:db8::1";
    uint64_t newExpiry = 1000000;
    mRepository->allServers_.push_back({address, 500000});
    bool result = mRepository->UpdateExistingEntry(address, newExpiry);
    EXPECT_TRUE(result);
}

HWTEST_F(DnsServerRepositoryTest, TestUpdateCurrentServers, TestSize.Level1) {
    DHCP_LOGI("TestUpdateCurrentServers!");
    std::string address = "2001:db8::11";
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    mRepository->allServers_.push_back({address, now + 500000});
    mRepository->currentServers_.clear();
    bool result = mRepository->UpdateCurrentServers();
    EXPECT_TRUE(result);
}
