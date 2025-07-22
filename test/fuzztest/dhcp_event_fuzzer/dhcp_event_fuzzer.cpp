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

#include "dhcp_event_fuzzer.h"
#include "dhcp_event.h"
#include "securec.h"
#include <cstring>
#include <vector>
#include <string>
#include <memory>
#include <mutex>
#include <thread>
#include <chrono>

namespace OHOS {
    constexpr size_t MIN_FUZZ_SIZE = 4;
    constexpr size_t MAX_FUZZ_SIZE = 4096;
    constexpr size_t IP_ADDR_LEN = 16;
    constexpr size_t IFNAME_MAX_LEN = 16;
    constexpr size_t REASON_MAX_LEN = 256;
    constexpr size_t VENDOR_MAX_LEN = 255;
    constexpr size_t MAC_ADDR_LEN = 18;
    constexpr size_t DEVICE_NAME_LEN = 64;
    constexpr size_t IPV6_ADDR_LEN = 40;
    constexpr size_t MAX_DNS_COUNT = 5;
    constexpr size_t MAX_STATIONS_COUNT = 10;
    constexpr size_t MAX_LEASES_COUNT = 10;
    constexpr size_t THREAD_LOOP_COUNT = 10;
    constexpr size_t CALLBACK_LOOP_COUNT = 5;
    constexpr size_t IP_RANGE_MAX = 255;
    constexpr size_t MAC_RANGE_MAX = 256;
    constexpr size_t LARGE_TEST_COUNT = 1000;
    constexpr size_t LONG_STRING_LEN = 1024;
    constexpr size_t VERY_LONG_STRING_LEN = 2048;
    constexpr size_t LARGE_VECTOR_SIZE = 1000;
    constexpr size_t MALFORMED_STRING_LEN = 256;
    constexpr size_t OPERATION_TYPE_COUNT = 8;
    constexpr size_t ADDITIONAL_DATA_CHECK_SIZE = 50;
    constexpr uint8_t PARSER_SINGLE_BYTE = 1;
    constexpr size_t LOOP_START_INDEX = 0;
    constexpr int32_t SUCCESS_STATUS = 0;
    constexpr uint32_t MICROSECOND_DELAY = 1;
    constexpr int32_t FUNCTION_SUCCESS = 0;
    
    // Switch case constants for fuzzing operations
    constexpr uint8_t OP_CLIENT_SUCCESS = 0;
    constexpr uint8_t OP_CLIENT_FAIL = 1;
    constexpr uint8_t OP_CLIENT_REPORT_OR_SERVER = 2;
    constexpr uint8_t OP_SERVER_CALLBACK = 3;
    constexpr uint8_t OP_RESULT_INFO_COPY = 4;
    constexpr uint8_t OP_CALLBACK_REGISTRATION = 5;
    constexpr uint8_t OP_CONCURRENT_OPERATIONS = 6;
    constexpr uint8_t OP_EDGE_CASES = 7;

    class FuzzDataParser {
    public:
        explicit FuzzDataParser(const uint8_t* data, size_t size)
            : data_(data), size_(size), pos_(LOOP_START_INDEX) {}

        bool HasData(size_t length) const
        {
            return pos_ + length <= size_;
        }

        template<typename T>
        T Extract()
        {
            if (!HasData(sizeof(T))) {
                return T{};
            }
            T value;
            if (memcpy_s(&value, sizeof(T), data_ + pos_, sizeof(T)) != EOK) {
                return T{};
            }
            pos_ += sizeof(T);
            return value;
        }

        std::string ExtractString(size_t maxLen)
        {
            if (!HasData(PARSER_SINGLE_BYTE)) {
                return "";
            }

            if (maxLen == 0) {
                return "";
            }
            
            size_t len = Extract<uint8_t>() % maxLen;
            if (!HasData(len)) {
                len = std::min(len, size_ - pos_);
            }
            
            if (len == LOOP_START_INDEX) {
                return "";
            }

            std::string result(reinterpret_cast<const char*>(data_ + pos_), len);
            pos_ += len;
            
            // Ensure null termination and remove any embedded nulls
            for (auto& c : result) {
                if (c == '\0') c = '_';
            }
            return result;
        }

        std::vector<uint8_t> ExtractBytes(size_t length)
        {
            if (!HasData(length)) {
                length = std::min(length, size_ - pos_);
            }
            
            std::vector<uint8_t> result(data_ + pos_, data_ + pos_ + length);
            pos_ += length;
            return result;
        }

    private:
        const uint8_t* data_;
        size_t size_;
        size_t pos_;
    };
    // Mock callback implementations for testing
    class MockClientCallBack {
    public:
        static void OnIpSuccessChanged(int status, const char* ifname, DhcpResult* result)
        {
            // Mock implementation - just validate parameters
            if (ifname == nullptr || result == nullptr) {
                return;
            }
            // Simulate some processing
            volatile int dummy = status + strlen(ifname) + result->iptype;
            (void)dummy;
        }

        static void OnIpFailChanged(int status, const char* ifname, const char* reason)
        {
            // Mock implementation - just validate parameters
            if (ifname == nullptr || reason == nullptr) {
                return;
            }
            // Simulate some processing
            volatile int dummy = status + strlen(ifname) + strlen(reason);
            (void)dummy;
        }
    };

    class MockDhcpClientReport {
    public:
        static void OnDhcpClientReport(int status, const char* ifname, DhcpResult* result)
        {
            // Mock implementation - just validate parameters
            if (ifname == nullptr || result == nullptr) {
                return;
            }
            // Simulate some processing
            volatile int dummy = status + strlen(ifname) + result->iptype;
            (void)dummy;
        }
    };
    class MockServerCallBack {
    public:
        static void OnServerSuccess(const char* ifname, DhcpStationInfo* infos, size_t size)
        {
            // Mock implementation - just validate parameters
            if (ifname == nullptr || infos == nullptr || size <= LOOP_START_INDEX) {
                return;
            }
            // Simulate some processing
            volatile int dummy = strlen(ifname) + size;
            for (size_t i = LOOP_START_INDEX; i < size; i++) {
                dummy += strlen(infos[i].ipAddr);
            }
            (void)dummy;
        }
    };
    OHOS::DHCP::DhcpResult CreateFuzzDhcpResult(FuzzDataParser& parser)
    {
        OHOS::DHCP::DhcpResult result;
        
        result.isOptSuc = parser.Extract<bool>();
        result.iptype = parser.Extract<int32_t>();
        result.strYourCli = parser.ExtractString(IP_ADDR_LEN);
        result.strServer = parser.ExtractString(IP_ADDR_LEN);
        result.strSubnet = parser.ExtractString(IP_ADDR_LEN);
        result.strDns1 = parser.ExtractString(IP_ADDR_LEN);
        result.strDns2 = parser.ExtractString(IP_ADDR_LEN);
        result.strRouter1 = parser.ExtractString(IP_ADDR_LEN);
        result.strRouter2 = parser.ExtractString(IP_ADDR_LEN);
        result.strVendor = parser.ExtractString(VENDOR_MAX_LEN);
        result.strLinkIpv6Addr = parser.ExtractString(IPV6_ADDR_LEN); // IPv6 address length
        result.strRandIpv6Addr = parser.ExtractString(IPV6_ADDR_LEN);
        result.strLocalAddr1 = parser.ExtractString(IPV6_ADDR_LEN);
        result.strLocalAddr2 = parser.ExtractString(IPV6_ADDR_LEN);
        result.uLeaseTime = parser.Extract<uint32_t>();
        result.uAddTime = parser.Extract<uint32_t>();
        result.uGetTime = parser.Extract<uint32_t>();

        // Add some DNS addresses
        size_t dnsCount = parser.Extract<uint8_t>() % MAX_DNS_COUNT; // Max DNS addresses
        for (size_t i = LOOP_START_INDEX; i < dnsCount; i++) {
            std::string dns = parser.ExtractString(IP_ADDR_LEN);
            if (!dns.empty()) {
                result.vectorDnsAddr.push_back(dns);
            }
        }

        return result;
    }

    std::vector<DhcpStationInfo> CreateFuzzStationInfos(FuzzDataParser& parser)
    {
        std::vector<DhcpStationInfo> infos;
        
        size_t count = parser.Extract<uint8_t>() % MAX_STATIONS_COUNT; // Max stations
        for (size_t i = LOOP_START_INDEX; i < count; i++) {
            DhcpStationInfo info;
            
            std::string ip = parser.ExtractString(IP_ADDR_LEN);
            if (strncpy_s(info.ipAddr, sizeof(info.ipAddr), ip.c_str(), ip.length()) != EOK) {
                strncpy_s(info.ipAddr, sizeof(info.ipAddr), "192.168.1.100", strlen("192.168.1.100"));
            }
            
            std::string mac = parser.ExtractString(MAC_ADDR_LEN);
            if (strncpy_s(info.macAddr, sizeof(info.macAddr), mac.c_str(), mac.length()) != EOK) {
                strncpy_s(info.macAddr, sizeof(info.macAddr), "00:11:22:33:44:55", strlen("00:11:22:33:44:55"));
            }
            
            std::string device = parser.ExtractString(DEVICE_NAME_LEN);
            if (strncpy_s(info.deviceName, sizeof(info.deviceName), device.c_str(), device.length()) != EOK) {
                strncpy_s(info.deviceName, sizeof(info.deviceName), "TestDevice", strlen("TestDevice"));
            }
            
            infos.push_back(info);
        }
        
        return infos;
    }

    void FuzzClientCallBackOnIpSuccess(FuzzDataParser& parser)
    {
        DhcpClientCallBack clientCallback;
        
        int status = parser.Extract<int32_t>();
        std::string ifname = parser.ExtractString(IFNAME_MAX_LEN);
        OHOS::DHCP::DhcpResult result = CreateFuzzDhcpResult(parser);
        
        // Register mock callback
        ClientCallBack mockCallback = {
            MockClientCallBack::OnIpSuccessChanged,
            MockClientCallBack::OnIpFailChanged
        };
        
        clientCallback.RegisterCallBack(ifname, &mockCallback);
        
        // Test the callback
        clientCallback.OnIpSuccessChanged(status, ifname, result);
        
        // Unregister
        clientCallback.UnRegisterCallBack(ifname);
    }

    void FuzzClientCallBackOnIpFail(FuzzDataParser& parser)
    {
        DhcpClientCallBack clientCallback;
        
        int status = parser.Extract<int32_t>();
        std::string ifname = parser.ExtractString(IFNAME_MAX_LEN);
        std::string reason = parser.ExtractString(REASON_MAX_LEN);
        
        // Register mock callback
        ClientCallBack mockCallback = {
            MockClientCallBack::OnIpSuccessChanged,
            MockClientCallBack::OnIpFailChanged
        };
        
        clientCallback.RegisterCallBack(ifname, &mockCallback);
        
        // Test the callback
        clientCallback.OnIpFailChanged(status, ifname, reason);
        
        // Unregister
        clientCallback.UnRegisterCallBack(ifname);
    }

#ifndef OHOS_ARCH_LITE
    void FuzzClientCallBackOnDhcpOfferReport(FuzzDataParser& parser)
    {
        DhcpClientCallBack clientCallback;
        
        int status = parser.Extract<int32_t>();
        std::string ifname = parser.ExtractString(IFNAME_MAX_LEN);
        OHOS::DHCP::DhcpResult result = CreateFuzzDhcpResult(parser);
        
        // Register mock report callback
        DhcpClientReport mockReport = {
            MockDhcpClientReport::OnDhcpClientReport
        };
        
        clientCallback.RegisterDhcpClientReportCallBack(ifname, &mockReport);
        
        // Test the callback
        clientCallback.OnDhcpOfferReport(status, ifname, result);
    }
#endif

    void FuzzServerCallBack(FuzzDataParser& parser)
    {
        DhcpServerCallBack serverCallback;
        
        int status = parser.Extract<int32_t>();
        std::string ifname = parser.ExtractString(IFNAME_MAX_LEN);
        
        // Test OnServerStatusChanged
        serverCallback.OnServerStatusChanged(status);
        
        // Test OnServerLeasesChanged
        std::vector<std::string> leases;
        size_t leaseCount = parser.Extract<uint8_t>() % MAX_LEASES_COUNT;
        for (size_t i = LOOP_START_INDEX; i < leaseCount; i++) {
            std::string lease = parser.ExtractString(REASON_MAX_LEN);
            leases.push_back(lease);
        }
        serverCallback.OnServerLeasesChanged(ifname, leases);
        
        // Test OnServerSerExitChanged
        serverCallback.OnServerSerExitChanged(ifname);
        
        // Test OnServerSuccess
        std::vector<DhcpStationInfo> stationInfos = CreateFuzzStationInfos(parser);
        
        // Register mock callback
        ServerCallBack mockCallback;
        mockCallback.OnServerSuccess = MockServerCallBack::OnServerSuccess;
        
        serverCallback.RegisterCallBack(ifname, &mockCallback);
        serverCallback.OnServerSuccess(ifname, stationInfos);
        
        // Unregister
        serverCallback.UnRegisterCallBack(ifname);
    }

    void FuzzResultInfoCopy(FuzzDataParser& parser)
    {
        DhcpClientCallBack clientCallback;
        
        DhcpResult cResult;
        OHOS::DHCP::DhcpResult oResult = CreateFuzzDhcpResult(parser);
        
        // Test ResultInfoCopy with various data
        clientCallback.ResultInfoCopy(cResult, oResult);
    }

    void FuzzCallBackRegistration(FuzzDataParser& parser)
    {
        DhcpClientCallBack clientCallback;
        DhcpServerCallBack serverCallback;
        
        std::string ifname1 = parser.ExtractString(IFNAME_MAX_LEN);
        std::string ifname2 = parser.ExtractString(IFNAME_MAX_LEN);
        
        // Test client callback registration
        ClientCallBack mockClientCallback = {
            MockClientCallBack::OnIpSuccessChanged,
            MockClientCallBack::OnIpFailChanged
        };
        
        // Test multiple registrations with same interface
        clientCallback.RegisterCallBack(ifname1, &mockClientCallback);
        clientCallback.RegisterCallBack(ifname1, &mockClientCallback); // Update
        
        // Test registration with different interfaces
        clientCallback.RegisterCallBack(ifname2, &mockClientCallback);
        
        // Test null pointer registration
        clientCallback.RegisterCallBack(ifname1, nullptr);
        
        // Test unregistration
        clientCallback.UnRegisterCallBack(ifname1);
        clientCallback.UnRegisterCallBack(ifname2);
        clientCallback.UnRegisterCallBack(""); // Empty interface name
        clientCallback.UnRegisterCallBack("nonexistent"); // Non-existent interface
        
        // Test server callback registration
        // Register mock callback
        ServerCallBack mockServerCallback;
        mockServerCallback.OnServerSuccess = MockServerCallBack::OnServerSuccess;
        
        serverCallback.RegisterCallBack(ifname1, &mockServerCallback);
        serverCallback.RegisterCallBack(ifname1, &mockServerCallback); // Update
        serverCallback.RegisterCallBack(ifname2, &mockServerCallback);
        serverCallback.RegisterCallBack(ifname1, nullptr); // Null pointer
        
        serverCallback.UnRegisterCallBack(ifname1);
        serverCallback.UnRegisterCallBack("");
        serverCallback.UnRegisterCallBack("nonexistent");
        
#ifndef OHOS_ARCH_LITE
        // Test DHCP client report registration
        DhcpClientReport mockReport = {
            MockDhcpClientReport::OnDhcpClientReport
        };
        
        clientCallback.RegisterDhcpClientReportCallBack(ifname1, &mockReport);
        clientCallback.RegisterDhcpClientReportCallBack(ifname1, nullptr);
#endif
    }

    void FuzzConcurrentOperations(FuzzDataParser& parser)
    {
        std::shared_ptr<DhcpClientCallBack> clientCallback = std::make_shared<DhcpClientCallBack>();
        std::shared_ptr<DhcpServerCallBack> serverCallback = std::make_shared<DhcpServerCallBack>();
        
        std::string ifname = parser.ExtractString(IFNAME_MAX_LEN);
        
        // Create mock callbacks
        ClientCallBack mockClientCallback = {
            MockClientCallBack::OnIpSuccessChanged,
            MockClientCallBack::OnIpFailChanged
        };
        
        // Register mock callback
        ServerCallBack mockServerCallback;
        mockServerCallback.OnServerSuccess = MockServerCallBack::OnServerSuccess;
        
        // Test concurrent registration and unregistration
        std::vector<std::thread> threads;
        
        // Thread 1: Register/unregister client callbacks
        threads.emplace_back([clientCallback, ifname, &mockClientCallback]() {
            for (size_t i = LOOP_START_INDEX; i < THREAD_LOOP_COUNT; i++) {
                clientCallback->RegisterCallBack(ifname, &mockClientCallback);
                std::this_thread::sleep_for(std::chrono::microseconds(MICROSECOND_DELAY));
                clientCallback->UnRegisterCallBack(ifname);
            }
        });
        
        // Thread 2: Register/unregister server callbacks
        threads.emplace_back([serverCallback, ifname, &mockServerCallback]() {
            for (size_t i = LOOP_START_INDEX; i < THREAD_LOOP_COUNT; i++) {
                serverCallback->RegisterCallBack(ifname, &mockServerCallback);
                std::this_thread::sleep_for(std::chrono::microseconds(MICROSECOND_DELAY));
                serverCallback->UnRegisterCallBack(ifname);
            }
        });
        
        // Thread 3: Trigger callbacks
        threads.emplace_back([clientCallback, ifname, &parser]() {
            OHOS::DHCP::DhcpResult result = CreateFuzzDhcpResult(const_cast<FuzzDataParser&>(parser));
            for (size_t i = LOOP_START_INDEX; i < CALLBACK_LOOP_COUNT; i++) {
                clientCallback->OnIpSuccessChanged(i, ifname, result);
                clientCallback->OnIpFailChanged(i, ifname, "test_reason");
                std::this_thread::sleep_for(std::chrono::microseconds(MICROSECOND_DELAY));
            }
        });
        
        // Wait for all threads to complete
        for (auto& thread : threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
    }

    void FuzzEdgeCases(FuzzDataParser& parser)
    {
        DhcpClientCallBack clientCallback;
        DhcpServerCallBack serverCallback;
        
        // Test with empty strings
        OHOS::DHCP::DhcpResult result = CreateFuzzDhcpResult(parser);
        clientCallback.OnIpSuccessChanged(SUCCESS_STATUS, "", result);
        clientCallback.OnIpFailChanged(SUCCESS_STATUS, "", "");
        
        // Test with very long strings
        std::string longIfname(LONG_STRING_LEN, 'A');
        std::string longReason(VERY_LONG_STRING_LEN, 'B');
        clientCallback.OnIpFailChanged(SUCCESS_STATUS, longIfname, longReason);
        
        // Test with special characters
        std::string specialIfname = "\x00\xFF\x01\x02test\n\r\t";
        std::string specialReason = "!@#$%^&*()_+{}|:<>?test";
        clientCallback.OnIpFailChanged(SUCCESS_STATUS, specialIfname, specialReason);
        
        // Test with extreme numeric values
        clientCallback.OnIpSuccessChanged(std::numeric_limits<int32_t>::max(), "test", result);
        clientCallback.OnIpSuccessChanged(std::numeric_limits<int32_t>::min(), "test", result);
        
        // Test with very large station info list
        std::vector<DhcpStationInfo> largeStationInfos;
        for (size_t i = LOOP_START_INDEX; i < LARGE_TEST_COUNT; i++) {
            DhcpStationInfo info;
            int ret = snprintf_s(info.ipAddr, sizeof(info.ipAddr), sizeof(info.ipAddr) - 1,
                "192.168.1.%d", i % IP_RANGE_MAX);
            if (ret < 0) {
                continue; // Skip if snprintf fails
            }
            ret = snprintf_s(info.macAddr, sizeof(info.macAddr), sizeof(info.macAddr) - 1,
                "00:11:22:33:44:%02X", i % MAC_RANGE_MAX);
            if (ret < 0) {
                continue; // Skip if snprintf fails
            }
            ret = snprintf_s(info.deviceName, sizeof(info.deviceName), sizeof(info.deviceName) - 1, "Device%d", i);
            if (ret < 0) {
                continue; // Skip if snprintf fails
            }
            largeStationInfos.push_back(info);
        }
        serverCallback.OnServerSuccess("test", largeStationInfos);
        
        // Test ResultInfoCopy with malformed data
        OHOS::DHCP::DhcpResult malformedResult;
        malformedResult.strYourCli = std::string(VERY_LONG_STRING_LEN, 'X'); // Very long string
        malformedResult.vectorDnsAddr.resize(LARGE_VECTOR_SIZE); // Very large vector
        for (auto& dns : malformedResult.vectorDnsAddr) {
            dns = std::string(MALFORMED_STRING_LEN, 'Y');
        }
        
        DhcpResult cResult;
        clientCallback.ResultInfoCopy(cResult, malformedResult);
    }
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Check minimum input size
    if (data == nullptr || size < MIN_FUZZ_SIZE || size > MAX_FUZZ_SIZE) {
        return FUNCTION_SUCCESS;
    }

    FuzzDataParser parser(data, size);
    
    // Extract operation type
    uint8_t operation = parser.Extract<uint8_t>() % OPERATION_TYPE_COUNT;
    
    switch (operation) {
        case OP_CLIENT_SUCCESS:
            FuzzClientCallBackOnIpSuccess(parser);
            break;
        case OP_CLIENT_FAIL:
            FuzzClientCallBackOnIpFail(parser);
            break;
        case OP_CLIENT_REPORT_OR_SERVER:
#ifndef OHOS_ARCH_LITE
            FuzzClientCallBackOnDhcpOfferReport(parser);
#else
            FuzzServerCallBack(parser);
#endif
            break;
        case OP_SERVER_CALLBACK:
            FuzzServerCallBack(parser);
            break;
        case OP_RESULT_INFO_COPY:
            FuzzResultInfoCopy(parser);
            break;
        case OP_CALLBACK_REGISTRATION:
            FuzzCallBackRegistration(parser);
            break;
        case OP_CONCURRENT_OPERATIONS:
            FuzzConcurrentOperations(parser);
            break;
        case OP_EDGE_CASES:
            FuzzEdgeCases(parser);
            break;
        default:
            // Fallback to basic operation
            FuzzClientCallBackOnIpSuccess(parser);
            break;
    }
    // Additional comprehensive testing
    if (parser.HasData(ADDITIONAL_DATA_CHECK_SIZE)) {
        // Perform multiple operations in sequence
        FuzzResultInfoCopy(parser);
        FuzzCallBackRegistration(parser);
    }
    return FUNCTION_SUCCESS;
}
}