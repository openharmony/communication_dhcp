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

#include "dhcpbinding_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "securec.h"
#include "dhcp_binding.h"
#include <fuzzer/FuzzedDataProvider.h>


namespace OHOS {
namespace DHCP {
constexpr size_t DHCP_SLEEP_1 = 2;
constexpr size_t U32_AT_SIZE_ZERO = 4;
constexpr int CFG_DATA_MAX_BYTES = 512;

void NextPendingIntervalTest(FuzzedDataProvider& FDP)
{
    uint64_t pendingInterval = FDP.ConsumeIntegral<uint64_t>();
    NextPendingInterval(pendingInterval);
}

void IsExpireTest(FuzzedDataProvider& FDP)
{
    AddressBinding binding;
    binding.ipAddress =  FDP.ConsumeIntegral<uint32_t>();
    binding.clientId = FDP.ConsumeIntegral<uint32_t>();
    binding.bindingTime = FDP.ConsumeIntegral<uint64_t>();
    binding.pendingTime = FDP.ConsumeIntegral<uint64_t>();
    binding.expireIn = FDP.ConsumeIntegral<uint64_t>();
    binding.leaseTime = FDP.ConsumeIntegral<uint64_t>();
    binding.pendingInterval = FDP.ConsumeIntegral<uint64_t>();
    IsExpire(&binding);
}

void ParseAddressBindingTest(FuzzedDataProvider& FDP)
{
    AddressBinding binding;
    binding.ipAddress =  FDP.ConsumeIntegral<uint32_t>();
    binding.clientId = FDP.ConsumeIntegral<uint32_t>();
    binding.bindingTime = FDP.ConsumeIntegral<uint64_t>();
    binding.pendingTime = FDP.ConsumeIntegral<uint64_t>();
    binding.expireIn = FDP.ConsumeIntegral<uint64_t>();
    binding.leaseTime = FDP.ConsumeIntegral<uint64_t>();
    binding.pendingInterval = FDP.ConsumeIntegral<uint64_t>();
    const char *buf = "Text";
    ParseAddressBinding(&binding, buf);
}

void WriteAddressBindingFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    int index = 0;
    AddressBinding binding;
    int ret = memset_s(&binding, sizeof(binding), 0, sizeof(binding));
    if (ret != EOK) {
        return;
    }
    binding.ipAddress =  FDP.ConsumeIntegral<uint32_t>();
    binding.clientId = FDP.ConsumeIntegral<uint32_t>();
    binding.bindingTime = FDP.ConsumeIntegral<uint64_t>();
    binding.pendingTime = FDP.ConsumeIntegral<uint64_t>();
    binding.expireIn = FDP.ConsumeIntegral<uint64_t>();
    binding.leaseTime = FDP.ConsumeIntegral<uint64_t>();
    binding.pendingInterval = FDP.ConsumeIntegral<uint64_t>();
    char out[CFG_DATA_MAX_BYTES] = {0};
    if (index < static_cast<int>(size)) {
        uint32_t bindingSize = FDP.ConsumeIntegral<uint32_t>();
        if (bindingSize > CFG_DATA_MAX_BYTES) {
            bindingSize = CFG_DATA_MAX_BYTES;
        }
        if (bindingSize < 1) {
            bindingSize = CFG_DATA_MAX_BYTES;
        }
        WriteAddressBinding(&binding, out, bindingSize);
    }
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::DHCP::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    FuzzedDataProvider FDP(data, size);
    sleep(DHCP_SLEEP_1);
    OHOS::DHCP::NextPendingIntervalTest(FDP);
    OHOS::DHCP::IsExpireTest(FDP);
    OHOS::DHCP::ParseAddressBindingTest(FDP);
    OHOS::DHCP::WriteAddressBindingFuzzTest(data, size);
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS
