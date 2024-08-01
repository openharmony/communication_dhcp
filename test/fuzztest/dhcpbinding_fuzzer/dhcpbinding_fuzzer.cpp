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

namespace OHOS {
namespace Wifi {
constexpr size_t DHCP_SLEEP_1 = 2;

void NextPendingIntervalTest(const uint8_t* data, size_t size)
{
    uint64_t index = 0;
    uint64_t pendingInterval = static_cast<uint64_t>(data[index++]);
    NextPendingInterval(pendingInterval);
}

void IsExpireTest(const uint8_t* data, size_t size)
{
    AddressBinding binding;
    uint64_t index = 0;
    binding.ipAddress = static_cast<uint32_t>(data[index++]);
    binding.clientId = static_cast<uint32_t>(data[index++]);
    binding.bindingTime = static_cast<uint64_t>(data[index++]);
    binding.pendingTime = static_cast<uint64_t>(data[index++]);
    binding.expireIn = static_cast<uint64_t>(data[index++]);
    binding.leaseTime = static_cast<uint64_t>(data[index++]);
    binding.pendingInterval = static_cast<uint64_t>(data[index++]);
    IsExpire(&binding);
}

void WriteAddressBindingTest(const uint8_t* data, size_t size)
{
    AddressBinding binding;
    uint64_t index = 0;
    uint32_t size_t = static_cast<uint64_t>(data[index++]);
    binding.ipAddress = static_cast<uint32_t>(data[index++]);
    binding.clientId = static_cast<uint32_t>(data[index++]);
    binding.bindingTime = static_cast<uint64_t>(data[index++]);
    binding.pendingTime = static_cast<uint64_t>(data[index++]);
    binding.expireIn = static_cast<uint64_t>(data[index++]);
    binding.leaseTime = static_cast<uint64_t>(data[index++]);
    binding.pendingInterval = static_cast<uint64_t>(data[index++]);
    char out;
    if (size > 0) {
        out = static_cast<char>(data[0]);
    }
    WriteAddressBinding(&binding, &out, size_t);
}

void ParseAddressBindingTest(const uint8_t* data, size_t size)
{
    AddressBinding binding;
    uint64_t index = 0;
    binding.ipAddress = static_cast<uint32_t>(data[index++]);
    binding.clientId = static_cast<uint32_t>(data[index++]);
    binding.bindingTime = static_cast<uint64_t>(data[index++]);
    binding.pendingTime = static_cast<uint64_t>(data[index++]);
    binding.expireIn = static_cast<uint64_t>(data[index++]);
    binding.leaseTime = static_cast<uint64_t>(data[index++]);
    binding.pendingInterval = static_cast<uint64_t>(data[index++]);
    char buf;
    if (size > 0) {
        buf = static_cast<char>(data[0]);
    }
    ParseAddressBinding(&binding, &buf);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    sleep(DHCP_SLEEP_1);
    OHOS::Wifi::NextPendingIntervalTest(data, size);
    OHOS::Wifi::IsExpireTest(data, size);
    OHOS::Wifi::WriteAddressBindingTest(data, size);
    OHOS::Wifi::ParseAddressBindingTest(data, size);
    return 0;
}
}  // namespace Wifi
}  // namespace OHOS
