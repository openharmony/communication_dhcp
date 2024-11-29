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
namespace DHCP {
constexpr size_t DHCP_SLEEP_1 = 2;
constexpr size_t U32_AT_SIZE_ZERO = 4;
constexpr int CFG_DATA_MAX_BYTES = 20;

void NextPendingIntervalTest(const uint8_t* data, size_t size)
{
    uint64_t pendingInterval = static_cast<uint64_t>(data[0]);
    NextPendingInterval(pendingInterval);
}

void IsExpireTest(const uint8_t* data, size_t size)
{
    AddressBinding binding;
    binding.ipAddress = static_cast<uint32_t>(data[0]);
    binding.clientId = static_cast<uint32_t>(data[0]);
    binding.bindingTime = static_cast<uint64_t>(data[0]);
    binding.pendingTime = static_cast<uint64_t>(data[0]);
    binding.expireIn = static_cast<uint64_t>(data[0]);
    binding.leaseTime = static_cast<uint64_t>(data[0]);
    binding.pendingInterval = static_cast<uint64_t>(data[0]);
    IsExpire(&binding);
}

void WriteAddressBindingTest(const uint8_t* data, size_t size)
{
    AddressBinding binding;
    uint32_t size_t = static_cast<uint64_t>(data[0]);
    binding.ipAddress = static_cast<uint32_t>(data[0]);
    binding.clientId = static_cast<uint32_t>(data[0]);
    binding.bindingTime = static_cast<uint64_t>(data[0]);
    binding.pendingTime = static_cast<uint64_t>(data[0]);
    binding.expireIn = static_cast<uint64_t>(data[0]);
    binding.leaseTime = static_cast<uint64_t>(data[0]);
    binding.pendingInterval = static_cast<uint64_t>(data[0]);
    char *out = nullptr;
    if (memcpy_s(out, CFG_DATA_MAX_BYTES, data, CFG_DATA_MAX_BYTES - 1) != EOK) {
        return;
    }
    WriteAddressBinding(&binding, out, size_t);
}

void ParseAddressBindingTest(const uint8_t* data, size_t size)
{
    AddressBinding binding;
    binding.ipAddress = static_cast<uint32_t>(data[0]);
    binding.clientId = static_cast<uint32_t>(data[0]);
    binding.bindingTime = static_cast<uint64_t>(data[0]);
    binding.pendingTime = static_cast<uint64_t>(data[0]);
    binding.expireIn = static_cast<uint64_t>(data[0]);
    binding.leaseTime = static_cast<uint64_t>(data[0]);
    binding.pendingInterval = static_cast<uint64_t>(data[0]);
    const char *buf = "Text";
    ParseAddressBinding(&binding, buf);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::DHCP::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    sleep(DHCP_SLEEP_1);
    OHOS::DHCP::NextPendingIntervalTest(data, size);
    OHOS::DHCP::IsExpireTest(data, size);
    OHOS::DHCP::WriteAddressBindingTest(data, size);
    OHOS::DHCP::ParseAddressBindingTest(data, size);
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS
