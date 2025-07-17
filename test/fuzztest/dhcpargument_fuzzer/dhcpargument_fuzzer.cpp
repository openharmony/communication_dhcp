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

#include "dhcpargument_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "securec.h"
#include "dhcp_argument.h"

namespace OHOS {
namespace DHCP {
constexpr size_t DHCP_SLEEP_1 = 2;
constexpr size_t U32_AT_SIZE_ZERO = 4;

void HasArgumentTest(const uint8_t* data, size_t size)
{
    const char *argument = "TEXT";
    HasArgument(argument);
}

void GetArgumentTest(const uint8_t* data, size_t size)
{
    const char *name = "TEXT";
    GetArgument(name);
}

void PutArgumentTest(const uint8_t* data, size_t size)
{
    const char *argument = "TEXT";
    const char *val = "TEXT";
    PutArgument(argument, val);
}

void ParseArgumentsTest(const uint8_t* data, size_t size)
{
    std::string ifName = std::string(reinterpret_cast<const char*>(data), size);
    std::string netMask = std::string(reinterpret_cast<const char*>(data), size);
    std::string ipRange = std::string(reinterpret_cast<const char*>(data), size);
    std::string localIp = std::string(reinterpret_cast<const char*>(data), size);
    ParseArguments(ifName, netMask, ipRange, localIp);
}

void FreeArgumentsTest(const uint8_t* data, size_t size)
{
    FreeArguments();
}

void InitArgumentsTest(const uint8_t* data, size_t size)
{
    InitArguments();
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::DHCP::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    sleep(DHCP_SLEEP_1);
    OHOS::DHCP::HasArgumentTest(data, size);
    OHOS::DHCP::GetArgumentTest(data, size);
    OHOS::DHCP::PutArgumentTest(data, size);
    OHOS::DHCP::ParseArgumentsTest(data, size);
    OHOS::DHCP::FreeArgumentsTest(data, size);
    OHOS::DHCP::InitArgumentsTest(data, size);
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS
