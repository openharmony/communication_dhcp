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
namespace Wifi {
constexpr size_t DHCP_SLEEP_1 = 2;

void HasArgumentTest(const uint8_t* data, size_t size)
{
    char argument;
    if (size > 0) {
        argument = static_cast<char>(data[0]);
    }
    HasArgument(&argument);
}

void GetArgumentTest(const uint8_t* data, size_t size)
{
    char name;
    if (size > 0) {
        name = static_cast<char>(data[0]);
    }
    GetArgument(&name);
}

void PutArgumentTest(const uint8_t* data, size_t size)
{
    char argument;
    char val;
    if (size > 0) {
        argument = static_cast<char>(data[0]);
        val = static_cast<char>(data[0]);
    }
    PutArgument(&argument, &val);
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

void ShowHelpTest(const uint8_t* data, size_t size)
{
    int index = 0;
    int argc = static_cast<int>(data[index++]);
    ShowHelp(argc);
}

void PrintRequiredArgumentsTest(const uint8_t* data, size_t size)
{
    PrintRequiredArguments();
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    sleep(DHCP_SLEEP_1);
    OHOS::Wifi::HasArgumentTest(data, size);
    OHOS::Wifi::GetArgumentTest(data, size);
    OHOS::Wifi::PutArgumentTest(data, size);
    OHOS::Wifi::ParseArgumentsTest(data, size);
    OHOS::Wifi::FreeArgumentsTest(data, size);
    OHOS::Wifi::ShowHelpTest(data, size);
    OHOS::Wifi::PrintRequiredArgumentsTest(data, size);
    return 0;
}
}  // namespace Wifi
}  // namespace OHOS
