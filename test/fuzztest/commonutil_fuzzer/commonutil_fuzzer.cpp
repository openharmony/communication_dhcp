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

#include "commonutil_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "securec.h"
#include "common_util.h"

namespace OHOS {
namespace Wifi {
constexpr size_t DHCP_SLEEP_1 = 2;

void CommonUtilFuzzTest(const uint8_t* data, size_t size)
{
    uint32_t index = 0;
    char buf[] = {"aabbcc"};
    size_t bufSize = static_cast<uint32_t>(data[index++]);
    Tmspsec();
    Tmspusec();
    LeftTrim(buf);
    RightTrim(buf);
    TrimString(buf);
    RemoveSpaceCharacters(buf, bufSize);
}

void GetFilePathTest(const uint8_t* data, size_t size)
{
    char fileName;
    if (size > 0) {
        fileName = static_cast<char>(data[0]);
    }
    (void)GetFilePath(&fileName);
}

void GetLeaseFileTest(const uint8_t* data, size_t size)
{
    char fileName;
    char ifname;
    if (size > 0) {
        fileName = static_cast<char>(data[0]);
        ifname = static_cast<char>(data[0]);
    }
    (void)GetLeaseFile(&fileName, &ifname);
}

void CreatePathTest(const uint8_t* data, size_t size)
{
    char fileName;
    if (size > 0) {
        fileName = static_cast<char>(data[0]);
    }
    (void)CreatePath(&fileName);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    sleep(DHCP_SLEEP_1);
    OHOS::Wifi::CommonUtilFuzzTest(data, size);
    OHOS::Wifi::GetFilePathTest(data, size);
    OHOS::Wifi::GetLeaseFileTest(data, size);
    OHOS::Wifi::CreatePathTest(data, size);
    return 0;
}
}  // namespace Wifi
}  // namespace OHOS
