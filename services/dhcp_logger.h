/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_DHCP_LOGGER_H
#define OHOS_DHCP_LOGGER_H

#ifdef OHOS_ARCH_LITE
#include "hilog/log.h"
#else
#include "hilog/log_c.h"
#include "hilog/log_cpp.h"
#endif

namespace OHOS {
namespace DHCP {
const unsigned int LOG_ID_DHCP = 0xD001560;
const unsigned int LOG_ID_DHCP_DHCP = LOG_ID_DHCP | 0x05;

#define DEFINE_DHCPLOG_DHCP_LABEL(name) \
    static constexpr OHOS::HiviewDFX::HiLogLabel DHCP_LOG_LABEL = {LOG_CORE, OHOS::DHCP::LOG_ID_DHCP_DHCP, name}

#define DHCP_LOGF(...) (void)OHOS::HiviewDFX::HiLog::Fatal(DHCP_LOG_LABEL, ##__VA_ARGS__)
#define DHCP_LOGE(...) (void)OHOS::HiviewDFX::HiLog::Error(DHCP_LOG_LABEL, ##__VA_ARGS__)
#define DHCP_LOGW(...) (void)OHOS::HiviewDFX::HiLog::Warn(DHCP_LOG_LABEL, ##__VA_ARGS__)
#define DHCP_LOGI(...) (void)OHOS::HiviewDFX::HiLog::Info(DHCP_LOG_LABEL, ##__VA_ARGS__)
#define DHCP_LOGD(...) (void)OHOS::HiviewDFX::HiLog::Debug(DHCP_LOG_LABEL, ##__VA_ARGS__)

#ifndef CHECK_NULL_AND_RETURN
#define CHECK_NULL_AND_RETURN(ptr, retValue) \
if (!(ptr)) { \
    DHCP_LOGI("Pointer %{public}s in %{public}s is NULL!", #ptr, __func__); \
    return retValue; \
}
#endif
}  // namespace DHCP
}  // namespace OHOS
#endif