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

#ifndef OHOS_DHCP_COMMON_UTILS_H
#define OHOS_DHCP_COMMON_UTILS_H

#include <string>

namespace OHOS {
namespace DHCP {
/**
 * @Description IP address anonymization
 *
 * <p> eg: 11.11.11.1 -> 11.11.11.*
 *
 * @param str - Input MAC address
 * @return std::string - Processed MAC
 */
constexpr int DECIMAL_NOTATION = 10;
std::string Ipv4Anonymize(const std::string str);
char *UintIp4ToStr(uint32_t uIp, bool bHost);
std::string IntIpv4ToAnonymizeStr(uint32_t ip);
std::string MacArray2Str(uint8_t *macArray, int32_t len);
int CheckDataLegal(std::string &data, int base = DECIMAL_NOTATION);
unsigned int CheckDataToUint(std::string &data, int base = DECIMAL_NOTATION);
long long CheckDataTolonglong(std::string &data, int base = DECIMAL_NOTATION);
int64_t GetElapsedSecondsSinceBoot();

/**
 * @Description IP address transfer to string
 *
 * @param str - Input Ip address
 * @param bHost - whether is bHost or not
 * @return std::string - Ip address
 */
std::string Ip4IntConvertToStr(uint32_t uIp, bool bHost);

/**
 * @Description add ip and mac into arp table
 *
 * @param iface - Input iface name
 * @param ipAddr - ip Addr
 * @param macAddr - mac address
 * @return int32_t - 0: sucess; 1: fail
 */
int32_t AddArpEntry(const std::string& iface, const std::string& ipAddr, const std::string& macAddr);

std::string Ipv6Anonymize(const std::string &str);
}
}
#endif
