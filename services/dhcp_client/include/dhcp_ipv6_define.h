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

#ifndef OHOS_DHCP_IPV6_DEFINE_H
#define OHOS_DHCP_IPV6_DEFINE_H
namespace OHOS {
namespace DHCP {
inline const int IPV6_ADDR_ANY = 0x0000U;
inline const int IPV6_ADDR_UNICAST = 0x0001U;
inline const int IPV6_ADDR_MULTICAST = 0x0002U;
inline const int IPV6_ADDR_SCOPE_MASK = 0x00F0U;
inline const int IPV6_ADDR_LOOPBACK = 0x0010U;
inline const int IPV6_ADDR_LINKLOCAL = 0x0020U;
inline const int IPV6_ADDR_SITELOCAL = 0x0040U;
inline const int IPV6_ADDR_COMPATV4 = 0x0080U;
inline const int IPV6_ADDR_MAPPED = 0x1000U;
inline const unsigned int IPV6_ADDR_SCOPE_NODELOCAL = 0X01;
inline const unsigned int  IPV6_ADDR_SCOPE_LINKLOCAL = 0X02;
inline const unsigned int  IPV6_ADDR_SCOPE_SITELOCAL = 0X05;
inline const int  IPV6_ADDR_SCOPE_GLOBAL = 0X0E;
inline const int S6_ADDR_INDEX_ZERO = 0;
inline const int S6_ADDR_INDEX_FIRST = 1;
inline const int S6_ADDR_INDEX_SECOND = 2;
inline const int S6_ADDR_INDEX_THIRD = 3;
inline const int ADDRTYPE_FLAG_ZERO = 0x00000000;
inline const int ADDRTYPE_FLAG_ONE = 0x00000001;
inline const int ADDRTYPE_FLAG_LOWF = 0x0000ffff;
inline const int ADDRTYPE_FLAG_HIGHE = 0xE0000000;
inline const int ADDRTYPE_FLAG_HIGHFF = 0xFF000000;
inline const int ADDRTYPE_FLAG_HIGHFFC = 0xFFC00000;
inline const int ADDRTYPE_FLAG_HIGHFE8 = 0xFE800000;
inline const int ADDRTYPE_FLAG_HIGHFEC = 0xFEC00000;
inline const int ADDRTYPE_FLAG_HIGHFE = 0xFE000000;
inline const int ADDRTYPE_FLAG_HIGHFC = 0xFC000000;
inline const int MASK_FILTER = 0x7;
inline const int KERNEL_BUFF_SIZE = (64 * 1024);
inline const int ND_OPT_MIN_LEN = 3;
inline const int ROUTE_BUFF_SIZE = 1024;
inline const int POSITION_OFFSET_1 = 1;
inline const int POSITION_OFFSET_2 = 2;
inline const int POSITION_OFFSET_3 = 3;
inline const int POSITION_OFFSET_4 = 4;
#define IPV6_ADDR_SCOPE_TYPE(scope) ((scope) << 16)
#define IPV6_ADDR_MC_SCOPE(a) ((a)->s6_addr[1] & 0x0f)
}  // namespace DHCP
}  // namespace OHOS
#endif /* OHOS_DHCP_IPV6_DEFINE_H */
