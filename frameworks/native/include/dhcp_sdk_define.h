/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
#ifndef OHOS_DHCP_DEF_H
#define OHOS_DHCP_DEF_H

/* Feature service ability id */
#define DHCP_CLIENT_ABILITY_ID  1126
#define DHCP_SERVER_ABILITY_ID  1127

#define INTERFACEDESCRIPTORL1  u"ohos.wifi.IDhcpClientService"
#define DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH (sizeof(INTERFACEDESCRIPTORL1)/sizeof(uint16_t))
#define DECLARE_INTERFACE_DESCRIPTOR_L1 ((uint16_t*)&INTERFACEDESCRIPTORL1[0])

#endif
