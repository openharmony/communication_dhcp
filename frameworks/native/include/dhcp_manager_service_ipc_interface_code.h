/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#ifndef OHOS_DHCP_MANAGER_SERVICE_IPC_INTERFACE_CODE_H
#define OHOS_DHCP_MANAGER_SERVICE_IPC_INTERFACE_CODE_H

namespace OHOS {
namespace DHCP {
enum class  DhcpClientInterfaceCode {
    DHCP_CLIENT_SVR_CMD_REG_CALL_BACK = 0x4000,
    DHCP_CLIENT_SVR_CMD_START_DHCP_CLIENT = 0x4001,
    DHCP_CLIENT_SVR_CMD_STOP_DHCP_CLIENT = 0x4002,
    DHCP_CLIENT_SVR_CMD_DEAL_DHCP_CACHE = 0x4003,
    DHCP_CLIENT_SVR_CMD_STOP_SA = 0x4004,

    /* CLIENT CALL BACK code */
    DHCP_CLIENT_CBK_CMD_IP_SUCCESS_CHANGE = 0x6000,
    DHCP_CLIENT_CBK_CMD_IP_FAIL_CHANGE = 0x6001,
    DHCP_CLIENT_CBK_CMD_DHCP_OFFER = 0x6002,
};

enum class  DhcpServerInterfaceCode {
    DHCP_SERVER_SVR_CMD_REG_CALL_BACK = 0x5000,
    DHCP_SERVER_SVR_CMD_START_DHCP_SERVER = 0x5001,
    DHCP_SERVER_SVR_CMD_STOP_DHCP_SERVER = 0x5002,
    DHCP_SERVER_SVR_CMD_GET_SERVER_STATUS = 0x5003,
    DHCP_SERVER_SVR_CMD_SET_DHCP_RANGE = 0x5004,
    DHCP_SERVER_SVR_CMD_SET_DHCP_NAME = 0x5005,
    DHCP_SERVER_SVR_CMD_PUT_DHCP_RANGE = 0x5006,
    DHCP_SERVER_SVR_CMD_REMOVE_ALL_DHCP_RANGE = 0x5007,
    DHCP_SERVER_SVR_CMD_REMOVE_DHCP_RANGE = 0x5008,
    DHCP_SERVER_SVR_CMD_UPDATE_RENEW_TIME = 0x5009,
    DHCP_SERVER_SVR_CMD_GET_IP_LIST = 0x500A,
    DHCP_SERVER_SVR_CMD_GET_DHCP_CLIENT_INFO = 0x500B,
    DHCP_SERVER_SVR_CMD_STOP_SA = 0x500C,

    /* SEREVR CALL BACK code */
    DHCP_SERVER_CBK_SERVER_STATUS_CHANGE = 0x7000,
    DHCP_SERVER_CBK_SERVER_LEASES_CHANGE = 0x7001,
    DHCP_SERVER_CBK_SER_EXIT_CHANGE = 0x7002,
    DHCP_SERVER_CBK_SERVER_SUCCESS = 0x7003,
};
}  // namespace DHCP
}  // namespace OHOS
#endif