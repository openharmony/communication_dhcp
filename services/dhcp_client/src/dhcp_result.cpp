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

#include <string>
#include <map>
#include <list>
#include <thread>
#include <mutex>
#include "securec.h"

#include "dhcp_client_service_impl.h"
#include "dhcp_logger.h"
#include "inner_api/include/dhcp_define.h"
#include "dhcp_result.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpResult");

bool PublishDhcpIpv4ResultEvent(const int code, const char *data, const char *ifname)
{
    DHCP_LOGI("PublishDhcpIpv4ResultEvent ifname:%{public}s code:%{public}d", ifname, code);
    std::string strIfName = ifname;
    std::string strData = data;
#ifndef OHOS_ARCH_LITE
    OHOS::sptr<OHOS::DHCP::DhcpClientServiceImpl> clientImpl = OHOS::DHCP::DhcpClientServiceImpl::GetInstance();
#else
    std::shared_ptr<OHOS::DHCP::DhcpClientServiceImpl> clientImpl = OHOS::DHCP::DhcpClientServiceImpl::GetInstance();
#endif
    if (code == PUBLISH_CODE_TIMEOUT) { // timeout
        if ((clientImpl != nullptr) && (clientImpl->DhcpIpv4ResultTimeOut(strIfName) != OHOS::DHCP::DHCP_OPT_SUCCESS)) {
            DHCP_LOGE("PublishDhcpIpv4ResultEvent DhcpIpv4ResultTimeOut failed!");
            return false;
        }
    } else {
        if (DhcpEventResultHandle(code, strData) != OHOS::DHCP::DHCP_OPT_SUCCESS) {
            DHCP_LOGE("PublishDhcpIpv4ResultEvent DhcpEventResultHandlefailed!");
            return false;
        }   
    }
    return true;
}

int DhcpEventResultHandle(const int code, const std::string &data)
{
    if (data.empty()) {
        DHCP_LOGE("DhcpEventResultHandle() error, data is empty!");
        return OHOS::DHCP::DHCP_OPT_FAILED;
    }
    DHCP_LOGI("Enter DhcpEventResultHandle() code:%{public}d, data:%{private}s", code, data.c_str());
    /* Data format - ipv4:ifname,time,cliIp,lease,servIp,subnet,dns1,dns2,router1,router2,vendor */
    std::string strData(data);
    std::string strFlag;
    std::string strResult;
    if (strData.find(OHOS::DHCP::EVENT_DATA_IPV4) != std::string::npos) {
        strFlag = strData.substr(0, (int)OHOS::DHCP::EVENT_DATA_IPV4.size());
        if (strFlag != OHOS::DHCP::EVENT_DATA_IPV4) {
            DHCP_LOGE("DhcpEventResultHandle() %{public}s ipv4flag:%{public}s error!", data.c_str(), strFlag.c_str());
            return OHOS::DHCP::DHCP_OPT_FAILED;
        }
        /* Skip separator ":" */
        strResult = strData.substr((int)OHOS::DHCP::EVENT_DATA_IPV4.size() + 1);
    } else if (strData.find(OHOS::DHCP::EVENT_DATA_IPV6) != std::string::npos) {
        strFlag = strData.substr(0, (int)OHOS::DHCP::EVENT_DATA_IPV6.size());
        if (strFlag != OHOS::DHCP::EVENT_DATA_IPV6) {
            DHCP_LOGE("DhcpEventResultHandle() %{public}s ipv6flag:%{public}s error!", data.c_str(), strFlag.c_str());
            return OHOS::DHCP::DHCP_OPT_FAILED;
        }
        strResult = strData.substr((int)OHOS::DHCP::EVENT_DATA_IPV6.size() + 1);
    } else {
        DHCP_LOGE("DhcpEventResultHandle() data:%{public}s error, no find ipflag!", data.c_str());
        return OHOS::DHCP::DHCP_OPT_FAILED;
    }
    DHCP_LOGI("DhcpEventResultHandle() flag:%{public}s, result:%{private}s", strFlag.c_str(), strResult.c_str());
    if (strFlag == OHOS::DHCP::EVENT_DATA_IPV4) {
        std::vector<std::string> vecSplits;
        if (!SplitStr(strResult, OHOS::DHCP::EVENT_DATA_DELIMITER, OHOS::DHCP::EVENT_DATA_NUM, vecSplits)) {
            DHCP_LOGE("DhcpEventResultHandle() SplitString strResult:%{public}s failed!", strResult.c_str());
            return OHOS::DHCP::DHCP_OPT_FAILED;
        }
        if (GetDhcpEventIpv4Result(code, vecSplits) != OHOS::DHCP::DHCP_OPT_SUCCESS) {
            DHCP_LOGE("DhcpEventResultHandle() GetDhcpEventIpv4Result failed!");
            return OHOS::DHCP::DHCP_OPT_FAILED;
        }
    }
    return OHOS::DHCP::DHCP_OPT_SUCCESS;
}

int GetDhcpEventIpv4Result(const int code, const std::vector<std::string> &splits)
{
    /* Check field ifname and time. */
    if (splits[OHOS::DHCP::DHCP_NUM_ZERO].empty() || splits[OHOS::DHCP::DHCP_NUM_ONE].empty()) {
        DHCP_LOGE("GetDhcpEventIpv4Result() ifname or time is empty!");
        return OHOS::DHCP::DHCP_OPT_FAILED;
    }

    /* Check field cliIp. */
    if (((code == PUBLISH_CODE_SUCCESS) && (splits[OHOS::DHCP::DHCP_NUM_TWO] == OHOS::DHCP::INVALID_STRING))
    || ((code == PUBLISH_CODE_FAILED) && (splits[OHOS::DHCP::DHCP_NUM_TWO] !=
        OHOS::DHCP::INVALID_STRING))) {
        DHCP_LOGE("GetDhcpEventIpv4Result() code:%{public}d,%{public}s error!", code,
            splits[OHOS::DHCP::DHCP_NUM_TWO].c_str());
        return OHOS::DHCP::DHCP_OPT_FAILED;
    }

    std::string ifname = splits[OHOS::DHCP::DHCP_NUM_ZERO];
#ifndef OHOS_ARCH_LITE
    OHOS::sptr<OHOS::DHCP::DhcpClientServiceImpl> clientImpl = OHOS::DHCP::DhcpClientServiceImpl::GetInstance();
#else
    std::shared_ptr<OHOS::DHCP::DhcpClientServiceImpl> clientImpl = OHOS::DHCP::DhcpClientServiceImpl::GetInstance();
#endif
    if (code == PUBLISH_CODE_FAILED) {
        return clientImpl->DhcpIpv4ResultFail(splits);  /* Get failed. */
    }
    /* Get success. */
    if (clientImpl->DhcpIpv4ResultSuccess(splits) != OHOS::DHCP::DHCP_OPT_SUCCESS) {
        DHCP_LOGE("GetDhcpEventIpv4Result() GetSuccessIpv4Result failed!");
        return OHOS::DHCP::DHCP_OPT_FAILED;
    }
    DHCP_LOGI("GetDhcpEventIpv4Result() ifname:%{public}s ok", ifname.c_str());
    return OHOS::DHCP::DHCP_OPT_SUCCESS;
}

bool SplitStr(const std::string src, const std::string delim, const int count, std::vector<std::string> &splits)
{
    if (src.empty() || delim.empty()) {
        DHCP_LOGE("SplitString() error, src or delim is empty!");
        return false;
    }
    splits.clear();
    std::string strData(src);
    int nDelim = 0;
    char *pSave = NULL;
    char *pTok = strtok_r(const_cast<char *>(strData.c_str()), delim.c_str(), &pSave);
    while (pTok != NULL) {
        splits.push_back(std::string(pTok));
        nDelim++;
        pTok = strtok_r(NULL, delim.c_str(), &pSave);
    }

    if (nDelim < count) {
        DHCP_LOGI("SplitString() %{public}s failed, nDelim:%{public}d,count:%{public}d!", src.c_str(), nDelim, count);
        return false;
    }
    DHCP_LOGI("SplitString() %{private}s success, delim:%{public}s, count:%{public}d, splits.size():%{public}d.",
        src.c_str(), delim.c_str(), count, (int)splits.size());
    return true;
}