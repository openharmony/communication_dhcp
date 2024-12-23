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
#include "dhcp_function.h"

#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <vector>
#include <sys/wait.h>

#include "securec.h"
#include "dhcp_logger.h"

namespace OHOS {
namespace DHCP {
DEFINE_DHCPLOG_DHCP_LABEL("DhcpFunction");

const int MAX_RETEY_WAIT_COUNT = 60;
const int WAIT_SLEEP_50MS = 50;

bool DhcpFunction::Ip4StrConToInt(const std::string& strIp, uint32_t& uIp, bool bHost)
{
    if (strIp.empty()) {
        DHCP_LOGE("Ip4StrConToInt error, strIp is empty()!");
        return false;
    }

    struct in_addr addr4;
    int nRet = inet_pton(AF_INET, strIp.c_str(), &addr4);
    if (nRet != 1) {
        DHCP_LOGE("Ip4StrConToInt strIp:%{private}s failed, nRet:%{public}d!", strIp.c_str(), nRet);
        if (nRet == 0) {
            DHCP_LOGE("Ip4StrConToInt strIp:%{private}s not in presentation format!", strIp.c_str());
        } else {
            DHCP_LOGE("Ip4StrConToInt strIp:%{private}s inet_pton not contain a valid address!", strIp.c_str());
        }
        return false;
    }

    if (bHost) {
        uIp = ntohl(addr4.s_addr);
    } else {
        uIp = addr4.s_addr;
    }

    return true;
}

bool DhcpFunction::Ip6StrConToChar(const std::string& strIp, uint8_t chIp[], size_t uSize)
{
    if (strIp.empty()) {
        DHCP_LOGE("Ip6StrConToChar param error, strIp is empty()!");
        return false;
    }

    struct in6_addr addr6;
    if (memset_s(&addr6, sizeof(addr6), 0, sizeof(addr6)) != EOK) {
        return false;
    }
    int nRet = inet_pton(AF_INET6, strIp.c_str(), &addr6);
    if (nRet != 1) {
        DHCP_LOGE("Ip6StrConToChar inet_pton strIp:%{private}s failed, nRet:%{public}d!", strIp.c_str(), nRet);
        if (nRet == 0) {
            DHCP_LOGE("Ip6StrConToChar strIp:%{private}s not in presentation format!", strIp.c_str());
        } else {
            DHCP_LOGE("Ip6StrConToChar strIp:%{private}s inet_pton not contain a valid address!", strIp.c_str());
        }
        return false;
    }

    for (size_t i = 0; i < uSize; i++) {
        chIp[i] = addr6.s6_addr[i];
    }

    return true;
}

std::string DhcpFunction::Ip6CharConToStr(uint8_t chIp[], int size)
{
    if (size <= 0) {
        DHCP_LOGE("Ip6CharConToStr param error, size:%{public}d!", size);
        return "";
    }

    std::string strIp = "";
    char bufIp6[INET6_ADDRSTRLEN] = {0};
    struct in6_addr addr6;
    if (memcpy_s(addr6.s6_addr, sizeof(addr6.s6_addr), &chIp, size) != EOK) {
        return "";
    }
    if (inet_ntop(AF_INET6, &addr6, bufIp6, INET6_ADDRSTRLEN) == nullptr) {
        DHCP_LOGE("Ip6CharConToStr chIp failed, inet_ntop nullptr!");
    } else {
        strIp = bufIp6;
        DHCP_LOGI("Ip6CharConToStr chIp -> strIp:%{private}s.", strIp.c_str());
    }

    return strIp;
}

bool DhcpFunction::CheckIpStr(const std::string& strIp)
{
    if (strIp.empty()) {
        DHCP_LOGE("CheckIpStr param error, strIp is empty()!");
        return false;
    }

    bool bIp4 = false;
    bool bIp6 = false;
    std::string::size_type idx = strIp.find(IP4_SEPARATOR);
    if (idx != std::string::npos) {
        bIp4 = true;
    }
    idx = strIp.find(IP6_SEPARATOR);
    if (idx != std::string::npos) {
        bIp6 = true;
    }
    if ((!bIp4 && !bIp6) || (bIp4 && bIp6)) {
        DHCP_LOGE("CheckIpStr strIp:%{private}s error, bIp4:%{public}d,bIp6:%{public}d!", strIp.c_str(), bIp4, bIp6);
        return false;
    }

    if (bIp4) {
        uint32_t uIp = 0;
        if (!Ip4StrConToInt(strIp, uIp)) {
            DHCP_LOGE("CheckIpStr Ip4StrConToInt failed, strIp:%{private}s.", strIp.c_str());
            return false;
        }
    } else {
        uint8_t	addr6[sizeof(struct in6_addr)] = {0};
        if (!Ip6StrConToChar(strIp, addr6, sizeof(struct in6_addr))) {
            DHCP_LOGE("CheckIpStr Ip6StrConToChar failed, strIp:%{private}s.", strIp.c_str());
            return false;
        }
    }

    return true;
}

int DhcpFunction::GetLocalIp(const std::string strInf, std::string& strIp, std::string& strMask)
{
    if (strInf.empty()) {
        DHCP_LOGE("GetLocalIp param error, strInf is empty!");
        return DHCP_OPT_ERROR;
    }

    int fd;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        DHCP_LOGE("GetLocalIp strInf:%{public}s failed, socket err:%{public}d!", strInf.c_str(), errno);
        return DHCP_OPT_FAILED;
    }

    struct ifreq iface;
    if (memset_s(&iface, sizeof(iface), 0, sizeof(iface)) != EOK) {
        close(fd);
        return DHCP_OPT_FAILED;
    }
    if (strncpy_s(iface.ifr_name, IFNAMSIZ, strInf.c_str(), IFNAMSIZ - 1) != EOK) {
        close(fd);
        return DHCP_OPT_FAILED;
    }
    iface.ifr_name[IFNAMSIZ - 1] = 0;

    /* inet addr */
    if (ioctl(fd, SIOCGIFADDR, &iface) < 0) {
        DHCP_LOGE("GetLocalIp() %{public}s failed, SIOCGIFADDR err:%{public}d!", strInf.c_str(), errno);
        close(fd);
        return DHCP_OPT_FAILED;
    }
    struct sockaddr_in *pSockIn = (struct sockaddr_in *)&iface.ifr_addr;
    char bufIp4[INET_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET, &(pSockIn->sin_addr), bufIp4, INET_ADDRSTRLEN) != nullptr) {
        strIp = bufIp4;
    }

    /* netmask addr */
    if (ioctl(fd, SIOCGIFNETMASK, &iface) < 0) {
        DHCP_LOGE("GetLocalIp() %{public}s failed, SIOCGIFNETMASK err:%{public}d!", strInf.c_str(), errno);
        close(fd);
        return DHCP_OPT_FAILED;
    }
    pSockIn = (struct sockaddr_in *)&iface.ifr_addr;
    char bufMask[INET_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET, &(pSockIn->sin_addr), bufMask, INET_ADDRSTRLEN) != nullptr) {
        strMask = bufMask;
    }

    close(fd);
    return DHCP_OPT_SUCCESS;
}

int DhcpFunction::GetLocalMac(const std::string ethInf, std::string& ethMac)
{
    struct ifreq ifr;
    int sd = 0;

    bzero(&ifr, sizeof(struct ifreq));
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        DHCP_LOGE("GetLocalMac socket ethInf:%{public}s,error:%{public}d!", ethInf.c_str(), errno);
        return -1;
    }

    if (strncpy_s(ifr.ifr_name, IFNAMSIZ, ethInf.c_str(), IFNAMSIZ - 1) != EOK) {
        close(sd);
        return -1;
    }

    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) {
        DHCP_LOGE("GetLocalMac ioctl ethInf:%{public}s,error:%{public}d!", ethInf.c_str(), errno);
        close(sd);
        return -1;
    }

    char mac[ETH_MAC_ADDR_LEN * ETH_MAC_ADDR_CHAR_NUM] = { 0 };
    int nRes = snprintf_s(mac,
        ETH_MAC_ADDR_LEN * ETH_MAC_ADDR_CHAR_NUM,
        ETH_MAC_ADDR_LEN * ETH_MAC_ADDR_CHAR_NUM - 1,
        "%02x:%02x:%02x:%02x:%02x:%02x",
        (unsigned char)ifr.ifr_hwaddr.sa_data[ETH_MAC_ADDR_INDEX_0],
        (unsigned char)ifr.ifr_hwaddr.sa_data[ETH_MAC_ADDR_INDEX_1],
        (unsigned char)ifr.ifr_hwaddr.sa_data[ETH_MAC_ADDR_INDEX_2],
        (unsigned char)ifr.ifr_hwaddr.sa_data[ETH_MAC_ADDR_INDEX_3],
        (unsigned char)ifr.ifr_hwaddr.sa_data[ETH_MAC_ADDR_INDEX_4],
        (unsigned char)ifr.ifr_hwaddr.sa_data[ETH_MAC_ADDR_INDEX_5]);
    if (nRes < 0) {
        DHCP_LOGE("GetLocalMac snprintf_s ethInf:%{public}s,error:%{public}d!", ethInf.c_str(), errno);
        close(sd);
        return -1;
    }
    ethMac = mac;
    close(sd);
    return 0;
}

int DhcpFunction::CheckRangeNetwork(const std::string strInf, const std::string strBegin, const std::string strEnd)
{
    if (strInf.empty() || strBegin.empty() || strEnd.empty()) {
        DHCP_LOGE("CheckRangeNetwork param error, strInf or strBegin or strEnd is empty!");
        return DHCP_OPT_ERROR;
    }

    std::string strIp, strMask;
    if (GetLocalIp(strInf, strIp, strMask) != DHCP_OPT_SUCCESS) {
        DHCP_LOGE("CheckRangeNetwork get %{public}s local ip failed", strInf.c_str());
        return DHCP_OPT_FAILED;
    }

    uint32_t uIp, uMask, uBegin, uEnd;
    if (!Ip4StrConToInt(strIp, uIp, false) || !Ip4StrConToInt(strMask, uMask, false) ||
        !Ip4StrConToInt(strBegin, uBegin, false) || !Ip4StrConToInt(strEnd, uEnd, false)) {
        DHCP_LOGE("CheckRangeNetwork %{public}s Ip4StrConToInt failed", strInf.c_str());
        return DHCP_OPT_FAILED;
    }

    if (!CheckSameNetwork(uIp, uBegin, uMask)) {
        DHCP_LOGE("Check %{public}s %{private}s %{public}s failed", strInf.c_str(), strIp.c_str(), strBegin.c_str());
        return DHCP_OPT_FAILED;
    }
    if (!CheckSameNetwork(uIp, uEnd, uMask)) {
        DHCP_LOGE("Check end %{public}s %{private}s %{public}s failed", strInf.c_str(), strIp.c_str(), strEnd.c_str());
        return DHCP_OPT_FAILED;
    }
    return DHCP_OPT_SUCCESS;
}

bool DhcpFunction::CheckSameNetwork(const uint32_t srcIp, const uint32_t dstIp, const uint32_t maskIp)
{
    uint32_t srcNet = srcIp & maskIp;
    uint32_t dstNet = dstIp & maskIp;
    return (srcNet == dstNet);
}

bool DhcpFunction::IsExistFile(const std::string& filename)
{
    bool bExist = false;
    std::fstream ioFile;
    ioFile.open(filename.c_str(), std::ios::in);
    if (ioFile) {
        ioFile.close();
        bExist = true;
    }
    DHCP_LOGE("IsExistFile %{public}s failed, err:%{public}d", filename.c_str(), errno);
    return bExist;
}

bool DhcpFunction::CreateFile(const std::string& filename, const std::string& filedata)
{
    std::ofstream outFile;
    outFile.open(filename.c_str());
    if (!outFile) {
        DHCP_LOGE("CreateFile %{public}s failed, err:%{public}s", filename.c_str(), strerror(errno));
        return false;
    }
    outFile.flush();
    outFile << filedata << std::endl;
    outFile.close();
    return true;
}

bool DhcpFunction::RemoveFile(const std::string& filename)
{
    if (std::remove(filename.c_str()) != 0) {
        DHCP_LOGE("RemoveFile filename:%{public}s failed!", filename.c_str());
        return false;
    }
    DHCP_LOGI("RemoveFile filename:%{public}s success.", filename.c_str());
    return true;
}

bool DhcpFunction::AddFileLineData(const std::string& filename, const std::string& prevdata, const std::string& linedata)
{
    bool bAdd = false;
    std::ifstream inFile;
    inFile.open(filename.c_str());
    std::string strFileData = "";
    std::string strTemp = "";
    char tmpLineData[1024] = {0};
    while (inFile.getline(tmpLineData, sizeof(tmpLineData))) {
        strTemp = tmpLineData;
        strFileData += strTemp;
        strFileData += "\n";
        if (strTemp == prevdata) {
            strFileData += linedata;
            bAdd = true;
        }
    }
    inFile.close();

    if (bAdd) {
        std::ofstream outFile;
        outFile.open(filename.c_str());
        outFile.flush();
        DHCP_LOGI("AddFileLineData Reflush filename:%{public}s, strFileData:%{public}s.",
            filename.c_str(), strFileData.c_str());
        outFile << strFileData;
        outFile.close();
    }
    return true;
}

bool DhcpFunction::DelFileLineData(const std::string& filename, const std::string& linedata)
{
    bool bDel = false;
    std::ifstream inFile;
    inFile.open(filename.c_str());
    std::string strFileData = "";
    std::string strTemp = "";
    char tmpLineData[1024] = {0};
    while (inFile.getline(tmpLineData, sizeof(tmpLineData))) {
        strTemp = tmpLineData;
        if (strTemp != linedata) {
            strFileData += strTemp;
            strFileData += "\n";
        } else {
            bDel = true;
        }
    }
    inFile.close();

    if (bDel) {
        std::ofstream outFile;
        outFile.open(filename.c_str());
        outFile.flush();
        DHCP_LOGI("DelFileLineData Reflush filename:%{public}s, strFileData:%{public}s.",
            filename.c_str(), strFileData.c_str());
        outFile << strFileData;
        outFile.close();
    }
    return true;
}

bool DhcpFunction::ModifyFileLineData(const std::string& filename, const std::string& srcdata,
    const std::string& dstdata)
{
    bool bModify = false;
    std::ifstream inFile;
    inFile.open(filename.c_str());
    std::string strFileData = "";
    std::string strTemp = "";
    char tmpLineData[1024] = {0};
    while (inFile.getline(tmpLineData, sizeof(tmpLineData))) {
        strTemp = tmpLineData;
        if (strTemp != srcdata) {
            strFileData += strTemp;
            strFileData += "\n";
        } else {
            strFileData += dstdata;
            strFileData += "\n";
            bModify = true;
        }
    }
    inFile.close();

    if (bModify) {
        std::ofstream outFile;
        outFile.open(filename.c_str());
        outFile.flush();
        DHCP_LOGI("ModifyFileLineData Reflush filename:%{public}s, strFileData:%{public}s.",
            filename.c_str(), strFileData.c_str());
        outFile << strFileData;
        outFile.close();
    }
    return true;
}

int DhcpFunction::FormatString(struct DhcpPacketResult &result)
{
    if (strncmp(result.strYiaddr, "*", 1) == 0) {
        if (memset_s(result.strYiaddr, INET_ADDRSTRLEN, 0, INET_ADDRSTRLEN) != EOK) {
            return -1;
        }
    }
    if (strncmp(result.strOptServerId, "*", 1) == 0) {
        if (memset_s(result.strOptServerId, INET_ADDRSTRLEN, 0, INET_ADDRSTRLEN) != EOK) {
            return -1;
        }
    }
    if (strncmp(result.strOptSubnet, "*", 1) == 0) {
        if (memset_s(result.strOptSubnet, INET_ADDRSTRLEN, 0, INET_ADDRSTRLEN) != EOK) {
            return -1;
        }
    }
    if (strncmp(result.strOptDns1, "*", 1) == 0) {
        if (memset_s(result.strOptDns1, INET_ADDRSTRLEN, 0, INET_ADDRSTRLEN) != EOK) {
            return -1;
        }
    }
    if (strncmp(result.strOptDns2, "*", 1) == 0) {
        if (memset_s(result.strOptDns2, INET_ADDRSTRLEN, 0, INET_ADDRSTRLEN) != EOK) {
            return -1;
        }
    }
    if (strncmp(result.strOptRouter1, "*", 1) == 0) {
        if (memset_s(result.strOptRouter1, INET_ADDRSTRLEN, 0, INET_ADDRSTRLEN) != EOK) {
            return -1;
        }
    }
    if (strncmp(result.strOptRouter2, "*", 1) == 0) {
        if (memset_s(result.strOptRouter2, INET_ADDRSTRLEN, 0, INET_ADDRSTRLEN) != EOK) {
            return -1;
        }
    }
    if (strncmp(result.strOptVendor, "*", 1) == 0) {
        if (memset_s(result.strOptVendor, DHCP_FILE_MAX_BYTES, 0, DHCP_FILE_MAX_BYTES) != EOK) {
            return -1;
        }
    }
    return 0;
}

#ifdef OHOS_ARCH_LITE
int DhcpFunction::GetDhcpPacketResult(const std::string& filename, struct DhcpPacketResult &result)
{
    FILE *pFile = fopen(filename.c_str(), "r");
    if (pFile == nullptr) {
        DHCP_LOGE("GetDhcpPacketResult() fopen %{public}s fail, err:%{public}s!", filename.c_str(), strerror(errno));
        return DHCP_OPT_FAILED;
    }

    char strIpFlag[DHCP_NUM_EIGHT];
    if (memset_s(strIpFlag, sizeof(strIpFlag), 0, sizeof(strIpFlag)) != EOK) {
        fclose(pFile);
        return DHCP_OPT_FAILED;
    }
    /* Format: IpFlag AddTime cliIp servIp subnet dns1 dns2 router1 router2 vendor lease */
    int nRes = fscanf_s(pFile, "%s %u %s %s %s %s %s %s %s %s %u\n", strIpFlag, DHCP_NUM_EIGHT, &result.uAddTime,
        result.strYiaddr, INET_ADDRSTRLEN, result.strOptServerId, INET_ADDRSTRLEN, result.strOptSubnet, INET_ADDRSTRLEN,
        result.strOptDns1, INET_ADDRSTRLEN, result.strOptDns2, INET_ADDRSTRLEN, result.strOptRouter1, INET_ADDRSTRLEN,
        result.strOptRouter2, INET_ADDRSTRLEN, result.strOptVendor, DHCP_FILE_MAX_BYTES, &result.uOptLeasetime);
    if (nRes == EOF) {
        DHCP_LOGE("GetDhcpPacketResult() fscanf %{public}s err:%{public}s!", filename.c_str(), strerror(errno));
        fclose(pFile);
        return DHCP_OPT_FAILED;
    } else if (nRes == 0) {
        DHCP_LOGW("GetDhcpPacketResult() fscanf file:%{public}s nRes:0 nullptr!", filename.c_str());
        fclose(pFile);
        return DHCP_OPT_NULL;
    } else if (nRes != EVENT_DATA_NUM) {
        DHCP_LOGE("GetDhcpPacketResult() fscanf file:%{public}s nRes:%{public}d ERROR!", filename.c_str(), nRes);
        fclose(pFile);
        return DHCP_OPT_FAILED;
    }

    if (fclose(pFile) != 0) {
        DHCP_LOGE("GetDhcpPacketResult() fclose file:%{public}s failed!", filename.c_str());
        return DHCP_OPT_FAILED;
    }

    /* Format dhcp packet result */
    if (FormatString(result) != 0) {
        DHCP_LOGE("GetDhcpPacketResult() file:%{public}s failed, FormatString result error!", filename.c_str());
        return DHCP_OPT_FAILED;
    }

    return DHCP_OPT_SUCCESS;
}
#endif

int DhcpFunction::InitPidfile(const std::string& piddir, const std::string& pidfile)
{
    if (piddir.empty() || pidfile.empty()) {
        DHCP_LOGE("InitPidfile() failed, piddir or pidfile is empty!");
        return DHCP_OPT_FAILED;
    }
    DHCP_LOGI("InitPidfile() piddir:%{public}s, pidfile:%{public}s.", piddir.c_str(), pidfile.c_str());
    unlink(pidfile.c_str());

    int fd;
    if ((fd = open(pidfile.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) {
        DHCP_LOGE("InitPidfile() failed, open pidfile:%{public}s err:%{public}d!", pidfile.c_str(), errno);
        return DHCP_OPT_FAILED;
    }

    char buf[PID_MAX_LEN] = {0};
    if (snprintf_s(buf, PID_MAX_LEN, PID_MAX_LEN - 1, "%d", getpid()) < 0) {
        DHCP_LOGE("InitPidfile() %{public}s failed, snprintf_s error:%{public}d!", pidfile.c_str(), errno);
        close(fd);
        return DHCP_OPT_FAILED;
    }
    ssize_t bytes;
    if ((bytes = write(fd, buf, strlen(buf))) <= 0) {
        DHCP_LOGE("InitPidfile() failed, write pidfile:%{public}s error:%{public}d, bytes:%{public}zd!",
            pidfile.c_str(), errno, bytes);
        close(fd);
        return DHCP_OPT_FAILED;
    }
    DHCP_LOGI("InitPidfile() pid:%{public}s write %{public}s, bytes:%{public}zd!", buf, pidfile.c_str(), bytes);
    close(fd);

    if (chdir(piddir.c_str()) != 0) {
        DHCP_LOGE("InitPidfile() failed, chdir piddir:%{public}s err:%{public}d!", piddir.c_str(), errno);
        return DHCP_OPT_FAILED;
    }

    /* Set default permissions for the specified client process id files and directories. */
    umask(DEFAULT_UMASK);

    /* Change attribs to the specified client process id files: 644 (user=rw, group=r, other=r). */
    chmod(pidfile.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    return DHCP_OPT_SUCCESS;
}

pid_t DhcpFunction::GetPID(const std::string& pidfile)
{
    /* Check pidfile is or not exists. */
    struct stat sb;
    if (stat(pidfile.c_str(), &sb) != 0) {
        DHCP_LOGW("GetPID() pidfile:%{public}s stat:%{public}d!", pidfile.c_str(), errno);
        return -1;
    }
    DHCP_LOGI("GetPID() pidfile:%{public}s stat st_size:%{public}d.", pidfile.c_str(), (int)sb.st_size);

    int fd;
    if ((fd = open(pidfile.c_str(), O_RDONLY)) < 0) {
        DHCP_LOGE("GetPID() failed, open pidfile:%{public}s error!", pidfile.c_str());
        return -1;
    }

    lseek(fd, 0, SEEK_SET);

    char buf[PID_MAX_LEN] = {0};
    ssize_t bytes;
    if ((bytes = read(fd, buf, sb.st_size)) < 0) {
        DHCP_LOGE("GetPID() failed, read pidfile:%{public}s error, bytes:%{public}zd!", pidfile.c_str(), bytes);
        close(fd);
        return -1;
    }
    DHCP_LOGI("GetPID() read pidfile:%{public}s, buf:%{public}s, bytes:%{public}zd.", pidfile.c_str(), buf, bytes);
    close(fd);

    return atoi(buf);
}

int DhcpFunction::CheckProRunning(const pid_t proPid, const std::string& proName)
{
    if ((proPid == 0) || proName.empty()) {
        DHCP_LOGE("CheckProRunning %{public}s param error!", proName.c_str());
        return -1;
    }
    char buf[DIR_MAX_LEN] = {0};
    if (snprintf_s(buf, DIR_MAX_LEN, DIR_MAX_LEN - 1, "/proc/%ld", (long int)proPid) < 0) {
        DHCP_LOGE("CheckProRunning %{public}s failed, snprintf_s errno:%{public}d!", proName.c_str(), errno);
        return -1;
    }
    if (access(buf, F_OK) != 0) {
        DHCP_LOGI("CheckProRunning %{public}s is not exist, %{public}s no running", buf, proName.c_str());
        return 0;
    }
    if (strcat_s(buf, sizeof(buf), "/exe") != EOK) {
        DHCP_LOGE("CheckProRunning %{public}s failed, strcat_s errno:%{public}d!", proName.c_str(), errno);
        return -1;
    }
    char proBuf[DIR_MAX_LEN] = {0};
    if (readlink(buf, proBuf, sizeof(proBuf)) < 0) {
        DHCP_LOGE("CheckProRunning %{public}s failed, readlink errno:%{public}d!", proName.c_str(), errno);
        return -1;
    }
    if (strstr(proBuf, proName.c_str()) == nullptr) {
        DHCP_LOGI("CheckProRunning %{public}s exe -> %{public}s, %{public}s no running", buf, proBuf, proName.c_str());
        return 0;
    }
    DHCP_LOGI("CheckProRunning %{public}s exe -> %{public}s, %{public}s is running", buf, proBuf, proName.c_str());
    return 1;
}

int DhcpFunction::CreateDirs(const std::string dirs, int mode)
{
    if (dirs.empty() || (dirs.size() >= DIR_MAX_LEN)) {
        DHCP_LOGE("CreateDirs() dirs:%{public}s error!", dirs.c_str());
        return DHCP_OPT_FAILED;
    }

    int nSrcLen = (int)dirs.size();
    char strDir[DIR_MAX_LEN] = {0};
    if (strncpy_s(strDir, sizeof(strDir), dirs.c_str(), dirs.size()) != EOK) {
        DHCP_LOGE("CreateDirs() strncpy_s dirs:%{public}s failed!", dirs.c_str());
        return DHCP_OPT_FAILED;
    }
    if (strDir[nSrcLen - 1] != '/') {
        if (nSrcLen == (DIR_MAX_LEN - 1)) {
            DHCP_LOGE("CreateDirs() dirs:%{public}s len:%{public}d error!", dirs.c_str(), nSrcLen);
            return DHCP_OPT_FAILED;
        }
        if (strcat_s(strDir, sizeof(strDir), "/") != EOK) {
            DHCP_LOGE("CreateDirs() strcat_s strDir:%{public}s failed!", strDir);
            return DHCP_OPT_FAILED;
        }
        nSrcLen++;
    }

    int i = (strDir[0] == '/') ? 1 : 0;
    for (; i <= nSrcLen - 1; i++) {
        if (strDir[i] == '/') {
            strDir[i] = 0;
            if ((access(strDir, F_OK) != 0) && (mkdir(strDir, mode) != 0)) {
                DHCP_LOGE("CreateDirs() mkdir %{public}s %{public}.4o %{public}d!", strDir, mode, errno);
                return DHCP_OPT_FAILED;
            }
            strDir[i] = '/';
        }
    }
    DHCP_LOGI("CreateDirs() %{public}s %{public}.4o success.", dirs.c_str(), mode);
    return DHCP_OPT_SUCCESS;
}

bool DhcpFunction::SplitString(
    const std::string src, const std::string delim, const int count, std::vector<std::string> &splits)
{
    if (src.empty() || delim.empty()) {
        DHCP_LOGE("SplitString() error, src or delim is empty!");
        return false;
    }

    splits.clear();

    std::string strData(src);
    int nDelim = 0;
    char *pSave = nullptr;
    char *pTok = strtok_r(const_cast<char *>(strData.c_str()), delim.c_str(), &pSave);
    while (pTok != nullptr) {
        splits.push_back(std::string(pTok));
        nDelim++;
        pTok = strtok_r(nullptr, delim.c_str(), &pSave);
    }
    if (nDelim != count) {
        DHCP_LOGE("SplitString() %{private}s failed, nDelim:%{public}d,count:%{public}d!", src.c_str(), nDelim, count);
        return false;
    }
    DHCP_LOGI("SplitString() %{private}s success, delim:%{public}s, count:%{public}d, splits.size():%{public}d.",
        src.c_str(), delim.c_str(), count, (int)splits.size());
    return true;
}

int DhcpFunction::WaitProcessExit(const pid_t& serverPid)
{
    int retryCount = 0;
    while (retryCount < MAX_RETEY_WAIT_COUNT) {
        pid_t ret = waitpid(serverPid, nullptr, WNOHANG);
        if (ret == -1) {
            DHCP_LOGE("WaitProcessExit() waitpid [%{public}d] failed, errno:%{public}d!", serverPid, errno);
            return -1;
        } else if (ret == 0) {
            retryCount++;
            usleep(WAIT_SLEEP_50MS);
        }
        return 0;
    }
    DHCP_LOGE("WaitProcessExit() timeout waitpid [%{public}d] failed!", serverPid);
    return -1;
}
}  // namespace DHCP
}  // namespace OHOS
