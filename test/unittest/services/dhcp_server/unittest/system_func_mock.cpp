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
#include <cstdint>
#include <sys/select.h>
#include <sys/time.h>
#include "system_func_mock.h"
#include "address_utils.h"
#include "dhcp_define.h"
#include "dhcp_logger.h"
#include "dhcp_message.h"
#include "dhcp_message_sim.h"
#include "dhcp_option.h"
#include "securec.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpServerSystemFuncMock");

using namespace OHOS::DHCP;

#define MAGIC_COOKIE_LENGTH 4
#define OPT_HEADER_LENGTH 2
#define TIME_SEC_TO_USEC (1000 * 1000)

static bool g_mockTag = false;
static int TIME_MSEC_TO_USEC = 1000;
SystemFuncMock &SystemFuncMock::GetInstance()
{
    static SystemFuncMock gSystemFuncMock;
    return gSystemFuncMock;
};

SystemFuncMock::SystemFuncMock() {}

SystemFuncMock::~SystemFuncMock() {}

void SystemFuncMock::SetMockFlag(bool flag)
{
    g_mockTag = flag;
}

bool SystemFuncMock::GetMockFlag(void)
{
    return g_mockTag;
}

extern "C" {
struct in_addr {
    uint32_t s_addr;
};

struct sockaddr_in {
    short int sin_family;
    unsigned short int sin_port;
    struct in_addr sin_addr;
    unsigned char sin_zero[8];
};

int __real_open(const char *__file, int __oflag);
int __wrap_open(const char *__file, int __oflag)
{
    if (g_mockTag) {
        return SystemFuncMock::GetInstance().open(__file, __oflag);
    } else {
        return __real_open(__file, __oflag);
    }
}

ssize_t __real_write(int fd, const void *buf, size_t count);
ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
    if (g_mockTag) {
        return SystemFuncMock::GetInstance().write(fd, buf, count);
    } else {
        return __real_write(fd, buf, count);
    }
}

ssize_t __real_read(int fd, void *buf, size_t count);
ssize_t __wrap_read(int fd, void *buf, size_t count)
{
    if (g_mockTag) {
        return SystemFuncMock::GetInstance().read(fd, buf, count);
    } else {
        return __real_read(fd, buf, count);
    }
}

int __real_socket(int __domain, int __type, int __protocol);
int __wrap_socket(int __domain, int __type, int __protocol)
{
    DHCP_LOGD("==>socket.");
    if (g_mockTag) {
        DHCP_LOGD(" ==>mock enable.");
        return SystemFuncMock::GetInstance().socket(__domain, __type, __protocol);
    } else {
        DHCP_LOGD(" ==>mock disable.");
    }
    return __real_socket(__domain, __type, __protocol);
}

int __real_setsockopt(int __fd, int __level, int __optname, const void *__optval, socklen_t __optlen);
int __wrap_setsockopt(int __fd, int __level, int __optname, const void *__optval, socklen_t __optlen)
{
    DHCP_LOGD("==>setsockopt.");
    if (g_mockTag) {
        DHCP_LOGD(" ==>mock enable.");
        return SystemFuncMock::GetInstance().setsockopt(__fd, __level, __optname, __optval, __optlen);
    } else {
        DHCP_LOGD(" ==>mock disable.");
    }
    return __real_setsockopt(__fd, __level, __optname, __optval, __optlen);
}

int __real_select(int __nfds, fd_set *__readfds, fd_set *__writefds, fd_set *__exceptfds, struct timeval *__timeout);
int __wrap_select(int __nfds, fd_set *__readfds, fd_set *__writefds, fd_set *__exceptfds, struct timeval *__timeout)
{
    const unsigned int SLEEP_TIEM = 300000;
    DHCP_LOGD("==>select.");
    if (g_mockTag) {
        DHCP_LOGD(" ==>mock enable.");
        DHCP_LOGD("message queue total: %d.", DhcpMsgManager::GetInstance().SendTotal());
        if (DhcpMsgManager::GetInstance().SendTotal() > 0) {
            FD_CLR(__nfds, __readfds);
            usleep(SLEEP_TIEM);
            return 1;
        }
        int retval = SystemFuncMock::GetInstance().select(__nfds, __readfds, __writefds, __exceptfds, __timeout);
        if (retval == 0) {
            if (__timeout != nullptr) {
                usleep(DHCP_SEL_WAIT_TIMEOUTS * TIME_MSEC_TO_USEC);
                DHCP_LOGD("select time out.");
            }
        }
        return retval;
    } else {
        DHCP_LOGD(" ==>mock disable.");
    }
    return __real_select(__nfds, __readfds, __writefds, __exceptfds, __timeout);
}

int __real_ioctl(int __fd, unsigned long __request, struct sockaddr *__ifreq);
int __wrap_ioctl(int __fd, unsigned long __request, struct sockaddr *__ifreq)
{
    if (g_mockTag) {
        return SystemFuncMock::GetInstance().ioctl(__fd, __request, __ifreq);
    } else {
        return __real_ioctl(__fd, __request, __ifreq);
    }
}

int __real_listen(int __fd, int __n);
int __wrap_listen(int __fd, int __n)
{
    if (g_mockTag) {
        return SystemFuncMock::GetInstance().listen(__fd, __n);
    } else {
        return __real_listen(__fd, __n);
    }
}

int __real_connect(int __fd, const struct sockaddr *__addr, socklen_t __len);
int __wrap_connect(int __fd, const struct sockaddr *__addr, socklen_t __len)
{
    if (g_mockTag) {
        return SystemFuncMock::GetInstance().connect(__fd, __addr, __len);
    } else {
        return __real_connect(__fd, __addr, __len);
    }
}

pid_t __real_vfork();
pid_t __wrap_vfork()
{
    if (g_mockTag) {
        return SystemFuncMock::GetInstance().vfork();
    } else {
        return __real_vfork();
    }
}

int __real_execv(const char *__path, char *const *__argv);
int __wrap_execv(const char *__path, char *const *__argv)
{
    if (g_mockTag) {
        return SystemFuncMock::GetInstance().execv(__path, __argv);
    } else {
        return __real_execv(__path, __argv);
    }
}

void __real__exit(int status);
void __wrap__exit(int status)
{
    if (g_mockTag) {
        SystemFuncMock::GetInstance()._exit(status);
    } else {
        __real__exit(status);
    }
    return;
}

pid_t __real_waitpid(pid_t pid, int *status, int options);
pid_t __wrap_waitpid(pid_t pid, int *status, int options)
{
    if (g_mockTag) {
        return SystemFuncMock::GetInstance().waitpid(pid, status, options);
    } else {
        return __real_waitpid(pid, status, options);
    }
}

int __real_kill(pid_t pid, int sig);
int __wrap_kill(pid_t pid, int sig)
{
    if (g_mockTag) {
        return SystemFuncMock::GetInstance().kill(pid, sig);
    } else {
        return __real_kill(pid, sig);
    }
}

int __real_bind(int __fd, struct sockaddr *__addr, socklen_t __len);
int __wrap_bind(int __fd, struct sockaddr *__addr, socklen_t __len)
{
    DHCP_LOGD("==>bind.");
    if (g_mockTag) {
        DHCP_LOGD(" ==>mock enable.");
        return SystemFuncMock::GetInstance().bind(__fd, __addr, __len);
    } else {
        DHCP_LOGD(" ==>mock disable.");
    }
    return __real_bind(__fd, __addr, __len);
}

int __real_close(int _fileno);
int __wrap_close(int _fileno)
{
    DHCP_LOGD("==>close.");
    if (g_mockTag) {
        DHCP_LOGD(" ==>mock enable.");
        return SystemFuncMock::GetInstance().close(_fileno);
    } else {
        DHCP_LOGD(" ==>mock disable.");
    }
    return __real_close(_fileno);
}

ssize_t recvfrom(int __fd, void *__buf, size_t __n, int __flags, struct sockaddr *__addr, socklen_t *__addr_len)
{
    DHCP_LOGD("==>recvfrom.");
    if (!g_mockTag) {
        DHCP_LOGD(" ==>mock disable.");
        return SystemFuncMock::GetInstance().recvfrom(__fd, __buf, __n, __flags, __addr, __addr_len);
    }
    DHCP_LOGD(" ==>mock enable.");
    if (DhcpMsgManager::GetInstance().SendTotal() > 0 && __buf) {
        DHCP_LOGD("== new message received.");
        DhcpMessage msg = { 0 };
        if (DhcpMsgManager::GetInstance().FrontSendMsg(&msg)) {
            (void)memcpy_s(__buf, __n, &msg, sizeof(DhcpMessage));
            DhcpMsgManager::GetInstance().PopSendMsg();
            uint32_t srcIp = DhcpMsgManager::GetInstance().GetClientIp();
            if (__addr != nullptr && srcIp != 0) {
                struct sockaddr_in *sAddr = reinterpret_cast<sockaddr_in *>(__addr);
                sAddr->sin_addr.s_addr = HostToNetwork(srcIp);
                DhcpMsgManager::GetInstance().SetClientIp(0);
            }
            return sizeof(DhcpMessage);
        }
    }
    return SystemFuncMock::GetInstance().recvfrom(__fd, __buf, __n, __flags, __addr, __addr_len);
}

int ParseMockOptions(DhcpMessage *packet)
{
    if (packet == nullptr) {
        DHCP_LOGD("dhcp message pointer is null.");
        return RET_FAILED;
    }
    DhcpMsgInfo reply;
    if (memset_s(&reply, sizeof(DhcpMsgInfo), 0, sizeof(DhcpMsgInfo)) != EOK) {
        DHCP_LOGD("failed to reset dhcp message info.");
        return RET_FAILED;
    }
    int retval = RET_FAILED;
    if (memcpy_s(&reply.packet, sizeof(reply.packet), packet, sizeof(DhcpMessage)) != EOK) {
        DHCP_LOGD("failed to fill dhcp message.");
        return RET_FAILED;
    }
    reply.length = sizeof(DhcpMessage);
    if (InitOptionList(&reply.options) != RET_SUCCESS) {
        DHCP_LOGD("failed to init dhcp option list.");
        return retval;
    }
    FreeOptionList(&reply.options);
    return retval;
}

ssize_t sendto(int __fd, const void *__buf, size_t __n, int __flags, struct sockaddr *__addr, socklen_t __addr_len)
{
    DHCP_LOGD("==>sendto.");
    if (g_mockTag) {
        DHCP_LOGD(" ==>mock enable.");
        if (__buf == nullptr) {
            return SystemFuncMock::GetInstance().sendto(__fd, __buf, __n, __flags, __addr, __addr_len);
        }
    } else {
        DHCP_LOGD(" ==>mock disable.");
    }
    return SystemFuncMock::GetInstance().sendto(__fd, __buf, __n, __flags, __addr, __addr_len);
}
}
