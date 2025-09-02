/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_MOCK_SYSTEM_FUNC_H
#define OHOS_MOCK_SYSTEM_FUNC_H

#include <gmock/gmock.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>

// force the linker to use our wrapper functions
#ifdef __cplusplus
extern "C" {
#endif
ssize_t __wrap_sendto(int __fd, const void *__buf, size_t __n, int __flags,
                      const struct sockaddr *__addr, socklen_t __addr_len);
#ifdef __cplusplus
}
#endif

// Preprocessor-level redefinition
#undef sendto
#define sendto __wrap_sendto

// force the linker to use our wrapper functions
#ifdef __cplusplus
extern "C" {
#endif
ssize_t __wrap_read(int fd, void *buf, size_t count);
#ifdef __cplusplus
}
#endif
// Preprocessor-level redefinition
#undef read
#define read __wrap_read

using ::testing::_;
using ::testing::Return;

namespace OHOS {
namespace DHCP {
class MockSystemFunc {
public:
    MOCK_METHOD2(open, int(const char *__file, int __oflag));
    MOCK_METHOD1(close, int(int));
    MOCK_METHOD3(write, ssize_t(int fd, const void *buf, size_t count));
    MOCK_METHOD3(read, ssize_t(int fd, void *buf, size_t count));
    MOCK_METHOD3(socket, int(int __domain, int __type, int __protocol));
    MOCK_METHOD5(setsockopt, int(int __fd, int __level, int __optname, const void *__optval, socklen_t __optlen));
    MOCK_METHOD3(ioctl, int(int __fd, unsigned long __request, struct sockaddr *__ifreq));
    MOCK_METHOD3(bind, int(int __fd, const struct sockaddr *__addr, socklen_t __len));
    MOCK_METHOD2(listen, int(int __fd, int __n));
    MOCK_METHOD3(connect, int(int __fd, const struct sockaddr *__addr, socklen_t __len));
    MOCK_METHOD5(select, int(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout));
    MOCK_METHOD6(sendto, ssize_t(int __fd, const void *__buf, size_t __n, int __flags, const struct sockaddr *__addr,
        socklen_t __addr_len));
    MOCK_METHOD4(socketpair, int(int address, int type, int protocol, int *socket));
    MOCK_METHOD2(fcntl2, int(int fd, int cmd));
    MOCK_METHOD3(fcntl3, int(int fd, int cmd, int arg));
    MOCK_METHOD1(if_nametoindex, unsigned int(const char *ifname));
    MOCK_METHOD3(poll, int(struct pollfd *fds, nfds_t nfds, int timeout));

    static MockSystemFunc &GetInstance(void);
    static void SetMockFlag(bool flag);
    static bool GetMockFlag(void);

private:
    MockSystemFunc();
    ~MockSystemFunc()
    {}
};
}  // namespace DHCP
}  // namespace OHOS
#endif
