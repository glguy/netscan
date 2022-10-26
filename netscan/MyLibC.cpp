//
//  MyLibC.cpp
//  netscan
//
//  Created by Eric Mertens on 10/26/22.
//

#include "MyLibC.hpp"

#include <unistd.h>

#include <cerrno>
#include <system_error>
#include <csignal>
#include <unistd.h>

auto Wait(pid_t pid, int options) -> std::tuple<pid_t, int> {
    for (;;) {
        int stat;
        auto res = waitpid(pid, &stat, options);
        if (-1 == res) {
            auto e = errno;
            if (EINTR != e) {
                throw std::system_error(e, std::generic_category(), "waitpid");
            }
        } else {
            return {res, stat};
        }
    }
}

auto Fork() -> pid_t {
    auto res = fork();
    if (-1 == res) {
        throw std::system_error(errno, std::generic_category(), "fork");
    }
    return res;
}

auto Kill(pid_t pid, int sig) -> void {
    auto res = kill(pid, sig);
    if (-1 == res) {
        throw std::system_error(errno, std::generic_category(), "kill");
    }
}

auto InAddrPton(char const* str) -> in_addr_t
{
    in_addr_t addr;
    switch (inet_pton(AF_INET, str, &addr)) {
        case 0:
            throw std::invalid_argument("bad inet address");
        case -1:
            throw std::system_error(errno, std::generic_category(), "inet_pton");
        default:
            return addr;
    }
}

auto Sigaction(int sig, struct sigaction const& act) -> struct sigaction {
    struct sigaction old;
    auto res = sigaction(sig, &act, &old);
    if (-1 == res) {
        throw std::system_error(errno, std::generic_category(), "sigaction");
    }
    return old;
}

auto Pipe() -> Pipes {
    int pipes[2];
    auto res = pipe(pipes);
    if (-1 == res) {
        throw std::system_error(errno, std::generic_category(), "pipe");
    }
    return {pipes[0], pipes[1]};
}

auto Close(int fd) -> void {
    for(;;) {
        auto res = close(fd);
        if (-1 == res) {
            auto e = errno;
            if (EINTR != e) {
                throw std::system_error(errno, std::generic_category(), "pipe");
            }
        } else {
            return;
        }
    }
}

auto WriteAll(int fd, char const* buf, size_t n) -> size_t {
    size_t wrote = 0;
    while (wrote < n) {
        auto res = write(fd, buf + wrote, n - wrote);
        switch (res) {
            case 0:
                return wrote;
            case -1:
            {
                auto e = errno;
                if (EINTR != e) {
                    throw std::system_error(errno, std::generic_category(), "pipe");
                }
                break;
            }
                default:
                wrote += res;
                break;
        }
    }
    return wrote;
}

auto ReadAll(int fd, char* buf, size_t n) -> size_t {
    size_t got = 0;
    while (got < n) {
        auto res = read(fd, buf+got, n-got);
        switch (res) {
            case 0:
                return got;
            case -1:
            {
                auto e = errno;
                if (EINTR != e) {
                    throw std::system_error(errno, std::generic_category(), "pipe");
                }
                break;
            }
            default:
                got += res;
                break;
        }
    }
    return got;
}