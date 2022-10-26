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
