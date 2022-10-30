//
//  MyLibC.cpp
//  netscan
//
//  Created by Eric Mertens on 10/26/22.
//

#include "MyLibC.hpp"

#include <unistd.h>

#include <cerrno>
#include <stdexcept>
#include <system_error>

#include <boost/numeric/conversion/cast.hpp>

auto Wait(pid_t pid, int options) -> std::pair<pid_t, int> {
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

/// Create a new process
/// @return Process ID of child to parent or 0 to child.
/// @exception std::system\_error
auto Fork() -> pid_t {
    auto res = fork();
    if (-1 == res) {
        throw std::system_error(errno, std::generic_category(), "fork");
    }
    return res;
}

/// Send signal to a process
/// @param pid target of signal
/// @param sig signal number
/// @exception std::system\_error
auto Kill(pid_t pid, int sig) -> void {
    auto res = kill(pid, sig);
    if (-1 == res) {
        throw std::system_error(errno, std::generic_category(), "kill");
    }
}

auto InAddrPton(char const* str) -> std::optional<in_addr_t>
{
    in_addr_t addr;
    switch (inet_pton(AF_INET, str, &addr)) {
        case 0:
            return {};
        case -1:
            throw std::system_error(errno, std::generic_category(), "inet_pton");
        default:
            return {addr};
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

/// Create descriptor pair for interprocess communication
/// @return pair of file descriptors
/// @exception std::system\_error
auto Pipe() -> Pipes {
    int pipes[2];
    auto res = pipe(pipes);
    if (-1 == res) {
        throw std::system_error(errno, std::generic_category(), "pipe");
    }
    return {pipes[0], pipes[1]};
}

/// Delete a descriptor
/// @param fd file descriptor to delete
/// @exception std::system\_error
auto Close(int fd) -> void {
    for(;;) {
        auto res = close(fd);
        if (-1 == res) {
            auto e = errno;
            if (EINTR != e) {
                throw std::system_error(e, std::generic_category(), "close");
            }
        } else {
            return;
        }
    }
}

/// Write as many bytes as possible to file descriptor until complete or
/// file is closed.
/// @param fd file descriptor
/// @param buf buffer to write
/// @params n size of buffer
/// @return total bytes written
/// @exception std::system\_error
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
                    throw std::system_error(e, std::generic_category(), "write");
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

/// Read from a file descriptor until buffer is filled or file is empty.
/// @param fd file descriptor
/// @param buf buffer to fill
/// @param n size of buffer
/// @return total bytes read
/// @exception std::system\_error
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
                    throw std::system_error(e, std::generic_category(), "read");
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

auto Poll(pollfd pollfds[], nfds_t n, std::optional<std::chrono::milliseconds> timeout) -> int {
    auto res = poll(pollfds, n, timeout ? boost::numeric_cast<int>(timeout->count()) : -1);
    if (-1 == res) {
        auto e = errno;
        if (EINTR != e) {
            throw std::system_error(e, std::generic_category(), "poll");
        }
    }
    return res;
}
