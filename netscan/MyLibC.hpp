//
//  MyLibC.hpp
//  netscan
//
//  Created by Eric Mertens on 10/26/22.
//

#ifndef MyLibC_hpp
#define MyLibC_hpp

#include <arpa/inet.h>
#include <sys/wait.h>
#include <poll.h>

#include <chrono>
#include <csignal>
#include <cstddef>
#include <optional>
#include <tuple>


/// Wait for process termination
/// @param pid of process to wait for
/// @param options Combination of WNOHANG and WUNTRACED
/// @return pid of process and status information
auto Wait(pid_t pid = -1, int options = 0) -> std::pair<pid_t, int>;

/// Create a new process
/// @return pid of created process to parent and 0 to child
/// @exception std::system\_error on failure
auto Fork() -> pid_t;
auto Kill(pid_t pid, int sig) -> void;
auto InAddrPton(char const* str) -> std::optional<in_addr_t>;
auto Sigaction(int sig, struct sigaction const& act) -> struct sigaction;
auto Sigprocmask(int how, sigset_t const& set) -> sigset_t;
auto Close(int fd) -> void;
auto WriteAll(int fd, char const* buf, size_t n) -> size_t;
auto ReadAll(int fd, char* buf, size_t n) -> size_t;
struct Pipes {
    int read, write;
};

auto Pipe() -> Pipes;

/// Poll an array of file descriptors.
/// @param pollfds array of pollfds
/// @param n length of array
/// @param timeout milliseconds to wait or empty for indefinite
/// @return Number of ready descriptors or -1 on signal interrupt
/// @exception std::system\_error
auto Poll(pollfd pollfds[], nfds_t n, std::optional<std::chrono::milliseconds> timeout) -> int;

template <std::size_t N>
auto Poll(pollfd (&pollfds)[N], std::optional<std::chrono::milliseconds> timeout) -> int {
    return Poll(pollfds, N, timeout);
}

auto FcntlSetFd(int fd, int arg) -> void;
auto FcntlGetFd(int fd) -> int;


#endif /* MyLibC_hpp */
