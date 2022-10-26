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

#include <cstddef>
#include <tuple>

auto Wait(pid_t pid = 0, int options = 0) -> std::tuple<pid_t, int>;
auto Fork() -> pid_t;
auto Kill(pid_t pid, int sig) -> void;
auto InAddrPton(char const* str) -> in_addr_t;
auto Sigaction(int sig, struct sigaction const& act) -> struct sigaction;
auto Close(int fd) -> void;
auto WriteAll(int fd, char const* buf, size_t n) -> size_t;
auto ReadAll(int fd, char* buf, size_t n) -> size_t;
struct Pipes {
    int read, write;
};

auto Pipe() -> Pipes;

#endif /* MyLibC_hpp */