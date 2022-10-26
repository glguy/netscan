//
//  main.cpp
//  netscan
//
//  Created by Eric Mertens on 10/5/22.
//

#include <spawn.h> // posix_spawn
#include <fcntl.h> // O_WRONLY
#include <inttypes.h> // PRIu32
#include <unistd.h> // STDOUT_FILENO STDERR_FILENO

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <tuple>
#include <unordered_set>
#include <utility>
#include <vector>

#include <boost/range/irange.hpp>
#include <fmt/format.h>
#include <pcap/pcap.h>

#include "LocalSignalHandler.hpp"
#include "MyLibC.hpp"
#include "Pcap.hpp"
#include "PosixSpawn.hpp"

using namespace std::chrono_literals;

namespace {

auto pcap_setup(char const* const device) -> Pcap
{
    auto p = Pcap::open_live(device, 16, 0, 100ms);
    auto filter = "icmp[icmptype] == icmp-echoreply";
    auto program = p.compile(filter, true, PCAP_NETMASK_UNKNOWN);
    p.setfilter(&program);
    return p;
}

auto ping_range(in_addr_t address, in_addr_t netmask) -> void
{
    auto start = ntohl(address);
    auto end   = ntohl(address | ~netmask);

    PosixSpawnFileActions actions;
    PosixSpawnAttr attr;

    actions.addopen( STDIN_FILENO, "/dev/null", O_RDONLY);
    actions.addopen(STDOUT_FILENO, "/dev/null", O_WRONLY);
    actions.addopen(STDERR_FILENO, "/dev/null", O_WRONLY);

    char arg0[] {"ping"};
    char arg1[] {"-W1"};
    char arg2[] {"-c1"};
    char* args[] {arg0, arg1, arg2, nullptr, nullptr};

    auto pids = std::vector<pid_t>();
    for (auto addr : boost::irange(start+1, end)) {
        auto arg = std::to_string(addr);
        args[3] = arg.data(); // null-terminated since C++11
        pids.push_back(PosixSpawnp("ping", actions, attr, args, nullptr));
    }

    for (auto pid : pids) {
        Wait(pid);
    }
}


auto wait_ready(int fd) -> bool {
    char buffer;
    auto got = ReadAll(fd, &buffer, 1);
    Close(fd);
    return 1 == got;
}

auto send_ready(int fd) -> void {
    WriteAll(fd, "1", 1);
    Close(fd);
}


auto PcapMain(char const* source, int fd) -> void {

    auto pcap = pcap_setup(source);

    static pcap_t* volatile raw = pcap.get();
    sigset_t sigset;
    sigemptyset(&sigset);
    LocalSignalHandler sigusr {SIGUSR1, {*[](int) { pcap_breakloop(raw); }, sigset, SA_RESETHAND}};

    // Wait to signal ready until signal handler is installed
    send_ready(fd);

    auto macs = std::unordered_set<std::string>{};
    pcap.loop(0, [&macs](auto pkt_header, auto pkt_data) {
        if (11 < pkt_header->caplen) {
            auto mac = fmt::format(
               "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
               pkt_data[ 6], pkt_data[ 7], pkt_data[ 8],
               pkt_data[ 9], pkt_data[10], pkt_data[11]);
            if (macs.insert(mac).second) {
                std::cout << mac << std::endl;
            }
        }
    });
}

}



auto main(int argc, char* argv[]) -> int
{
    if (argc != 4) {
        std::cerr << "Usage: netscan interface network netmask" << std::endl;
        return 1;
    }

    try {
        auto address = InAddrPton(argv[2]);
        auto netmask = InAddrPton(argv[3]);
        if (address & ~netmask) {
            throw std::invalid_argument("network and netmask mismatch");
        }

        auto pipes = Pipe();
        pid_t pid = Fork();
        if (0 == pid) {
            close(pipes.read);
            PcapMain(argv[1], pipes.write);
            exit(EXIT_SUCCESS);
        }

        Close(pipes.write);
        if (!wait_ready(pipes.read)) {
            return 1;
        }

        ping_range(address, netmask);
        std::this_thread::sleep_for(1s);

        Kill(pid, SIGUSR1);
        auto [_, status] = Wait(pid);
        if (!WIFEXITED(status) || WEXITSTATUS(status)) {
            return 1;
        }
    } catch (std::exception const& e) {
        std::cerr << "Failure: " << e.what() << std::endl;
        return 1;
    }
}
