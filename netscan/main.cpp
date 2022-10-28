/// @mainpage Local network mac address scanner

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

/// Construct a ping reply listener
/// @param device name to listen on
auto pcap_setup(char const* const device) -> Pcap
{
    auto p = Pcap::open_live(device, 16, 0, 100ms);
    auto filter = "icmp[icmptype] == icmp-echoreply";
    auto program = p.compile(filter, true, PCAP_NETMASK_UNKNOWN);
    p.setfilter(&program);
    return p;
}

/// Invoke ping once for every address on the given network.
/// @param address Network number
/// @param netmask Network mask
/// @limit maximum number of concurrent pings to spawn
auto ping_range(in_addr_t address, in_addr_t netmask, int limit) -> void
{
    auto start = ntohl(address);
    auto end   = ntohl(address | ~netmask);

    PosixSpawnAttr attr;
    attr.setflags(POSIX_SPAWN_SETPGROUP);
    pid_t pgroup = 0;

    PosixSpawnFileActions actions;
    actions.addopen( STDIN_FILENO, "/dev/null", O_RDONLY);
    actions.addopen(STDOUT_FILENO, "/dev/null", O_WRONLY);
    actions.addopen(STDERR_FILENO, "/dev/null", O_WRONLY);

    char arg0[] {"ping"};
    char arg1[] {"-W1"};
    char arg2[] {"-c1"};
    char* args[] {arg0, arg1, arg2, nullptr, nullptr};

    int n = 0;
    for (auto addr : boost::irange(start+1, end)) {
        auto arg = std::to_string(addr);
        args[3] = arg.data(); // null-terminated since C++11

        auto pid = PosixSpawnp("ping", actions, attr, args, nullptr);
        n++;

        if (pgroup == 0) {
            attr.setpgroup(pgroup = pid);
        }

        while (n > 0) {
            int flags = n >= limit ? 0 : WNOHANG;
            auto [pid,_] = Wait(-pgroup, flags);

            if (pid == 0) { break; }
            n--;
        }

        if (n == 0) {
            attr.setpgroup(pgroup = 0);
        }
    }

    while (n > 0) {
        Wait(-pgroup);
        n--;
    }
}

/// Wait until one byte is available to read on the given file descriptor
/// @param fd file descriptor of read end of pipe
/// @return true on success
auto wait_ready(int fd) -> bool {
    char buffer;
    auto got = ReadAll(fd, &buffer, 1);
    Close(fd);
    return 1 == got;
}

/// Transmit a single byte to corresponding wait\_ready call
/// @param fd file descriptor of write end of pipe
auto send_ready(int fd) -> void {
    WriteAll(fd, "1", 1);
    Close(fd);
}

/// Main function for PCAP listener process
/// @param source name of device to listen on
/// @param fd file descriptor of pipe to signal when ready
auto PcapMain(char const* source, int fd) -> void {

    auto pcap = pcap_setup(source);

    static pcap_t* raw;
    raw = pcap.get();

    struct sigaction act;
    act.sa_handler = [](int){ pcap_breakloop(raw); };
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    LocalSignalHandler breaker {SIGUSR1, act};

    // Wait to signal ready until signal handler is installed
    send_ready(fd);

    std::unordered_set<std::string> macs;
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

struct options {
    int spawn_limit = 50;
    char const* device;
    in_addr_t network;
    in_addr_t netmask;
};

auto get_options(int argc, char** argv) -> options {
    options o;

    int ch;
    while ((ch = getopt(argc, argv, "hl:")) != -1) {
        switch (ch) {
            default: throw std::invalid_argument("bad command-line flag");
            case 'h':
                std::cerr << "Usage: netscan [-l limit] interface network netmask" << std::endl;
                exit(EXIT_SUCCESS);
            case 'l':
                o.spawn_limit = atoi(optarg);
                if (o.spawn_limit <= 0) {
                    throw std::invalid_argument("bad spawn limit");
                }
                break;
        }
    }

    argc -= optind;
    argv += optind;

    switch (argc) {
        case 0: throw std::invalid_argument("interface argument missing");
        case 1: throw std::invalid_argument("network argument missing");
        case 2: throw std::invalid_argument("netmask argument missing");
        case 3: break;
        default: throw std::invalid_argument("too many arguments");
    }

    o.device = argv[0];
    o.network = InAddrPton(argv[1]);
    o.netmask = InAddrPton(argv[2]);

    // Ensure network number has a zero host number part
    if (o.network & ~o.netmask) {
        throw std::invalid_argument("network and netmask mismatch");
    }

    return o;
}

}

/// Main function
/// @param argc Command line argument count
/// @param argv Command line arguments
auto main(int argc, char** argv) -> int
{
    try {
        auto options = get_options(argc, argv);

        // Create pcap capture loop process
        auto pipes = Pipe();
        auto pid = Fork();
        if (0 == pid) {
            Close(pipes.read);
            PcapMain(options.device, pipes.write);
            return 0;
        }

        // Wait for capture loop process to be ready
        Close(pipes.write);
        if (!wait_ready(pipes.read)) {
            return 1;
        }

        // Ping all the hosts on the network
        ping_range(options.network, options.netmask, options.spawn_limit);
        std::this_thread::sleep_for(1s);

        // Clean up the capture loop process
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
