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

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_set>
#include <utility>

#include <boost/range/irange.hpp>
#include <boost/program_options.hpp>
#include <fmt/format.h>
#include <pcap/pcap.h>

#include "LocalSignalHandler.hpp"
#include "MyLibC.hpp"
#include "Pcap.hpp"
#include "PosixSpawn.hpp"
#include "PosixSpawnFileActions.hpp"
#include "PosixSpawnAttr.hpp"

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

auto breakloop_sigaction(pcap_t* p) -> struct sigaction {
    static std::atomic<pcap_t*> raw;
    static_assert(decltype(raw)::is_always_lock_free); // requirement for signal handler
    raw = p;

    struct sigaction act;
    act.sa_handler = [](auto){ pcap_breakloop(raw); };
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);

    return act;
}

/// Main function for PCAP listener process
/// @param source name of device to listen on
/// @param fd file descriptor of pipe to signal when ready
auto PcapMain(std::string const& source, int fd) -> void {

    auto pcap = pcap_setup(source.c_str());
    LocalSignalHandler breaker {SIGUSR1, breakloop_sigaction(pcap.get())};
    send_ready(fd);

    std::unordered_set<std::string> macs;
    auto body = [&macs](auto pkt_header, auto pkt_data) {
        if (11 < pkt_header->caplen) {
            auto mac = fmt::format(
               "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
               pkt_data[ 6], pkt_data[ 7], pkt_data[ 8],
               pkt_data[ 9], pkt_data[10], pkt_data[11]);
            if (macs.insert(mac).second) {
                std::cout << mac << std::endl;
            }
        }
    };

    pcap.loop(0, body);
    pcap.dispatch(0, body); // finish the rest of the buffer after a break
}

struct ipv4_argument {
    in_addr_t value;
};

auto validate(boost::any& v, std::vector<std::string> const& values, ipv4_argument*, int) -> void {
    namespace po = boost::program_options;
    po::validators::check_first_occurrence(v);
    auto const& s = po::validators::get_single_string(values);
    if (auto a = InAddrPton(s.c_str())) {
        v = boost::any(ipv4_argument{*a});
    } else {
        throw po::validation_error(po::validation_error::invalid_option_value);
    }
}

struct options {
    int spawn_limit;
    std::string device;
    ipv4_argument network;
    ipv4_argument netmask;
};

auto get_options(int argc, char** argv) -> options {
    namespace po = boost::program_options;
    options o;

    po::options_description desc("Allowed options");
    desc.add_options()
        ("help", "produce help message")
        ("limit,l", po::value(&o.spawn_limit)->default_value(50), "concurrent process spawn limit")
        ("device",  po::value(&o.device)->required(), "libpcap capture device")
        ("network", po::value(&o.network)->required(), "network number")
        ("netmask", po::value(&o.netmask)->required(), "network mask");

    po::positional_options_description p;
    p.add("device", 1).add("network", 1).add("netmask", 1);

    po::variables_map vm;
    po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);

    if (vm.count("help")) {
        std::cout << desc << std::endl;
        exit(EXIT_SUCCESS);
    }

    po::notify(vm);

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
        ping_range(options.network.value, options.netmask.value, options.spawn_limit);
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
