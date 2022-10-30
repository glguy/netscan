/// @mainpage Local network mac address scanner

//
//  main.cpp
//  netscan
//
//  Created by Eric Mertens on 10/5/22.
//

#include <spawn.h> // posix_spawn
#include <fcntl.h> // O_WRONLY
#include <poll.h> // poll
#include <unistd.h> // STDOUT_FILENO STDIN_FILENO

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <system_error>
#include <tuple>
#include <unordered_set>
#include <utility>

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
namespace ch = std::chrono;

namespace {

/// Construct a ping reply listener
/// @param device name to listen on
auto pcap_setup(std::string const& device) -> Pcap
{
    auto p = Pcap::open_live(device.c_str(), 16, 0, 100ms);
    auto filter = "icmp[icmptype] == icmp-echoreply";
    auto program = p.compile(filter, true, PCAP_NETMASK_UNKNOWN);
    p.setfilter(&program);
    return p;
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

// Logic to be applied to each of the packets
class Processor {
    std::unordered_set<std::string> macs;
public:
    auto operator()(auto pkt_header, auto pkt_data) -> void {
        if (11 < pkt_header->caplen) {
            auto mac = fmt::format(
               "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
               pkt_data[ 6], pkt_data[ 7], pkt_data[ 8],
               pkt_data[ 9], pkt_data[10], pkt_data[11]);
            if (macs.insert(mac).second) {
                std::cout << mac << std::endl;
            }
        }
    }
};

extern "C" auto null_handler(int) -> void {}

} // namespace

/// Main function
/// @param argc Command line argument count
/// @param argv Command line arguments
auto main(int argc, char** argv) -> int
{
    try {
        // generates interrupts to break out of poll
        Sigaction(SIGCHLD, {null_handler, 0, SA_NOCLDSTOP});

        auto options = get_options(argc, argv);
        auto pcap = pcap_setup(options.device);

        PosixSpawnAttr attr;
        PosixSpawnFileActions actions;
        actions.addopen( STDIN_FILENO, "/dev/null", O_RDONLY);
        actions.addopen(STDOUT_FILENO, "/dev/null", O_WRONLY);

        char arg0[] {"ping"}, arg1[] {"-W1"}, arg2[] {"-c1"};
        char* args[] {arg0, arg1, arg2, nullptr, nullptr};

        pollfd pollfds[] {{pcap.selectable_fd(), POLLIN}};

        auto addr = ntohl(options.network.value) + 1;
        auto end = ntohl(options.network.value | ~options.netmask.value);
        int kids = 0;

        Processor processor;

        std::optional<ch::steady_clock::time_point> cutoff;
        for(;;) {
            while (kids && Wait(-1, WNOHANG).first) { kids--; }

            while (kids < options.spawn_limit && addr < end) {
                auto arg = std::to_string(addr);
                args[3] = arg.data(); // null-terminated since C++11
                PosixSpawnp("ping", actions, attr, args, nullptr);
                kids++;
                addr++;
            }

            std::optional<ch::milliseconds> timeout;
            if (cutoff) {
                timeout = std::max(0ms, ch::round<ch::milliseconds>(*cutoff - ch::steady_clock::now()));
            } else if (0 == kids) {
                cutoff = ch::steady_clock::now() + 1s;
                timeout = 1s;
            }

            switch (Poll(pollfds, timeout)) {
            case 0: return 0;
            case 1: pcap.dispatch(0, processor);
            }
        }

    } catch (std::exception const& e) {
        std::cerr << "Failure: " << e.what() << std::endl;
        return 1;
    }
}
