/// @mainpage Local network mac address scanner

//
//  main.cpp
//  netscan
//
//  Created by Eric Mertens on 10/5/22.
//

#include <atomic>
#include <csignal>
#include <limits>
#include <spawn.h> // posix_spawn
#include <fcntl.h> // O_WRONLY
#include <poll.h> // poll
#include <unistd.h> // STDOUT_FILENO STDIN_FILENO
#include <fcntl.h>

#include <sys/select.h>

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
    p.setfilter(p.compile(filter, true, PCAP_NETMASK_UNKNOWN));
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

auto set_cloexec(int fd) {
    FcntlSetFd(fd, FD_CLOEXEC |  FcntlGetFd(fd));
}

// Logic to be applied to each of the packets
class PacketLogic {
    std::unordered_set<std::string> macs_;
public:
    auto operator()(auto pkt_header, auto pkt_data) -> void {
        if (11 < pkt_header->caplen) {
            auto mac = fmt::format(
               "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
               pkt_data[ 6], pkt_data[ 7], pkt_data[ 8],
               pkt_data[ 9], pkt_data[10], pkt_data[11]);
            if (macs_.insert(mac).second) {
                std::cout << mac << std::endl;
            }
        }
    }
};

class SpawnLogic {
    PosixSpawnAttr attr_;
    PosixSpawnFileActions actions_;
    char arg0_[5] {"ping"};
    char arg1_[4] {"-W1"};
    char arg2_[4] {"-c1"};
    char* args_[5] {arg0_, arg1_, arg2_, nullptr, nullptr};

public:
    SpawnLogic() {
        actions_.addopen( STDIN_FILENO, "/dev/null", O_RDONLY);
        actions_.addopen(STDOUT_FILENO, "/dev/null", O_WRONLY);
    }

    auto spawn(uint32_t addr) {
        auto arg = std::to_string(addr);
        args_[3] = arg.data(); // null-terminated since C++11
        PosixSpawnp("ping", actions_, attr_, args_, nullptr);
    }

};

class SelectLogic {

    int nfds_;
    fd_set readfds_;
    sigset_t chldmask_;
    sigset_t nochldmask_;
    std::optional<ch::steady_clock::time_point> cutoff_;

    template <class Rep, class Period>
    static auto to_timespec(ch::duration<Rep, Period> duration) -> timespec {
        timespec result;
        result.tv_sec  = ch::floor<ch::seconds    >(duration     ).count();
        result.tv_nsec = ch::floor<ch::nanoseconds>(duration % 1s).count();
        return result;
    }

    auto timeout(bool hasKids) -> std::optional<timespec> {
        if (hasKids) {
            return {};
        }
        auto now = ch::steady_clock::now();
        if (cutoff_) {
            return to_timespec(std::max(decltype(now)::duration::zero(), *cutoff_ - now));
        }
        cutoff_ = now + 1s;
        return to_timespec(1s);
    }

public:
    SelectLogic(int pcap_fd) {
        nfds_ = pcap_fd + 1;

        FD_ZERO(&readfds_);
        FD_SET(pcap_fd, &readfds_);

        sigemptyset(&chldmask_);
        sigaddset(&chldmask_, SIGCHLD);

        sigfillset(&nochldmask_);
        sigdelset(&nochldmask_, SIGCHLD);

        Sigprocmask(SIG_SETMASK, chldmask_);
        Sigaction(SIGCHLD, {[](int){}});
    }

    auto wait(bool hasKids) {
        fd_set fds;
        FD_COPY(&readfds_, &fds);
        auto to = timeout(hasKids);
        return pselect(nfds_, &fds, nullptr, nullptr, to ? &*to : nullptr, &nochldmask_);
    }
};

} // namespace

/// Main function
/// @param argc Command line argument count
/// @param argv Command line arguments
auto main(int argc, char** argv) -> int
{
    try {
        auto options = get_options(argc, argv);
        auto pcap = pcap_setup(options.device);
        set_cloexec(pcap.fileno());

        auto addr = ntohl(options.network.value) + 1;
        auto end = ntohl(options.network.value | ~options.netmask.value);
        auto kids = 0;

        PacketLogic packetLogic;
        SpawnLogic spawnLogic;
        SelectLogic selectLogic(pcap.selectable_fd());

        for(;;) {
            while (kids < options.spawn_limit && addr < end) {
                spawnLogic.spawn(addr);
                kids++;
                addr++;
            }

            auto events = selectLogic.wait(kids);
            switch (events) {
            case -1:
                while (kids && Wait(-1, WNOHANG).first) { kids--; }
                break;
            case 0:
                return 0;
            case 1:
                pcap.dispatch(0, packetLogic);
            }
        }

    } catch (std::exception const& e) {
        std::cerr << "Failure: " << e.what() << std::endl;
        return 1;
    }
}
