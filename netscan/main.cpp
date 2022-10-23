//
//  main.cpp
//  netscan
//
//  Created by Eric Mertens on 10/5/22.
//

#include <pcap/pcap.h>

#include "Pcap.hpp"
#include "PosixSpawnFileActions.hpp"
#include "PosixSpawnAttr.hpp"

#include <errno.h>
#include <spawn.h> // posix_spawn
#include <fcntl.h> // O_WRONLY
#include <inttypes.h> // PRIu32
#include <unistd.h> // STDOUT_FILENO STDERR_FILENO
#include <arpa/inet.h>
#include <sys/wait.h> // waitpid
#include <sys/select.h>

#include <chrono>
#include <cstring>
#include <iostream>
#include <iterator>
#include <memory>
#include <future>
#include <numeric>
#include <optional>
#include <string>
#include <system_error>
#include <thread>
#include <tuple>
#include <unordered_set>
#include <utility>
#include <vector>
#include <stdexcept>
#include <system_error>


using namespace std::chrono_literals;

namespace {

auto pcap_setup(char const* const interface) -> Pcap
{
    auto p = Pcap::open_live(interface, 16, 0, 100ms);
    auto filter = "icmp[icmptype] == icmp-echoreply";
    auto program = p.compile(filter, true, PCAP_NETMASK_UNKNOWN);
    p.setfilter(&program);
    return p;
}

auto ping_main(uint32_t address, uint32_t netmask) -> void
{
    auto start = address & netmask;
    auto end   = start | ~netmask;
    
    PosixSpawnFileActions actions;
    PosixSpawnAttr attr;
    
    actions.addopen(STDIN_FILENO , "/dev/null", O_RDONLY, 0);
    actions.addopen(STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    actions.addopen(STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    
    char arg0[] {"ping"};
    char arg1[] {"-W1"};
    char arg2[] {"-c1"};
    char arg3[11];
    char* const args[] {arg0, arg1, arg2, arg3, nullptr};
    
    int kids = 0;
    for (auto addr = start + 1; addr < end; addr++) {
        sprintf(arg3, "%" PRIu32, addr);
        auto res = posix_spawnp(nullptr, "ping", actions.get(), attr.get(), args, nullptr);
        if (0 != res) {
            throw std::system_error(res, std::generic_category(), "posix_spawn");
        }
        kids++;
    }

    while (kids > 0) {
        auto res = wait(nullptr);
        if (-1 != res) {
            kids -= 1;
        } else if (EINTR != errno) {
            throw std::system_error(errno, std::generic_category(), "wait");
        }
    }
}

auto addrparse(char const* str) -> uint32_t
{
    in_addr_t addr;
    switch (inet_pton(AF_INET, str, &addr)) {
        case 0:
            throw std::runtime_error("bad inet address");
        case -1:
            throw std::system_error(errno, std::generic_category(), "inet_pton");
        default:
            return ntohl(addr);
    }
}

}

auto main(int argc, char* argv[]) -> int
{
    if (argc != 4) {
        std::cerr << "Usage: netscan interface network netmask" << std::endl;
        return 1;
    }

    try {
        auto address = addrparse(argv[2]);
        auto netmask = addrparse(argv[3]);

        auto pcap = pcap_setup(argv[1]);
        auto raw = pcap.raw();

        auto listener = std::async(std::launch::async, [&pcap]() {
            auto macs = std::unordered_set<std::string>();
            pcap.loop(0, [&macs](auto pkt_header, auto pkt_data) {
                if (12 < pkt_header->caplen) {
                    char buffer[18];
                    sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x",
                            int(pkt_data[6]), int(pkt_data[7]),  int(pkt_data[8]),
                            int(pkt_data[9]), int(pkt_data[10]), int(pkt_data[11]));
                    if (macs.insert(buffer).second) {
                        std::cout << buffer << std::endl;
                    }
                }
            });
        });
                
        ping_main(address, netmask);
        std::this_thread::sleep_for(1s);
        pcap_breakloop(raw);
        listener.get();

        return 0;

    } catch (std::exception const& e) {
        std::cerr << "Failure: " << e.what() << std::endl;
        return 1;
    }
}
