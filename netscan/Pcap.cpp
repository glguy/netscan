//
//  Pcap.cpp
//  netscan
//
//  Created by Eric Mertens on 10/10/22.
//

#include "Pcap.hpp"

#include <boost/numeric/conversion/cast.hpp>

#include <stdexcept>
#include <type_traits>

auto Pcap::PcapDelete::operator()(pcap_t* p) const noexcept -> void {
    pcap_close(p);
}

Pcap::Pcap(pcap_t* p) noexcept : _pcap{p} {}

auto Pcap::compile(char const* str, bool optimize, bpf_u_int32 netmask) -> BpfProgram {
    BpfProgram program;
    checked(pcap_compile(_pcap.get(), &program, str, optimize, netmask));
    return program;
}

auto Pcap::setfilter(BpfProgram* program) -> void {
    checked(pcap_setfilter(_pcap.get(), program));
}

auto Pcap::dispatch(int cnt, pcap_handler callback, u_char* data) -> int {
    return checked(pcap_dispatch(_pcap.get(), cnt, callback, data));
}

auto Pcap::open_live(char const* device, int snaplen, bool promisc, std::chrono::milliseconds timeout_ms) -> Pcap {
    char errbuf[PCAP_ERRBUF_SIZE];
    if (auto p = pcap_open_live(device, snaplen, promisc, boost::numeric_cast<int>(timeout_ms.count()), errbuf)) {
        return Pcap{p};
    }
    throw std::runtime_error(errbuf);
}

auto Pcap::checked(int res) -> int {
    if (PCAP_ERROR == res) {
        throw std::runtime_error(pcap_geterr(_pcap.get()));
    }
    return res;
}
