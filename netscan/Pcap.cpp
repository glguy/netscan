//
//  Pcap.cpp
//  netscan
//
//  Created by Eric Mertens on 10/10/22.
//

#include "Pcap.hpp"

#include <boost/numeric/conversion/cast.hpp>

#include <stdexcept>

void Pcap::PcapDelete::operator()(pcap_t* p) const noexcept {
    pcap_close(p);
}

Pcap::Pcap(pcap_t* p) noexcept : _pcap{p} {}

BpfProgram Pcap::compile(char const* str, bool optimize, bpf_u_int32 netmask) {
    BpfProgram program;
    checked(pcap_compile(_pcap.get(), &program, str, int(optimize), netmask));
    return program;
}

void Pcap::setfilter(BpfProgram* program) {
    checked(pcap_setfilter(_pcap.get(), program));
}

std::optional<std::pair<pcap_pkthdr*, u_char const*>> Pcap::next() {
    pcap_pkthdr* header;
    u_char const* data;

    if (pcap_next_ex(_pcap.get(), &header, &data)) {
        return {{header,data}};
    } else {
        return {};
    }
}

Pcap Pcap::open_live(char const* device, int snaplen, bool promisc, std::chrono::milliseconds timeout_ms) {
    char errbuf[PCAP_ERRBUF_SIZE];
    if (auto p = pcap_open_live(device, snaplen, int(promisc), boost::numeric_cast<int>(timeout_ms.count()), errbuf)) {
        return Pcap{p};
    }
    throw std::runtime_error(errbuf);
}

void Pcap::checked(int res) {
    if (PCAP_ERROR == res) {
        throw std::runtime_error(pcap_geterr(_pcap.get()));
    }
}
