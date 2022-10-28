//
//  Pcap.cpp
//  netscan
//
//  Created by Eric Mertens on 10/10/22.
//

#include "Pcap.hpp"

#include <boost/numeric/conversion/cast.hpp>

#include <stdexcept>

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

auto Pcap::loop(int cnt, pcap_handler callback, u_char* data) -> int {
    return checked(pcap_loop(_pcap.get(), cnt, callback, data));
}

auto Pcap::open_live(char const* device, int snaplen, bool promisc, std::chrono::milliseconds timeout_ms) -> Pcap {
    char errbuf[PCAP_ERRBUF_SIZE];
    if (auto p = pcap_open_live(device, snaplen, promisc, boost::numeric_cast<int>(timeout_ms.count()), errbuf)) {
        return Pcap{p};
    }
    throw std::runtime_error(errbuf);
}

auto Pcap::checked(int res) const -> int {
    if (PCAP_ERROR == res) {
        throw std::runtime_error(pcap_geterr(_pcap.get()));
    }
    return res;
}

auto Pcap::next() -> std::optional<std::pair<pcap_pkthdr*, u_char const*>> {
    pcap_pkthdr *h;
    u_char const* d;
    switch (checked(pcap_next_ex(_pcap.get(), &h, &d))) {
        case 1:
            return {{h,d}};
        default:
            return {};
    }
}

auto Pcap::selectable_fd() -> int {
    return pcap_get_selectable_fd(_pcap.get());
}

auto Pcap::required_select_timeout() -> timeval const* {
    return pcap_get_required_select_timeout(_pcap.get());
}

auto Pcap::set_nonblock(int x) -> void {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_setnonblock(_pcap.get(), x, errbuf);
}

auto Pcap::get() -> pcap_t* {
    return _pcap.get();
}

auto Pcap::release() -> pcap_t* {
    return _pcap.release();
}

auto Pcap::fileno() const -> int {
    return checked(pcap_fileno(_pcap.get()));
}
