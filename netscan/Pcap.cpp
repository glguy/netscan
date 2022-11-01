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

Pcap::Pcap(pcap_t* p) noexcept : pcap_{p} {}

auto Pcap::compile(char const* str, bool optimize, bpf_u_int32 netmask) -> BpfProgram {
    BpfProgram program;
    checked(pcap_compile(pcap_.get(), program.get(), str, optimize, netmask));
    return program;
}

auto Pcap::setfilter(BpfProgram program) -> void {
    checked(pcap_setfilter(pcap_.get(), program.get()));
}

auto Pcap::dispatch(int cnt, pcap_handler callback, u_char* data) -> int {
    return checked(pcap_dispatch(pcap_.get(), cnt, callback, data));
}

auto Pcap::loop(int cnt, pcap_handler callback, u_char* data) -> int {
    return checked(pcap_loop(pcap_.get(), cnt, callback, data));
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
        throw std::runtime_error(pcap_geterr(pcap_.get()));
    }
    return res;
}

auto Pcap::next() -> std::optional<std::pair<pcap_pkthdr*, u_char const*>> {
    pcap_pkthdr *h;
    u_char const* d;
    switch (checked(pcap_next_ex(pcap_.get(), &h, &d))) {
        case 1:
            return {{h,d}};
        default:
            return {};
    }
}

auto Pcap::selectable_fd() const -> int {
    return checked(pcap_get_selectable_fd(pcap_.get()));
}

auto Pcap::required_select_timeout() -> timeval const* {
    return pcap_get_required_select_timeout(pcap_.get());
}

auto Pcap::set_nonblock(int x) -> void {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_setnonblock(pcap_.get(), x, errbuf);
}

auto Pcap::get() -> pcap_t* {
    return pcap_.get();
}

auto Pcap::release() -> pcap_t* {
    return pcap_.release();
}

auto Pcap::fileno() const -> int {
    return checked(pcap_fileno(pcap_.get()));
}
