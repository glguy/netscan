//
//  Pcap.hpp
//  netscan
//
//  Created by Eric Mertens on 10/10/22.
//

#ifndef Pcap_hpp
#define Pcap_hpp

#include "BpfProgram.hpp"

#include <chrono>
#include <concepts>
#include <memory>
#include <optional>
#include <tuple>

#include <pcap/pcap.h>

class Pcap {
    struct PcapDelete { auto operator()(pcap_t* p) const noexcept -> void; };
    std::unique_ptr<pcap_t, PcapDelete> _pcap;

    explicit Pcap(pcap_t* p) noexcept;
    auto checked(int res) const -> int;

public:
    static auto open_live(char const* device, int snaplen, bool promisc, std::chrono::milliseconds timeout_ms) -> Pcap;

    auto compile(char const* str, bool optimize, bpf_u_int32 netmask) -> BpfProgram;
    auto setfilter(BpfProgram* program) -> void;
    auto dispatch(int cnt, pcap_handler callback, u_char *user) -> int;
    auto loop(int cnt, pcap_handler callback, u_char *user) -> int;
    auto fileno() const -> int;
    auto next() -> std::optional<std::pair<pcap_pkthdr*, u_char const*>>;
    auto selectable_fd() -> int;
    auto required_select_timeout() -> timeval const*;
    auto set_nonblock(int x) -> void;

    auto get() -> pcap_t*;
    auto release() -> pcap_t*;

    template <std::invocable<pcap_pkthdr*, u_char const*> Callback>
    auto dispatch(int cnt, Callback const& callback) -> int {
        return dispatch(cnt, [](auto fp, auto header, auto data) {
            (*reinterpret_cast<Callback*>(fp))(header, data);
        }, const_cast<u_char*>(reinterpret_cast<u_char const*>(&callback)));
    }

    template <std::invocable<pcap_pkthdr*, u_char const*> Callback>
    auto loop(int cnt, Callback const& callback) -> int {
        return loop(cnt, [](auto fp, auto header, auto data) {
            (*reinterpret_cast<Callback*>(fp))(header, data);
        }, const_cast<u_char*>(reinterpret_cast<u_char const*>(&callback)));
    }
};

#endif /* Pcap_hpp */
