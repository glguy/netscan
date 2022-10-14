//
//  Pcap.hpp
//  netscan
//
//  Created by Eric Mertens on 10/10/22.
//

#ifndef Pcap_hpp
#define Pcap_hpp

#include "BpfProgram.hpp"

#include <pcap/pcap.h>

#include <concepts>
#include <memory>
#include <tuple>
#include <optional>
#include <functional>

class Pcap {
    struct PcapDelete { auto operator()(pcap_t* p) const noexcept -> void; };
    std::unique_ptr<pcap_t, PcapDelete> _pcap;
    
    explicit Pcap(pcap_t* p) noexcept;
    auto checked(int res) -> int;

public:
    auto compile(char const* str, bool optimize, bpf_u_int32 netmask) -> BpfProgram;
    auto setfilter(BpfProgram* program) -> void;
    auto next() -> std::optional<std::pair<pcap_pkthdr*, u_char const*>>;

    auto dispatch(int cnt, pcap_handler callback, u_char *user) -> int;

    template <std::invocable<pcap_pkthdr*, u_char const*> Callback>
    auto dispatch(int cnt, Callback const& callback) -> int {
        return dispatch(cnt, [](auto fp, auto header, auto data) {
            (*reinterpret_cast<Callback*>(fp))(header, data);
        }, const_cast<u_char*>(reinterpret_cast<u_char const*>(&callback)));
    }
    
    int loop(int cnt, pcap_handler callback, u_char *user);

    template <std::invocable<pcap_pkthdr*, u_char const*> Callback>
    auto loop(int cnt, Callback const& callback) -> int {
        return loop(cnt, [](auto fp, auto header, auto data) {
            (*reinterpret_cast<Callback*>(fp))(header, data);
        }, const_cast<u_char*>(reinterpret_cast<u_char const*>(&callback)));
    }

    auto breakloop() -> void;

    static auto open_live(char const* device, int snaplen, bool promisc, std::chrono::milliseconds timeout_ms) -> Pcap;
};

#endif /* Pcap_hpp */
