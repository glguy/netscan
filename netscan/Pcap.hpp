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

#include <memory>
#include <tuple>
#include <optional>

class Pcap {
    struct PcapDelete { void operator()(pcap_t* p) const noexcept; };
    std::unique_ptr<pcap_t, PcapDelete> _pcap;
    
    explicit Pcap(pcap_t* p) noexcept;
    void checked(int res);

public:
    BpfProgram compile(char const* str, bool optimize, bpf_u_int32 netmask);
    void setfilter(BpfProgram* program);
    std::optional<std::pair<pcap_pkthdr*, u_char const*>> next();
    static Pcap open_live(char const* device, int snaplen, bool promisc, std::chrono::milliseconds timeout_ms);
};

#endif /* Pcap_hpp */
