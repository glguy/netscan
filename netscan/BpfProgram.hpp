//
//  BpfProgram.hpp
//  netscan
//
//  Created by Eric Mertens on 10/11/22.
//

#ifndef BpfProgram_hpp
#define BpfProgram_hpp

#include <pcap/pcap.h>

#include <utility>

struct BpfProgram final : public bpf_program {
    BpfProgram() noexcept : bpf_program{} {}
    BpfProgram(BpfProgram const&) = delete;
    BpfProgram(BpfProgram &&rhs) noexcept;
    auto operator=(BpfProgram const&) -> BpfProgram& = delete;
    auto operator=(BpfProgram &&rhs) noexcept -> BpfProgram&;
    ~BpfProgram();
};

#endif /* BpfProgram_hpp */
