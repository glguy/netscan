//
//  BpfProgram.hpp
//  netscan
//
//  Created by Eric Mertens on 10/11/22.
//

#ifndef BpfProgram_hpp
#define BpfProgram_hpp

#include <pcap/pcap.h>

class BpfProgram final {
    bpf_program program_;
public:
    BpfProgram() noexcept : program_{} {}
    BpfProgram(BpfProgram const&) = delete;
    BpfProgram(BpfProgram &&rhs) noexcept;
    auto operator=(BpfProgram const&) -> BpfProgram& = delete;
    auto operator=(BpfProgram &&rhs) noexcept -> BpfProgram&;
    ~BpfProgram();
    auto get() -> bpf_program*;
    auto get() const -> bpf_program const*;
};

#endif /* BpfProgram_hpp */
