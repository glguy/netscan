//
//  BpfProgram.cpp
//  netscan
//
//  Created by Eric Mertens on 10/11/22.
//

#include "BpfProgram.hpp"

BpfProgram& BpfProgram::operator=(BpfProgram &&rhs) noexcept {
    std::swap<bpf_program>(*this, rhs);
    return *this;
}

BpfProgram::BpfProgram(BpfProgram &&rhs) noexcept : bpf_program{} {
    std::swap<bpf_program>(*this, rhs);
};

BpfProgram::~BpfProgram() {
    pcap_freecode(this);
}
