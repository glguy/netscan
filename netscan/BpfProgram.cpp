//
//  BpfProgram.cpp
//  netscan
//
//  Created by Eric Mertens on 10/11/22.
//

#include "BpfProgram.hpp"

#include <new>

auto BpfProgram::operator=(BpfProgram &&rhs) noexcept -> BpfProgram& {
    if (&rhs != this) {
        this->~BpfProgram();
        new (this) BpfProgram(std::move(rhs));
    }
    return *this;
}

BpfProgram::BpfProgram(BpfProgram &&rhs) noexcept : bpf_program{} {
    std::swap<bpf_program>(*this, rhs);
};

BpfProgram::~BpfProgram() {
    pcap_freecode(this);
}
