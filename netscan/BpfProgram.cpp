//
//  BpfProgram.cpp
//  netscan
//
//  Created by Eric Mertens on 10/11/22.
//

#include "BpfProgram.hpp"

#include <new>
#include <utility>

auto BpfProgram::operator=(BpfProgram &&rhs) noexcept -> BpfProgram& {
    if (&rhs != this) {
        this->~BpfProgram();
        new (this) BpfProgram(std::move(rhs));
    }
    return *this;
}

BpfProgram::BpfProgram(BpfProgram &&rhs) noexcept : program_{} {
    std::swap(program_, rhs.program_);
};

BpfProgram::~BpfProgram() {
    pcap_freecode(&program_);
}

auto BpfProgram::get() -> bpf_program* {
    return &program_;
}

auto BpfProgram::get() const -> bpf_program const* {
    return &program_;
}
