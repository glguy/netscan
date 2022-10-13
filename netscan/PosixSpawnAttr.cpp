//
//  PosixSpawnAttrs.cpp
//  netscan
//
//  Created by Eric Mertens on 10/12/22.
//

#include "PosixSpawnAttr.hpp"

#include <system_error>

PosixSpawnAttr::PosixSpawnAttr() {
    auto res = posix_spawnattr_init(&_raw);
    if (0 != res) {
        throw std::system_error(errno, std::generic_category(), "posix_spawnattr_init");
    }
}

PosixSpawnAttr::~PosixSpawnAttr() {
    posix_spawnattr_destroy(&_raw);
}

posix_spawnattr_t const* PosixSpawnAttr::get() const {
    return &_raw;
}

void PosixSpawnAttr::setflags(short flags) {
    auto res = posix_spawnattr_setflags(&_raw, flags);
    if (0 != res) {
        throw std::system_error(errno, std::generic_category(), "posix_spawn_setflags");
    }
}
