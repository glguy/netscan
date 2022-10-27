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

auto PosixSpawnAttr::get() const -> posix_spawnattr_t const* {
    return &_raw;
}

auto PosixSpawnAttr::setflags(short flags) -> void {
    auto res = posix_spawnattr_setflags(&_raw, flags);
    if (0 != res) {
        throw std::system_error(errno, std::generic_category(), "posix_spawnattr_setflags");
    }
}

auto PosixSpawnAttr::getflags() const -> short {
    short flags;
    auto e = posix_spawnattr_getflags(&_raw, &flags);
    if (0 != e) {
        throw std::system_error(errno, std::generic_category(), "posix_spawnattr_getflags");
    }
    return flags;
}

auto PosixSpawnAttr::setpgroup(pid_t pgroup) -> void {
    auto e = posix_spawnattr_setpgroup(&_raw, pgroup);
    if (0 != e) {
        throw std::system_error(e, std::generic_category(), "posix_spawnattr_setpgroup");
    }
}

auto PosixSpawnAttr::getpgroup() const -> pid_t {
    pid_t pgroup;
    auto e = posix_spawnattr_getpgroup(&_raw, &pgroup);
    if (0 != e) {
        throw std::system_error(e, std::generic_category(), "posix_spawnattr_getpgroup");
    }
    return pgroup;
}
