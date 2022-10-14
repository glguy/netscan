//
//  PosixSpawnAttr.hpp
//  netscan
//
//  Created by Eric Mertens on 10/12/22.
//

#ifndef PosixSpawnAttr_hpp
#define PosixSpawnAttr_hpp

#include <spawn.h>

class PosixSpawnAttr final {
    posix_spawnattr_t _raw;

public:
    PosixSpawnAttr();
    ~PosixSpawnAttr();

    PosixSpawnAttr(PosixSpawnAttr const&) = delete;
    PosixSpawnAttr(PosixSpawnAttr &&rhs) = delete;
    auto operator= (PosixSpawnAttr &&) -> PosixSpawnAttr& = delete;
    auto operator= (PosixSpawnAttr const&) -> PosixSpawnAttr& = delete;
    
    auto setflags(short flags) -> void;
    auto get() const -> posix_spawnattr_t const*;
};

#endif /* PosixSpawnAttr_hpp */
