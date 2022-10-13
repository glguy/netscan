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
    PosixSpawnAttr& operator= (PosixSpawnAttr &&) = delete;
    PosixSpawnAttr& operator= (PosixSpawnAttr const&) = delete;
    
    void setflags(short flags);
    
    posix_spawnattr_t const* get() const;
};

#endif /* PosixSpawnAttr_hpp */
