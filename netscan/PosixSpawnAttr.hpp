//
//  PosixSpawnAttr.hpp
//  netscan
//
//  Created by Eric Mertens on 10/12/22.
//

#ifndef PosixSpawnAttr_hpp
#define PosixSpawnAttr_hpp

#include <spawn.h>

/// Attributes for PosixSpawn
/// @class PosixSpawnAttr
class PosixSpawnAttr final {
    posix_spawnattr_t _raw;

public:
    /// Constructs a default PosixSpawnAttr using posix\_spawnattr\_init
    PosixSpawnAttr();

    /// Deallocates a PosixSpawnAttr using posix\_spawnattr\_destroy
    ~PosixSpawnAttr();

    PosixSpawnAttr(PosixSpawnAttr const&) = delete;
    PosixSpawnAttr(PosixSpawnAttr &&rhs) = delete;
    auto operator= (PosixSpawnAttr &&) -> PosixSpawnAttr& = delete;
    auto operator= (PosixSpawnAttr const&) -> PosixSpawnAttr& = delete;

    /// Set the flags
    /// @param flags new flags
    /// @exception std::system\_error on invalid flags
    auto setflags(short flags) -> void;
    
    /// Get the flags
    /// @returns attribute flags
    /// @exception std::system\_error on internal error
    auto getflags() const -> short;
    
    /// Set the spawn-pgroup attribute
    /// @param pgroup process group
    /// @exception std::system\_error on internal error
    auto setpgroup(pid_t pgroup) -> void;
    
    /// Get the spawn-pgroup attribute
    /// @return process group (default 0)
    /// @exception std::system\_error on internal error
    auto getpgroup() const -> pid_t;
    
    /// Return pointer to underlying posix\_spawnattr\_t
    auto get() const -> posix_spawnattr_t const*;
};

#endif /* PosixSpawnAttr_hpp */
