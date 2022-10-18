//
//  PosixSpawnFileActions.hpp
//  netscan
//
//  Created by Eric Mertens on 10/11/22.
//

#ifndef PosixSpawnFileActions_hpp
#define PosixSpawnFileActions_hpp

#include <spawn.h>

class PosixSpawnFileActions final {
    posix_spawn_file_actions_t _raw;

public:
    PosixSpawnFileActions();
    ~PosixSpawnFileActions();

    PosixSpawnFileActions(PosixSpawnFileActions const&) = delete;
    PosixSpawnFileActions(PosixSpawnFileActions &&rhs) = delete;
    auto operator= (PosixSpawnFileActions &&) -> PosixSpawnFileActions& = delete;
    auto operator= (PosixSpawnFileActions const&) -> PosixSpawnFileActions& = delete;

    auto addopen(int filedes, char const* path, int flags, mode_t mode) -> void;
    auto addclose(int filedes) -> void;
    auto get() const -> posix_spawn_file_actions_t const*;
};
#endif /* PosixSpawnFileActions_hpp */
