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
    PosixSpawnFileActions& operator= (PosixSpawnFileActions &&) = delete;
    PosixSpawnFileActions& operator= (PosixSpawnFileActions const&) = delete;
    
    void addopen(int filedes, char const* path, int flags, mode_t mode);
    posix_spawn_file_actions_t const* get() const;
};
#endif /* PosixSpawnFileActions_hpp */
