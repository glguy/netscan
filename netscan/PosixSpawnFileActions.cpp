//
//  PosixSpawnFileActions.cpp
//  netscan
//
//  Created by Eric Mertens on 10/11/22.
//

#include "PosixSpawnFileActions.hpp"

#include <system_error>

PosixSpawnFileActions::PosixSpawnFileActions() {
    auto res = posix_spawn_file_actions_init(&_raw);
    if (0 != res) {
        throw std::system_error(errno, std::generic_category(), "posix_spawn_file_actions_init");
    }
}

PosixSpawnFileActions::~PosixSpawnFileActions() {
    posix_spawn_file_actions_destroy(&_raw);
}

auto PosixSpawnFileActions::addopen(int filedes, char const* path, int flags, mode_t mode) -> void {
    int res = posix_spawn_file_actions_addopen(&_raw, filedes, path, flags, mode);
    if (0 != res) {
        throw std::system_error(errno, std::generic_category(), "posix_spawn_file_actions_addopen");
    }
}

auto PosixSpawnFileActions::addclose(int filedes) -> void {
    int res = posix_spawn_file_actions_addclose(&_raw, filedes);
    if (0 != res) {
        throw std::system_error(errno, std::generic_category(), "posix_spawn_file_actions_addclose");
    }
}

auto PosixSpawnFileActions::get() const -> posix_spawn_file_actions_t const* {
    return &_raw;
}
