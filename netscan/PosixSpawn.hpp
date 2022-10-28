//
//  PosixSpawn.hpp
//  netscan
//
//  Created by Eric Mertens on 10/23/22.
//

#ifndef PosixSpawn_hpp
#define PosixSpawn_hpp

#include <spawn.h>

class PosixSpawnFileActions;
class PosixSpawnAttr;

/// Spawn a process (possibly using search path)
/// @param path File path to executable
/// @param actions spawn actions
/// @param attr spawn attributes
/// @param argv null-terminated argument array
/// @param envp null-terminated environment array
auto PosixSpawnp
 (char const* path,
  PosixSpawnFileActions const& actions,
  PosixSpawnAttr const& attr,
  char * const* argv,
  char * const* envp
  ) -> pid_t;

/// Spawn a process (possibly using search path)
/// @param path File path to executable
/// @param actions spawn actions
/// @param attr spawn attributes
/// @param argv null-terminated argument array
/// @param envp null-terminated environment array
auto PosixSpawn
 (char const* path,
  PosixSpawnFileActions const& actions,
  PosixSpawnAttr const& attr,
  char * const* argv,
  char * const* envp
  ) -> pid_t;

#endif /* PosixSpawn_hpp */
