//
//  PosixSpawn.hpp
//  netscan
//
//  Created by Eric Mertens on 10/23/22.
//

#ifndef PosixSpawn_hpp
#define PosixSpawn_hpp

#include <spawn.h>

#include "PosixSpawnAttr.hpp"
#include "PosixSpawnFileActions.hpp"

auto PosixSpawnp
 (char const* path,
  PosixSpawnFileActions const& actions,
  PosixSpawnAttr const& attr,
  char * const* argv,
  char * const* envp
  ) -> pid_t;

#endif /* PosixSpawn_hpp */
