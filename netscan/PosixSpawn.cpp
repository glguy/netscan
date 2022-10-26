//
//  PosixSpawn.cpp
//  netscan
//
//  Created by Eric Mertens on 10/23/22.
//

#include "PosixSpawn.hpp"
#include <system_error>

auto PosixSpawnp
 (char const* path,
  PosixSpawnFileActions const& actions,
  PosixSpawnAttr const& attr,
  char * const* argv,
  char * const* envp
  ) -> pid_t {

     pid_t pid;
     auto res = posix_spawnp(&pid, path, actions.get(), attr.get(), argv, envp);
     if (0 != res) {
         throw std::system_error(res, std::generic_category(), "posix_spawnp");
     }
     return pid;
 }
