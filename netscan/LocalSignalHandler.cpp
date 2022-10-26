//
//  LocalSignalHandler.cpp
//  netscan
//
//  Created by Eric Mertens on 10/26/22.
//

#include "LocalSignalHandler.hpp"

LocalSignalHandler::LocalSignalHandler(int sig, struct sigaction const& act)
    : sig{sig}, previous{Sigaction(sig, act)} {}

LocalSignalHandler::~LocalSignalHandler() {
    Sigaction(sig, previous);
}
