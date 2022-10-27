//
//  LocalSignalHandler.hpp
//  netscan
//
//  Created by Eric Mertens on 10/26/22.
//

#ifndef LocalSignalHandler_hpp
#define LocalSignalHandler_hpp

#include "MyLibC.hpp"

#include <csignal>

class LocalSignalHandler {
    int sig;
    struct sigaction previous;
public:
    LocalSignalHandler(int sig, struct sigaction const& act);
    LocalSignalHandler(LocalSignalHandler const&) = delete;
    LocalSignalHandler(LocalSignalHandler &&) = delete;
    auto operator=(LocalSignalHandler const&) -> LocalSignalHandler& = delete;
    auto operator=(LocalSignalHandler&&) -> LocalSignalHandler& = delete;
    ~LocalSignalHandler();
};

#endif /* LocalSignalHandler_hpp */
