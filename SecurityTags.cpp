#include "SecurityTags.h"

ExitCode setTag(std::string fileName, std::string tagToAttach)
{
    std::cout << "We are in setTag, fileName = "<< fileName \
                << " tagToAttach = " << tagToAttach << std::endl;
    return ExitCode::OK;
}


