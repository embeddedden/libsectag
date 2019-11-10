#include "SecurityTags.h"
#include <cstdio>
#include <iostream>

ExitCode setTag(std::string fileName, std::string tagToAttach)
{
    std::cout << "We are in setTag, fileName = "<< fileName \
                << " tagToAttach = " << tagToAttach << std::endl;
    return ExitCode::OK;
}

ExitCode getTags(const std::string filePath, std::vector<std::string> tags)
{
    char * tagsString;
    lgetfilecon(filePath.c_str(), &tagsString);
    std::cout << "Security context of " << filePath << " is:" << std::endl;
    std::cout << tagsString << std::endl;
    tags.push_back(tagsString);
    return ExitCode::OK;
}
