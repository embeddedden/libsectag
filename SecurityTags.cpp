#include "SecurityTags.h"
#include <cstdio>
#include <iostream>
#include <regex>

static ExitCode parseContextForTags(const std::string *context, std::vector<std::string> *tags);

ExitCode setTag(std::string fileName, std::string tagToAttach)
{
    std::cout << "We are in setTag, fileName = "<< fileName \
                << " tagToAttach = " << tagToAttach << std::endl;
    return ExitCode::OK;
}

ExitCode getTags(const std::string filePath, std::vector<std::string> tags)
{
    char * tagsString;
    // Some check is required here
    lgetfilecon(filePath.c_str(), &tagsString);
    std::cout << "Security context of " << filePath << " is:" << std::endl;
    std::cout << tagsString << std::endl;
    //const std::string tmpContext("unconfined_u:object_r:xdg_pictures_t:Tags: Private,Audio,Confid,Video picture");
    const std::string tmpContext(tagsString);
    //Parse the tag
    parseContextForTags(&tmpContext, &tags);
    tags.push_back(tagsString);
    return ExitCode::OK;
}

static ExitCode parseContextForTags(const std::string *context, std::vector<std::string> *tags)
{
    std::ignore = tags;
    std::string s(*context);
    std::smatch m;
    //naive regex, doesn't encounter maany cases
    //Works only for context like: user:role:type:Tags tag1,tag2,...,tagn<EOF>
    //FIXME: Tags\\s\\s works, why with two spaces while in context there is only one?
    std::regex tagsRegex("(?:(Tags:  ))|(\\b\\w+(?=\\,))|(\\b\\w+(?=$))");
    while(std::regex_search(s, m, tagsRegex))
    {
        for (auto x:m)
            std::cout << x << " ";
        std::cout << std::endl;
        s = m.suffix().str();
    }
    return ExitCode::OK;
}
