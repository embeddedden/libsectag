#include "SecurityTags.h"
#include <cstdio>
#include <iostream>
#include <regex>
#include <map>
#include <fstream>

static ExitCode parseContextForTags(const std::string *context, std::vector<std::string> *tags);
static ExitCode parseSetransLine(const std::string &setransLine);
std::map <std::string, std::string> tagsAndCategories;

//FIXME: make a class with a constructor?
ExitCode initializeTags()
{
    std::ifstream setransFile;
    std::string catString;
    //TODO: change to not fixed file name
    setransFile.open("/etc/selinux/refpolicy_mls/setrans.d/security_tags.conf",\
                     std::ifstream::in);

    std::getline(setransFile, catString);
    while (setransFile.good())
    {
        //std::cout << catString << std::endl;
        parseSetransLine(catString);
        std::getline(setransFile, catString);
    }
    //std::cout << "Tags and categories are:" << std::endl;
    for(auto it:tagsAndCategories) {}
    //    std::cout << it.first << "  " << it.second << std::endl;
    setransFile.close();
    return ExitCode::OK;
}

//FIXME: unoptimized and naive version
//function to parse setrans.conf lines, e.g. "c0=Private"
static ExitCode parseSetransLine(const std::string &setransLine)
{
    std::string s(setransLine);
    std::string tmpCat, tmpTag;
    std::regex regexCategory("^(c\\d+)(?=\\=)");
    std::regex regexTag("(?!\\=)\\w+(?=$)");
    //std::cout << "Category found" << std::endl;
    std::smatch m;
    if(std::regex_search(s, m, regexCategory))
    {
        tmpCat = *(m.begin());
        //std::cout << "'"<< tmpCat << "'"<< std::endl;
    }
    s = setransLine;
    std::cout << "Tag found" << std::endl;
    if(std::regex_search(s, m, regexTag))
    {
        tmpTag = *(m.begin());
        //std::cout << "'"<< tmpTag << "'"<< std::endl;
    }
    tagsAndCategories[tmpTag] = tmpCat;
    return ExitCode::OK;
}

ExitCode setTag(std::string fileName, std::string tagToAttach)
{
    std::regex contextFirstHalfRegex("(\\w+:\\w+:\\w+:)");
    std::smatch m;
    std::string newContext = "s2:c0";
    char * fileContext;
    std::cout << "We are in setTag, fileName = "<< fileName \
                << " tagToAttach = " << tagToAttach << std::endl;
    std::vector<std::string> currentTags, currentCategories;
    lgetfilecon(fileName.c_str(), &fileContext);
    std::string s(fileContext);
    std::cout << "[setTag]Security context of " << fileName << " is:" << std::endl;
    std::cout << fileContext << std::endl;
    if (std::regex_search(s, m, contextFirstHalfRegex))
    {
        std::cout << "First half " << m[0] << std::endl;
        newContext.insert(0, m[0]);
    }
    //get already attached tags
    getTags(fileName, currentTags);
    for (auto ct:currentTags)
    {
        currentCategories.push_back(tagsAndCategories[ct]);
        std::cout << tagsAndCategories[ct] <<"  "<<ct << std::endl;
        newContext.append(","+tagsAndCategories[ct]);
    }
    std::cout << "newContext: " << newContext << std::endl;
    return ExitCode::OK;
}

ExitCode getTags(const std::string filePath, std::vector<std::string> &tags)
{
    char * tagsString;
    tags.clear();
    // Some check is required here, need to free tagsString?
    lgetfilecon(filePath.c_str(), &tagsString);
    std::cout << "Security context of " << filePath << " is:" << std::endl;
    std::cout << tagsString << std::endl;
    //const std::string tmpContext("unconfined_u:object_r:xdg_pictures_t:Tags: Private,Audio,Confid,Video picture");
    const std::string tmpContext(tagsString);
    //Parse the tag
    parseContextForTags(&tmpContext, &tags);
    std::cout << "Tags are: " << std::endl;
    for (auto t:tags)
        std::cout <<"'"<< t <<"'"<< std::endl;
    return ExitCode::OK;
}

static ExitCode parseContextForTags(const std::string *context, std::vector<std::string> *tags)
{
//    std::ignore = tags;
    std::string s(*context);
    std::smatch m;
    //naive regex, doesn't encounter maany cases
    //Works only for context like: user:role:type:Tags tag1,tag2,...,tagn<EOF>
    //FIXME: Tags\\s\\s works, why with two spaces while in context there is only one?
    std::regex tagsRegex("(?:(Tags:\\s\\s))|(\\b\\w+(?=\\,))|(\\b\\w+(?=$))");
    while(std::regex_search(s, m, tagsRegex))
    {
#ifdef DEBUG
        for (auto x:m)
            std::cout << "'"<< x << "'";
        std::cout << std::endl;
#else
        tags->push_back(m[0]);
#endif //DEBUG
        s = m.suffix().str();
    }

    return ExitCode::OK;
}
