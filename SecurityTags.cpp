#include "SecurityTags.h"
#include <cstdio>
#include <iostream>
#include <regex>
#include <map>
#include <fstream>
#include <cstdio>

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

static ExitCode getContextFirstPart(const std::string *fileName, std::string &contextFirstHalf)
{
    std::regex contextFirstHalfRegex("(\\w+:\\w+:\\w+:)");
    std::smatch m;
    std::string newContext = "s2:c0"; //we use this value for Security Tags mechanism
    char * fileContext;
    //need to free it?
    lgetfilecon(fileName->c_str(), &fileContext);
    std::string s(fileContext);
    if (std::regex_search(s, m, contextFirstHalfRegex))
    {
        std::cout << "First half " << m[0] << std::endl;
        newContext.insert(0, m[0]);
        std::cout << "New context: " << newContext << std::endl;
    }
    contextFirstHalf.assign(newContext);

    return ExitCode::OK;
}

ExitCode addTag(std::string fileName, std::string tagToAttach)
{
    std::string newContext = "s2:c0";
    std::cout << "We are in addTag, fileName = "<< fileName \
                << " tagToAttach = " << tagToAttach << std::endl;
    std::vector<std::string> currentTags, currentCategories;

    getContextFirstPart(&fileName, newContext);
    //get already attached tags
    getTags(fileName, currentTags);
    for (auto ct:currentTags)
    {
        currentCategories.push_back(tagsAndCategories[ct]);
        std::cout << tagsAndCategories[ct] <<"  "<<ct << std::endl;
        newContext.append(","+tagsAndCategories[ct]);
    }
    if (std::find(currentTags.begin(), currentTags.end(), tagToAttach) != \
        currentTags.end())
    {
        std::cout << "Tag is already attached" << std::endl;
        return ExitCode::OK;
    }
    std::cout << "New context with existing tags: " << newContext << std::endl;
    //Look for a tag in a .conf file
    auto it = tagsAndCategories.find(tagToAttach);
    if (it != tagsAndCategories.end())
    {
        newContext.append(","+tagsAndCategories[tagToAttach]);
    }
    else
    {
        if (createNewTag(tagToAttach) == ExitCode::OK)
            newContext.append(","+tagsAndCategories[tagToAttach]);
        else {
            return ExitCode::FAILURE;
        }
    }
    std::cout << "New context with the new tag: " << newContext << std::endl;
    //Check exit code
    lsetfilecon(fileName.c_str(), newContext.c_str());
    return ExitCode::OK;
}

ExitCode removeTag(const std::string &fileName, const std::string &tagToRemove)
{
    std::string newContext = "s2:c0";
    std::cout << "We are in removeTag, fileName = "<< fileName \
                << " tagToRemove = " << tagToRemove << std::endl;
    std::vector<std::string> currentTags, currentCategories;
    getContextFirstPart(&fileName, newContext);
    //get already attached tags
    getTags(fileName, currentTags);
    for (auto ct:currentTags)
    {
        if (ct != tagToRemove)
        {
            currentCategories.push_back(tagsAndCategories[ct]);
            std::cout << tagsAndCategories[ct] <<"  "<<ct << std::endl;
            newContext.append(","+tagsAndCategories[ct]);
        }
    }
    std::cout << "New context without the tag: " << newContext << std::endl;
    //Check exit code
    lsetfilecon(fileName.c_str(), newContext.c_str());
    return ExitCode::OK;
}

ExitCode createNewTag(std::string newTag)
{
    std::ofstream setransFile;
    //should make mcstrans reread values with...d-bus?
    std::string restartMcstrans("systemctl restart mcstrans");
    //TODO: change to not fixed file name
    setransFile.open("/etc/selinux/refpolicy_mls/setrans.d/security_tags.conf",\
                     std::ofstream::out|std::ofstream::app);
    std::regex findNumberInCat("\\d+");
    std::smatch m;
    uint32_t biggestCategory=0;
    for (auto p:tagsAndCategories)
    {
        if (std::regex_search(p.second, m, findNumberInCat))
            //FIXME: can be enhanced (avoid two function calls)
            if (biggestCategory < std::stoul(m[0]))
                biggestCategory = std::stoi(m[0]);
    }
    std::cout << "The biggest category is: "<< biggestCategory<<std::endl;
    //TODO: should check correctnes of the newTag
    setransFile << "c" << biggestCategory+1 << "=" <<newTag<<std::endl;
    setransFile.close();
    //restart mcstrans
    FILE * pipe = popen(restartMcstrans.c_str(), "r");
    pclose(pipe);
    tagsAndCategories[newTag]="c"+std::to_string(biggestCategory+1);
    std::cout << "New Category - "<< tagsAndCategories[newTag] << std::endl;
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
