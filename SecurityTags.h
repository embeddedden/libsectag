#ifndef SECURITYTAGS_H
#define SECURITYTAGS_H
#include <iostream>
#include <string>
#include <selinux/selinux.h>
#include <vector>

//ExitCodes as temporary solution
enum class ExitCode {OK, FAILURE};

ExitCode initializeTags();

ExitCode addTag(std::string fileName, std::string tagToAttach);

ExitCode createNewTag(std::string newTag);

ExitCode removeTag(std::string fileName, std::string tagToRemove);

ExitCode getTags(const std::string, std::vector<std::string> &tags);

#endif //SECURITYTAGS_H
