#ifndef SECURITYTAGS_H
#define SECURITYTAGS_H
#include <iostream>
#include <string>


enum class ExitCode {OK, FAILURE};

ExitCode setTag(std::string fileName, std::string tagToAttach);



#endif //SECURITYTAGS_H
