#include <SecurityTags.h>
#include <vector>
#include <string>

int main ()
{
    ExitCode res;
    initializeTags();
    res = setTag ("longfilename", "tagname");
    std::vector <std::string> a;
    getTags("/home/guest/Pictures/picture", a);
    if (res != ExitCode::OK)
        return 1;
    else
        return 0;
}
