#include <SecurityTags.h>
#include <vector>
#include <string>

int main ()
{
    ExitCode res;
    initializeTags();
    res = addTag ("/home/guest/Pictures/picture", "NewTag");
    std::vector <std::string> a;
    getTags("/home/guest/Pictures/picture", a);
    res = removeTag ("/home/guest/Pictures/picture", "Video");

    getTags("/home/guest/Pictures/picture", a);
    res = removeTag ("/home/guest/Pictures/picture", "NewTag");
    getTags("/home/guest/Pictures/picture", a);
    res = removeTag ("/home/guest/Pictures/picture", "NewTa");
    getTags("/home/guest/Pictures/picture", a);

    if (res != ExitCode::OK)
        return 1;
    else
        return 0;
}
