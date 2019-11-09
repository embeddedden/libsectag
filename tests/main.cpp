#include <SecurityTags.h>

int main ()
{
    ExitCode res;
    res = setTag ("longfilename", "tagname");
    if (res != ExitCode::OK)
        return 1;
    else
        return 0;
}
