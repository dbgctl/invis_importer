#include <Windows.h>

#include "invis_importer.h"

int main()
{

    II_CALL(LoadLibraryA, "user32.dll");
    II_CALL(MessageBoxA, 0ull, "hello", "success", 0ull);

    return 0;
}