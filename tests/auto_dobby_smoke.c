#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    void *handle;
    int (*hook)(void);
    int (*changed)(void);

    if (argc != 2)
        return 1;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 2;
    }
    hook = (int (*)(void))dlsym(handle, "parallax_auto_hook");
    changed = (int (*)(void))dlsym(handle, "parallax_auto_changed");
    if (!hook || !changed)
        return 3;
    if (!hook())
        return 4;
    if (!changed())
        return 5;
    sleep(13);
    if (!changed())
        return 6;
    puts("auto Dobby smoke: PASS");
    return 0;
}
