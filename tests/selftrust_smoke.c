#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    void *handle;
    size_t (*fn)(const char *);
    int (*changed)(void);
    int (*helper_loaded)(void);
    int (*run_selftrust)(void);
    if (argc != 2) return 64;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    fn = (size_t (*)(const char *))dlsym(handle, "parallax_sample_strlen");
    changed = (int (*)(void))dlsym(handle, "parallax_selftrust_marker_changed");
    helper_loaded = (int (*)(void))dlsym(handle, "parallax_selftrust_helper_loaded");
    run_selftrust = (int (*)(void))dlsym(handle, "parallax_run_selftrust");
    if (!fn || !changed || !helper_loaded || !run_selftrust) return 2;
    if (!run_selftrust()) { fprintf(stderr, "self-trust API unavailable\n"); return 7; }
    if (fn("parallax") != 8) return 3;
    if (!changed()) { fprintf(stderr, "RO marker was not patched\n"); return 5; }
    if (!helper_loaded()) { fprintf(stderr, "dobby helper was not loaded\n"); return 6; }
    sleep(6);
    if (fn("watchdog") != 8) return 4;
    puts("self-trust ultra smoke: PASS");
    return 0;
}
