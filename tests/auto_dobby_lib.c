#include <dlfcn.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

extern int parallax_dummy_helper(void);

__attribute__((visibility("default")))
size_t parallax_sample_strlen(const char *s) { return strlen(s); }

__attribute__((visibility("default")))
int parallax_auto_call_helper(void) { return parallax_dummy_helper(); }

__attribute__((section(".text.parallax"), used, aligned(4096)))
const unsigned char parallax_auto_blob[1048576] = { 0x50, 0x56, 0x4d, 0x34 };

static void *g_hook_target;

__attribute__((visibility("default")))
int parallax_auto_hook(void) {
    void *handle;
    void *target;
    void *page;
    long page_size;
    uint32_t nop = 0xd503201f;

    handle = dlopen("libdobby_selftrust.so", RTLD_NOW | RTLD_LOCAL);
    if (!handle)
        return 0;
    target = dlsym(handle, "parallax_dummy_helper");
    if (!target)
        return 0;
    page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0)
        return 0;
    page = (void *)((uintptr_t)target & ~(uintptr_t)(page_size - 1));
    if (mprotect(page, (size_t)page_size,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        return 0;
    memcpy(target, &nop, sizeof(nop));
    __builtin___clear_cache((char *)target, (char *)target + sizeof(nop));
    mprotect(page, (size_t)page_size, PROT_READ | PROT_EXEC);
    g_hook_target = target;
    return 1;
}

__attribute__((visibility("default")))
int parallax_auto_changed(void) {
    uint32_t first;
    if (!g_hook_target)
        return 0;
    memcpy(&first, g_hook_target, sizeof(first));
    return first == 0xd503201f;
}

__attribute__((visibility("default"))) void parallax_init(void) {}
