#include <dlfcn.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../include/parallax_selftrust.h"

__attribute__((visibility("default")))
size_t parallax_sample_strlen(const char *s) { return strlen(s); }

__attribute__((visibility("default"), noinline))
int parallax_selftrust_hook_target(int x) { return x + 1; }

/* Packer needs a large executable segment; keep it out of .rodata so the
   marker below stays in its own page. */
__attribute__((section(".text.parallax"), used, aligned(4096)))
const unsigned char parallax_selftrust_blob[1048576] = { 0x50, 0x56, 0x4d, 0x34 };

static ParallaxSelfTrustApi *g_api;
static int g_helper_loaded;

__attribute__((visibility("default")))
void parallax_self_trust_init(ParallaxSelfTrustApi *api) {
    if (api && api->abi_version == PARALLAX_SELF_TRUST_ABI)
        g_api = api;
}

__attribute__((visibility("default")))
int parallax_run_selftrust(void) {
    void *page;
    long page_size;
    if (!g_api)
        return 0;
    page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0)
        return 0;

    /* Simulate JNI_OnLoad installing a Dobby-style inline hook. */
    g_api->begin(g_api->ctx);

    page = (void *)((uintptr_t)&parallax_selftrust_hook_target &
                    ~(uintptr_t)(page_size - 1));
    if (mprotect(page, (size_t)page_size,
                 PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        uint32_t nop = 0xd503201f;
        memcpy((void *)&parallax_selftrust_hook_target, &nop, sizeof(nop));
        __builtin___clear_cache((char *)&parallax_selftrust_hook_target,
                                (char *)&parallax_selftrust_hook_target +
                                    sizeof(nop));
        mprotect(page, (size_t)page_size, PROT_READ | PROT_EXEC);
    }
    g_api->grant_range(g_api->ctx, (void *)&parallax_selftrust_hook_target,
                       sizeof(uint32_t));

    g_helper_loaded =
        dlopen("libdobby_selftrust.so", RTLD_NOW | RTLD_LOCAL) != 0;
    g_api->trust_path(g_api->ctx, "libdobby_selftrust.so");

    g_api->end(g_api->ctx);
    return 1;
}

__attribute__((visibility("default")))
int parallax_selftrust_marker_changed(void) {
    uint32_t first;
    memcpy(&first, (const void *)&parallax_selftrust_hook_target,
           sizeof(first));
    return first == 0xd503201f;
}

__attribute__((visibility("default")))
int parallax_selftrust_helper_loaded(void) {
    return g_helper_loaded;
}

__attribute__((visibility("default"))) void parallax_init(void) {}
