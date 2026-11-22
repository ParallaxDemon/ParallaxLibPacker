#ifndef PARALLAX_SELFTRUST_H
#define PARALLAX_SELFTRUST_H

/*
 * Parallax Self-Trust Ultra (optional, opt-in)
 *
 * The protected .so can install hooks, patch its own read-only image, and
 * load helper frameworks (Dobby/Frida gadget) without tripping the runtime
 * watchdog. Only code executing from the protected module's own executable
 * range can use this API; a foreign library calling it is silently ignored.
 *
 * The stub calls the exported callback below once, before the library's ELF
 * constructors run. Keep the symbol exported (default visibility):
 *
 *   __attribute__((visibility("default")))
 *   void parallax_self_trust_init(ParallaxSelfTrustApi *api)
 *   {
 *       g_parallax_api = api;
 *   }
 *
 * In JNI_OnLoad (or any later entry point), wrap mutations:
 *
 *   g_parallax_api->begin(g_parallax_api->ctx);
 *   install_dobby_hooks();
 *   g_parallax_api->end(g_parallax_api->ctx);
 *
 * begin() automatically seals after 8 watchdog ticks (~16 s) if end() is
 * forgotten. grant_all()/grant_slot()/grant_range() adopt an already applied
 * change immediately. trust_path() allows one helper path (basename or full
 * path) through the Frida/Dobby maps scan.
 *
 * If the callback is absent, the runtime still grants an automatic trusted
 * window while the library's ELF constructors run.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define PARALLAX_SELF_TRUST_ABI 1u

typedef struct ParallaxSelfTrustApi {
    unsigned int abi_version;
    unsigned int reserved;
    void *ctx;

    void (*begin)(void *ctx);
    void (*end)(void *ctx);
    void (*grant_all)(void *ctx);
    void (*grant_slot)(void *ctx, void *slot);
    void (*grant_range)(void *ctx, void *addr, unsigned long len);
    void (*trust_path)(void *ctx, const char *path);
} ParallaxSelfTrustApi;

typedef void (*ParallaxSelfTrustInit)(ParallaxSelfTrustApi *api);

#ifdef __cplusplus
}
#endif

#endif
