/* amd64-linux.elf-so_main.c -- stub loader for compressed shared library

   This file is part of the UPX executable compressor.

   Copyright (C) Markus Franz Xaver Johannes Oberhumer
   Copyright (C) Laszlo Molnar
   Copyright (C) John F. Reiser
   All Rights Reserved.

   UPX and the UCL library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.
   If not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   Markus F.X.J. Oberhumer              Laszlo Molnar
   <markus@oberhumer.com>               <ezerotven+github@gmail.com>

   John F. Reiser
   <jreiser@users.sourceforge.net>
 */


#include "include/linux.h"
#include "../../parallax_vm4.h"

// Pprotect is mprotect, but page-aligned on the lo end (Linux requirement)
extern unsigned Pprotect(void *, size_t, unsigned);
extern void *Pmap(void *, size_t, unsigned, unsigned, int, size_t);
extern int Punmap(void *, size_t);
extern int Psync(void const *, size_t, unsigned);
extern size_t Pwrite(unsigned, void const *, size_t);
#define MS_SYNC 4
#define MFD_EXEC 0x10

extern void f_int3(int arg);

/* Raw syscall bridges from arm64-linux.elf-so_fold.S (no libc dependency). */
extern int parallax_fork(void);
extern int parallax_pipe2(int fds[2], int flags);
extern int parallax_dup3(int oldfd, int newfd, int flags);
extern int parallax_execve(char const *path, char *argv[], char *envp[]);
extern long parallax_wait4(int pid, int *status, int options, void *rusage);
extern long parallax_ppoll(void *fds, unsigned long nfds, void *timeout,
                           void *sigmask, size_t sigsetsize);
extern int parallax_kill(int pid, int sig);
extern long parallax_prctl(int op, unsigned long a2, unsigned long a3,
                           unsigned long a4, unsigned long a5);
extern long parallax_newfstatat(int dfd, char const *path, void *statbuf,
                                int flags);
#if defined(__aarch64__)
extern int exit_group(int);
#else
void my_bkpt(void const *, ...);
#endif

#ifndef DEBUG  //{
#define DEBUG 0
#endif  //}

#if !DEBUG //{
#define DPRINTF(fmt, args...) /*empty*/
#else  //}{
// DPRINTF is defined as an expression using "({ ... })"
// so that DPRINTF can be invoked inside an expression,
// and then followed by a comma to ignore the return value.
// The only complication is that percent and backslash
// must be doubled in the format string, because the format
// string is processed twice: once at compile-time by 'asm'
// to produce the assembled value, and once at runtime to use it.
#if defined(__powerpc__)  //{
#define DPRINTF(fmt, args...) ({ \
    char const *r_fmt; \
    asm("bl 0f; .string \"" fmt "\"; .balign 4; 0: mflr %0" \
/*out*/ : "=r"(r_fmt) \
/* in*/ : \
/*und*/ : "lr"); \
    dprintf(r_fmt, args); \
})
#elif defined(__x86_64) //}{
#define DPRINTF(fmt, args...) ({ \
    char const *r_fmt; \
    asm("call 0f; .asciz \"" fmt "\"; 0: pop %0" \
/*out*/ : "=r"(r_fmt) ); \
    dprintf(r_fmt, args); \
})
#elif defined(__aarch64__) //}{
#define DPRINTF(fmt, args...) ({ \
    char const *r_fmt; \
    asm("bl 0f; .string \"" fmt "\"; .balign 4; 0: mov %0,x30" \
/*out*/ : "=r"(r_fmt) \
/* in*/ : \
/*und*/ : "x30"); \
    dprintf(r_fmt, args); \
})
#elif defined(__riscv) //}{
#define DPRINTF(fmt, args...) ({ \
    char const *r_fmt; \
    asm("jal %0, 0f; .string \"" fmt "\"; .balign 4; 0:" \
/*out*/ : "=r"(r_fmt) \
/* in*/ : \
/*und*/ : ); \
    dprintf(r_fmt, args); \
})

#endif  //}

static int dprintf(char const *fmt, ...); // forward
#endif  /*}*/

#if DEBUG  //{
void dprint8(
    char const *fmt,
    void *a, void *b, void *c, void *d,
    void *e, void *f, void *g, void *h
)
{
    dprintf(fmt, a, b, c, d, e, f, g, h);
}
#endif  //}

/*************************************************************************
// configuration section
**************************************************************************/

// In order to make it much easier to move this code at runtime and execute
// it at an address different from it load address:  there must be no
// static data, and no string constants.

/*************************************************************************
// util
**************************************************************************/

#if 0  //{  save space
#define ERR_LAB error: exit(127);
#define err_exit(a) goto error
#else  //}{  save debugging time
#define ERR_LAB /*empty*/

static void
err_exit(int a)
{
    (void)a;  // debugging convenience
    DPRINTF("err_exit %%x\\n", a);
#if defined(__aarch64__)
    exit_group(a ? (a & 0xff) : 127);  // nonzero loader-specific exit; never mask errors as success
#else
    my_bkpt((void const *)(long)a);
    exit(127);
#endif
    for (;;) {
    }
}
#endif  //}

/*************************************************************************
// "file" util
**************************************************************************/

typedef struct {
    size_t size;  // must be first to match size[0] uncompressed size
    char *buf;
} Extent;


static void
parallax_secure_zero(void *address, size_t length)
{
    volatile unsigned char *p = (volatile unsigned char *)address;
    while (length-- != 0)
        *p++ = 0;
}

static void
xread(Extent *x, char *buf, size_t count)
{
    DPRINTF("xread x.size=%%x  x.buf=%%p  buf=%%p  count=%%x\\n",
        x->size, x->buf, buf, count);
    char *p=x->buf, *q=buf;
    size_t j;
    if (x->size < count) {
        err_exit(8);
    }
    for (j = count; 0!=j--; ++p, ++q) {
        *q = *p;
    }
    x->buf  += count;
    x->size -= count;
    DPRINTF("yread x.size=%%x  x.buf=%%p  buf=%%p  count=%%x\\n",
        x->size, x->buf, buf, count);
}

/*************************************************************************
// UPX & NRV stuff
**************************************************************************/

int f_expand( // .globl in $(ARCH)-linux.elf-so_fold.S
    nrv_byte const *binfo, nrv_byte *dst, size_t *dstlen);

static void
unpackExtent(
    Extent *const xi,  // input includes struct b_info
    Extent *const xo,  // output
    unsigned const pvm_program_id
)
{
    while (xo->size) {
        DPRINTF("unpackExtent xi=(%%p %%p)  xo=(%%p %%p)\\n",
            xi->size, xi->buf, xo->size, xo->buf);
        struct b_info h;
        //   Note: if h.sz_unc == h.sz_cpr then the block was not
        //   compressible and is stored in its uncompressed form.

        // Read and check block sizes.
        xread(xi, (char *)&h, sizeof(h));
        DPRINTF("h.sz_unc=%%x  h.sz_cpr=%%x  h.b_method=%%x\\n",
            h.sz_unc, h.sz_cpr, h.b_method);
        if (h.sz_unc == 0) {                     // uncompressed size 0 -> EOF
            if (h.sz_cpr != UPX_MAGIC_LE32)      // h.sz_cpr must be h->magic
                err_exit(2);
            if (xi->size != 0)                 // all bytes must be written
                err_exit(3);
            break;
        }
        if (h.sz_cpr <= 0) {
            err_exit(4);
ERR_LAB
        }
        if (h.sz_cpr > h.sz_unc
        ||  h.sz_unc > xo->size ) {
            err_exit(5);
        }

#if defined(__aarch64__)
        unsigned char *const pvm_block_start = (unsigned char *)xi->buf;
        size_t const pvm_block_size = h.sz_cpr;
        /*
         * PVM4 is opt-in per block via b_unused. The disk copy remains in
         * diversified form; only the block currently being consumed is
         * decoded inside the already-private side buffer. Blocks without a
         * tag (for example an incompressible literal block) are accepted as
         * ordinary UPX blocks.
         */
        if (parallax_vm4_is_tag(h.b_unused)) {
            if (pvm_program_id == 0 || h.sz_cpr == 0) {
                err_exit(9);
            }
            parallax_vm4_decode(
                    (unsigned char *)xi->buf,
                    h.sz_cpr,
                    pvm_program_id,
                    h.sz_unc,
                    h.sz_cpr,
                    h.b_method,
                    h.b_unused);

            /*
             * f_expand() receives the b_info immediately before xi->buf.
             * Clear only the private copy's transport marker so legacy
             * decompressor code never interprets it as compression metadata.
             */
            ((struct b_info *)(void *)(xi->buf - sizeof(h)))->b_unused = 0;
        }
#else
        (void)pvm_program_id;
#endif
        // Now we have:
        //   assert(h.sz_cpr <= h.sz_unc);
        //   assert(h.sz_unc > 0 && h.sz_unc <= blocksize);
        //   assert(h.sz_cpr > 0 && h.sz_cpr <= blocksize);

        if (h.sz_cpr < h.sz_unc) { // Decompress block
            size_t out_len = h.sz_unc;  // EOF for lzma
            int const j = f_expand((unsigned char *)xi->buf - sizeof(h),
                (unsigned char *)xo->buf, &out_len);
            if (j != 0 || out_len != (nrv_uint)h.sz_unc) {
                DPRINTF("  j=%%x  out_len=%%x  &h=%%p\\n", j, out_len, &h);
                err_exit(7);
            }
#if defined(__aarch64__)
            parallax_secure_zero(pvm_block_start, pvm_block_size);
#endif
            xi->buf  += h.sz_cpr;
            xi->size -= h.sz_cpr;
        }
        else { // copy literal block
            DPRINTF("  copy %%p  %%p  %%p\\n", xi->buf, xo->buf, h.sz_cpr);
            xi->size += sizeof(h);  // xread(xi, &h, sizeof(h)) was a peek
            xread(xi, xo->buf, h.sz_cpr);
        }
        xo->buf  += h.sz_unc;
        xo->size -= h.sz_unc;
    }
}

#if defined(__x86_64) //}{
#define addr_string(string) ({ \
    char const *str; \
    asm("call 0f; .asciz \"" string "\"; 0: pop %0" \
/*out*/ : "=r"(str) ); \
    str; \
})
#elif defined(__aarch64__) //}{
#define addr_string(string) ({ \
    char const *str; \
    asm("bl 0f; .string \"" string "\"; .balign 4; 0: mov %0,x30" \
/*out*/ : "=r"(str) \
/* in*/ : \
/*und*/ : "x30"); \
    str; \
})
#elif defined(__riscv) //}{
#define addr_string(string) ({ \
    char const *str; \
    asm("jal %0,0f; .string \"" string "\"; .balign 4; 0:" \
/*out*/ : "=r"(str) \
/* in*/ : \
/*und*/ : ); \
    str; \
})
#else  //}{
       error;
#endif  //}

extern int memfd_create(const char *name, unsigned int flags);

#define ElfW(sym) Elf64_ ## sym

#define nullptr (void *)0

#if defined(__aarch64__)

/*
 * Conservative client-side hook guard for Android ARM64 shared libraries.
 *
 * Compatibility rules:
 *   - no network access or server dependency;
 *   - no port probing;
 *   - root/Magisk alone is not a failure signal;
 *   - only strong hook/tracer evidence is fatal;
 *   - checks use /proc plus already-relocated ELF metadata and do not patch GOT.
 */

#define PARALLAX_PT_DYNAMIC 2
#define PARALLAX_DT_NULL 0
#define PARALLAX_DT_PLTRELSZ 2
#define PARALLAX_DT_STRTAB 5
#define PARALLAX_DT_SYMTAB 6
#define PARALLAX_DT_RELA 7
#define PARALLAX_DT_RELASZ 8
#define PARALLAX_DT_NEEDED 1
#define PARALLAX_DT_HASH 4
#define PARALLAX_DT_RELAENT 9
#define PARALLAX_DT_PLTREL 20
#define PARALLAX_DT_JMPREL 23
#define PARALLAX_DT_GNU_HASH 0x6ffffef5
#define PARALLAX_R_AARCH64_GLOB_DAT 1025u
#define PARALLAX_R_AARCH64_JUMP_SLOT 1026u

typedef struct {
    Elf64_Sxword d_tag;
    union {
        Elf64_Xword d_val;
        Elf64_Addr d_ptr;
    } d_un;
} ParallaxDyn64;

typedef struct {
    Elf64_Addr r_offset;
    Elf64_Xword r_info;
    Elf64_Sxword r_addend;
} ParallaxRela64;

typedef struct {
    Elf64_Word st_name;
    unsigned char st_info;
    unsigned char st_other;
    Elf64_Half st_shndx;
    Elf64_Addr st_value;
    Elf64_Xword st_size;
} ParallaxSym64;

/*
 * Parallax Watchdog state.
 *
 * The runtime stub is folded into a position-independent loader region and
 * must not contain writable static data, so all mutable watchdog state lives
 * in an anonymous mmap page allocated at load time. A POSIX timer delivers a
 * real-time signal; the signal payload carries the state pointer (siginfo
 * si_value at offset 24 on AArch64), so the handler needs no global anchor.
 */

#define PARALLAX_WD_MAGIC 0x50584c47u /* "PXLG" */
#define PARALLAX_WD_SIGNAL 45
#define PARALLAX_WD_INTERVAL_SEC 1
#define PARALLAX_WD_MAX_GUARDS 2048
#define PARALLAX_WD_MAX_SEGMENTS 32
#define PARALLAX_WD_MAX_SEGMENT_BYTES (8u * 1024u * 1024u)
#define PARALLAX_WD_PROLOGUE_BYTES 32
#define PARALLAX_WD_MAX_CODE_GUARDS 32
#define PARALLAX_WD_CODE_GUARD_BYTES 128u
#define PARALLAX_WD_MAX_TRUSTED_PATHS 8
#define PARALLAX_WD_TRUSTED_PATH_BYTES 128
#define PARALLAX_SELF_TRUST_ABI 1u
#define PARALLAX_SELF_TRUST_TICKS 8u
#define PARALLAX_STARTUP_TRUST_TICKS 5u

#define PARALLAX_NOINLINE __attribute__((noinline))

#define PARALLAX_OWNER_OTHER 0
#define PARALLAX_OWNER_LIBC 1
#define PARALLAX_OWNER_CURL 2
#define PARALLAX_OWNER_SSL 3
#define PARALLAX_GUARD_DEFERRED 0
#define PARALLAX_GUARD_FROZEN 1

typedef struct {
    Elf64_Addr slot;
    Elf64_Addr target;
    unsigned char prologue[PARALLAX_WD_PROLOGUE_BYTES];
    unsigned char owner;
    unsigned char state;
    unsigned char is_func;
    unsigned char reserved;
} ParallaxGuard64;

typedef struct {
    Elf64_Addr lo;
    Elf64_Addr hi;
    uint64_t hash;
} ParallaxSegment64;

typedef struct {
    Elf64_Addr addr;
    uint64_t hash;
    uint32_t len;
    uint32_t reserved;
} ParallaxCodeGuard64;

typedef struct {
    uint32_t abi_version;
    uint32_t reserved;
    void *ctx;
    void (*begin)(void *ctx);
    void (*end)(void *ctx);
    void (*grant_all)(void *ctx);
    void (*grant_slot)(void *ctx, void *slot);
    void (*grant_range)(void *ctx, void *addr, unsigned long len);
    void (*trust_path)(void *ctx, char const *path);
} ParallaxSelfTrustApi;

typedef struct {
    uint32_t magic;
    uint32_t n_guards;
    uint32_t n_segments;
    uint32_t n_code_guards;
    uint32_t timer_started;
    uint32_t tick;
    uint32_t self_trust;
    uint32_t self_trust_budget;
    uint32_t n_trusted_paths;
    uint32_t self_trust_ready;
    void (*self_trust_init)(ParallaxSelfTrustApi *);
    ParallaxSelfTrustApi api;
    char trusted_paths[PARALLAX_WD_MAX_TRUSTED_PATHS][PARALLAX_WD_TRUSTED_PATH_BYTES];
    Elf64_Addr module_lo;
    Elf64_Addr module_hi;
    Elf64_Addr libc_lo;
    Elf64_Addr libc_hi;
    Elf64_Addr curl_lo;
    Elf64_Addr curl_hi;
    Elf64_Addr ssl_lo;
    Elf64_Addr ssl_hi;
    int timer_id;
    uint32_t reserved1;
    ParallaxGuard64 guards[PARALLAX_WD_MAX_GUARDS];
    ParallaxSegment64 segments[PARALLAX_WD_MAX_SEGMENTS];
    ParallaxCodeGuard64 code_guards[PARALLAX_WD_MAX_CODE_GUARDS];
} ParallaxWatchdogState;

static PARALLAX_NOINLINE int parallax_runtime_precheck(
        Elf64_Addr *libc_lo,
        Elf64_Addr *libc_hi,
        Elf64_Addr *curl_lo,
        Elf64_Addr *curl_hi,
        Elf64_Addr *ssl_lo,
        Elf64_Addr *ssl_hi);

typedef struct {
    void (*handler)(int, void *, void *);
    unsigned long flags;
    void (*restorer)(void);
    unsigned long mask;
} ParallaxKernelSigaction;

typedef struct {
    void *value;
    int signo;
    int notify;
    int pad[12];
} ParallaxSigevent;

typedef struct {
    long sec;
    long nsec;
} ParallaxTimespec64;

typedef struct {
    ParallaxTimespec64 interval;
    ParallaxTimespec64 value;
} ParallaxItimerspec64;

extern int rt_sigaction(int, void const *, void *, size_t);
extern int timer_create(int, void const *, int *);
extern int timer_settime(int, int, void const *, void *);
extern int timer_delete(int);
extern int exit_group(int);
extern void *mmap(void *, size_t, int, int, int, off_t);

static unsigned char parallax_ascii_lower(unsigned char c) {
    if (c >= 'A' && c <= 'Z')
        return (unsigned char)(c + ('a' - 'A'));
    return c;
}

static unsigned char parallax_token_byte(uint64_t lo, uint64_t hi, unsigned index) {
    if (index < 8u)
        return (unsigned char)((lo >> (index * 8u)) & 0xffu);
    index -= 8u;
    return (unsigned char)((hi >> (index * 8u)) & 0xffu);
}

static long parallax_find_token_ci(
        char const *buf,
        size_t len,
        uint64_t lo,
        uint64_t hi,
        unsigned token_len) {
    size_t i;
    if (token_len == 0 || token_len > 16u || len < token_len)
        return -1;
    for (i = 0; i + token_len <= len; ++i) {
        unsigned j;
        for (j = 0; j < token_len; ++j) {
            unsigned char a = parallax_ascii_lower((unsigned char)buf[i + j]);
            unsigned char b = parallax_ascii_lower(parallax_token_byte(lo, hi, j));
            if (a != b)
                break;
        }
        if (j == token_len)
            return (long)i;
    }
    return -1;
}

static int parallax_has_token_ci(
        char const *buf,
        size_t len,
        uint64_t lo,
        uint64_t hi,
        unsigned token_len) {
    return 0 <= parallax_find_token_ci(buf, len, lo, hi, token_len);
}

static void parallax_unpack_path(
        char *out,
        unsigned len,
        uint64_t a,
        uint64_t b,
        uint64_t d) {
    unsigned i;
    for (i = 0; i < len; ++i) {
        uint64_t word = i < 8u ? a : (i < 16u ? b : d);
        unsigned shift = (i & 7u) * 8u;
        out[i] = (char)((word >> shift) & 0xffu);
    }
    out[len] = 0;
}

static __attribute__((unused)) int parallax_ld_preload_active(void) {
    char path[19];
    char buf[4096 + 16];
    size_t carry = 0;
    int fd;

    parallax_unpack_path(
            path, 18,
            0x65732f636f72702full,
            0x7269766e652f666cull,
            0x0000000000006e6full);
    fd = openat(0, path, O_RDONLY, 0);
    if (fd < 0)
        return 0; /* compatibility: unreadable /proc is not by itself an attack */

    for (;;) {
        ssize_t got = read(fd, buf + carry, 4096);
        size_t total;
        long at;
        if (got <= 0)
            break;
        total = carry + (size_t)got;
        at = parallax_find_token_ci(
                buf, total,
                0x4f4c4552505f444cull,
                0x00000000003d4441ull,
                11u);
        if (0 <= at && (size_t)at + 11u < total && buf[at + 11] != 0) {
            close(fd);
            return 1;
        }

        carry = total < 16u ? total : 16u;
        {
            size_t i;
            for (i = 0; i < carry; ++i)
                buf[i] = buf[total - carry + i];
        }
    }
    close(fd);
    return 0;
}

static PARALLAX_NOINLINE __attribute__((unused)) int parallax_tracer_attached(void) {
    char path[18];
    char buf[4096];
    ssize_t got;
    int fd;
    long at;
    size_t i;

    parallax_unpack_path(
            path, 17,
            0x65732f636f72702full,
            0x75746174732f666cull,
            0x0000000000000073ull);
    fd = openat(0, path, O_RDONLY, 0);
    if (fd < 0)
        return 0;
    got = read(fd, buf, sizeof(buf));
    close(fd);
    if (got <= 0)
        return 0;

    at = parallax_find_token_ci(
            buf, (size_t)got,
            0x6950726563617254ull,
            0x0000000000003a64ull,
            10u);
    if (at < 0)
        return 0;
    i = (size_t)at + 10u;
    while (i < (size_t)got && (buf[i] == ' ' || buf[i] == '\t'))
        ++i;
    return i < (size_t)got && buf[i] >= '1' && buf[i] <= '9';
}

static int parallax_parse_hex_range(
        char const *line,
        size_t len,
        Elf64_Addr *lo,
        Elf64_Addr *hi) {
    size_t i = 0;
    Elf64_Addr a = 0, b = 0;
    int seen = 0;

    while (i < len && line[i] != '-') {
        unsigned v;
        char c = line[i++];
        if (c >= '0' && c <= '9')
            v = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f')
            v = 10u + (unsigned)(c - 'a');
        else if (c >= 'A' && c <= 'F')
            v = 10u + (unsigned)(c - 'A');
        else
            return 0;
        if (a > (~(Elf64_Addr)0 >> 4))
            return 0;
        a = (a << 4) | v;
        seen = 1;
    }
    if (!seen || i >= len || line[i++] != '-')
        return 0;

    seen = 0;
    while (i < len && line[i] != ' ') {
        unsigned v;
        char c = line[i++];
        if (c >= '0' && c <= '9')
            v = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f')
            v = 10u + (unsigned)(c - 'a');
        else if (c >= 'A' && c <= 'F')
            v = 10u + (unsigned)(c - 'A');
        else
            return 0;
        if (b > (~(Elf64_Addr)0 >> 4))
            return 0;
        b = (b << 4) | v;
        seen = 1;
    }
    if (!seen || b <= a)
        return 0;
    *lo = a;
    *hi = b;
    return 1;
}

/* Native pin verifies the APK Signing Block, independent of PackageManager. */
#if defined(__aarch64__)
#include "parallax_apk_cert_pin.h"
#endif

static void parallax_unpack_path5(
        char *out,
        unsigned len,
        uint64_t a,
        uint64_t b,
        uint64_t d,
        uint64_t e,
        uint64_t f) {
    unsigned i;
    for (i = 0; i < len; ++i) {
        uint64_t word = i < 8u ? a : (i < 16u ? b : (i < 24u ? d : (i < 32u ? e : f)));
        unsigned shift = (i & 7u) * 8u;
        out[i] = (char)((word >> shift) & 0xffu);
    }
    out[len] = 0;
}

static int parallax_read_file(char const *path, char *buf, size_t cap) {
    int fd = openat(0, path, O_RDONLY, 0);
    ssize_t got;
    if (fd < 0 || cap == 0)
        return -1;
    got = read(fd, buf, cap - 1u);
    close(fd);
    if (got < 0)
        return -1;
    buf[got] = 0;
    return (int)got;
}

static int parallax_open_packed(unsigned len, uint64_t a, uint64_t b, uint64_t d) {
    char path[25];
    int fd;
    parallax_unpack_path(path, len, a, b, d);
    fd = openat(0, path, O_RDONLY, 0);
    if (fd < 0)
        return 0;
    close(fd);
    return 1;
}

static int parallax_open_packed5(
        unsigned len,
        uint64_t a, uint64_t b, uint64_t d, uint64_t e, uint64_t f) {
    char path[40];
    int fd;
    parallax_unpack_path5(path, len, a, b, d, e, f);
    fd = openat(0, path, O_RDONLY, 0);
    if (fd < 0)
        return 0;
    close(fd);
    return 1;
}

/* Existence probe for paths whose parent is searchable. Do NOT treat
   EACCES as existence: an untrusted app gets EACCES for a missing
   /data/local/su too, because the parent directory is hidden. */
static int parallax_path_present(
        unsigned len,
        uint64_t a, uint64_t b, uint64_t d) {
    char path[25];
    char st[256];
    long r;
    parallax_unpack_path(path, len, a, b, d);
    r = parallax_newfstatat(-100 /* AT_FDCWD */, path, st, 0);
    return r == 0;
}

/* Fork+exec /system/bin/getprop with raw syscalls only. The child runs
   nothing but close/dup3/execve; the parent reads the dump through a pipe.
   Any failure (SELinux, seccomp, missing binary) is a silent "no data",
   never a crash, so ordinary devices keep working. */
static int parallax_getprop_dump(char *buf, size_t cap) {
    struct PollFd {
        int fd;
        short events;
        short revents;
    };
    struct PollTs {
        long sec;
        long nsec;
    };
    int fds[2];
    int pid;
    ssize_t got;
    size_t total = 0;
    unsigned idle = 0;
    int hung = 0;
    int truncated = 0;
    char path[20];
    char *argv[2];
    char *envp[1];

    if (parallax_pipe2(fds, 0) != 0)
        return 0;
    pid = parallax_fork();
    if (pid == 0) {
        close(fds[0]);
        if (fds[1] != 1) {
            parallax_dup3(fds[1], 1, 0);
            close(fds[1]);
        }
        parallax_unpack_path(
                path, 19,
                0x2f6d65747379732full,
                0x707465672f6e6962ull,
                0x0000000000706f72ull);
        argv[0] = path;
        argv[1] = 0;
        envp[0] = 0;
        parallax_execve(path, argv, envp);
        exit_group(127);
    }
    close(fds[1]);
    if (pid < 0) {
        close(fds[0]);
        return 0;
    }
    /* A wedged property service must not hang the host app. Eight empty
       200 ms slices (1.6 s) with no data means "give up and skip". */
    while (total + 1u < cap) {
        struct PollFd pfd;
        struct PollTs ts;
        long r;
        pfd.fd = fds[0];
        pfd.events = 1; /* POLLIN */
        pfd.revents = 0;
        ts.sec = 0;
        ts.nsec = 200000000L;
        r = parallax_ppoll(&pfd, 1, &ts, 0, 0);
        if (r < 0) {
            if (r == -4) /* EINTR */
                continue;
            break;
        }
        if (r == 0) {
            if (++idle >= 8u) {
                hung = 1;
                break;
            }
            continue;
        }
        idle = 0;
        got = read(fds[0], buf + total, cap - 1u - total);
        if (got < 0) {
            if (got == -4) /* EINTR */
                continue;
            break;
        }
        if (got == 0)
            break;
        total += (size_t)got;
    }
    if (total + 1u >= cap)
        truncated = 1;
    close(fds[0]);
    if (hung)
        parallax_kill(pid, 9);
    for (;;) {
        int status;
        long wr = parallax_wait4(pid, &status, 0, 0);
        if (wr != -4)
            break;
    }
    buf[total] = 0;
    /* A truncated or wedged dump could hide the boot/security keys behind
       property flooding or a stalled property service: fail closed. */
    if (truncated || hung)
        return -2;
    return total != 0;
}

static int parallax_token_at_ci(
        char const *buf,
        size_t len,
        size_t at,
        uint64_t lo,
        uint64_t hi,
        unsigned token_len) {
    unsigned j;
    if (at > len || len - at < token_len)
        return 0;
    for (j = 0; j < token_len; ++j) {
        unsigned char a = parallax_ascii_lower((unsigned char)buf[at + j]);
        unsigned char b = parallax_ascii_lower(parallax_token_byte(lo, hi, j));
        if (a != b)
            return 0;
    }
    return 1;
}

/* Match "[<key>]: [<value>]" exactly, so unrelated properties whose value
   happens to be "disabled" (for example [ro.boot.atm]) are ignored. */
static int parallax_prop_has(
        char const *buf,
        size_t len,
        uint64_t key_lo,
        uint64_t key_hi,
        unsigned key_len,
        uint64_t val_lo,
        uint64_t val_hi,
        unsigned val_len) {
    size_t search = 0;
    while (search < len) {
        long rel = parallax_find_token_ci(
                buf + search, len - search, key_lo, key_hi, key_len);
        size_t at;
        if (rel < 0)
            return 0;
        at = search + (size_t)rel;
        if (parallax_token_at_ci(
                    buf, len, at + key_len, val_lo, val_hi, val_len))
            return 1;
        search = at + key_len;
    }
    return 0;
}

static PARALLAX_NOINLINE int parallax_getprop_bad(void) {
    enum { CAP = 256u * 1024u };
    char *dump = (char *)mmap(
            0, CAP, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    size_t n = 0;
    int bad = 0;
    int r;

    if (dump == (char *)-1)
        return 0;
    r = parallax_getprop_dump(dump, CAP);
    if (r < 0) {
        /* Truncated/timed-out dump: treat as hostile instead of skipping. */
        Punmap(dump, CAP);
        return 1;
    }
    if (r > 0) {
        while (n + 1u < CAP && dump[n] != 0)
            ++n;
        bad = parallax_prop_has(
                      dump, n,
                      0x74617473746f6f62ull, 0x0000000000005d65ull, 10u,
                      0x676e61726f5b203aull, 0x0000000000005d65ull, 10u) ||
              parallax_prop_has(
                      dump, n,
                      0x74617473746f6f62ull, 0x0000000000005d65ull, 10u,
                      0x6f6c6c65795b203aull, 0x0000000000005d77ull, 10u) ||
              parallax_prop_has(
                      dump, n,
                      0x74617473746f6f62ull, 0x0000000000005d65ull, 10u,
                      0x005d6465725b203aull, 0, 7u) ||
              parallax_prop_has(
                      dump, n,
                      0x6f6d797469726576ull, 0x00000000005d6564ull, 11u,
                      0x62617369645b203aull, 0x000000005d64656cull, 12u) ||
              parallax_prop_has(
                      dump, n,
                      0x61742e646c697562ull, 0x00000000005d7367ull, 11u,
                      0x2d747365745b203aull, 0x0000005d7379656bull, 13u) ||
              parallax_prop_has(
                      dump, n,
                      0x61742e646c697562ull, 0x00000000005d7367ull, 11u,
                      0x6b2d7665645b203aull, 0x000000005d737965ull, 12u) ||
              parallax_prop_has(
                      dump, n,
                      0x79742e646c697562ull, 0x00000000005d6570ull, 11u,
                      0x64726573755b203aull, 0x0000005d67756265ull, 13u) ||
              parallax_prop_has(
                      dump, n,
                      0x6f6c2e6873616c66ull, 0x0000005d64656b63ull, 13u,
                      0x0000005d305b203aull, 0, 5u) ||
              parallax_prop_has(
                      dump, n,
                      0x6c65732e746f6f62ull, 0x0000005d78756e69ull, 13u,
                      0x696d7265705b203aull, 0x00005d6576697373ull, 14u) ||
              parallax_prop_has(
                      dump, n,
                      0x67756265642e6f72ull, 0x00005d656c626167ull, 14u,
                      0x0000005d315b203aull, 0, 5u) ||
              parallax_prop_has(
                      dump, n,
                      0x72756365732e6f72ull, 0x0000000000005d65ull, 10u,
                      0x0000005d305b203aull, 0, 5u);
    }
    Punmap(dump, CAP);
    return bad;
}

static PARALLAX_NOINLINE int parallax_selinux_bad(void) {
    char path[24];
    char buf[16];
    int got;
    parallax_unpack_path(
            path, 23,
            0x2f73662f7379732full,
            0x2f78756e696c6573ull,
            0x006563726f666e65ull);
    got = parallax_read_file(path, buf, sizeof(buf));
    return got > 0 && buf[0] == '0';
}

static PARALLAX_NOINLINE int parallax_context_bad(void) {
    char path[24];
    char buf[256];
    int got;
    parallax_unpack_path(
            path, 23,
            0x65732f636f72702full,
            0x2f727474612f666cull,
            0x00746e6572727563ull);
    got = parallax_read_file(path, buf, sizeof(buf));
    if (got <= 0)
        return 0;
    return parallax_has_token_ci(buf, (size_t)got, 0x00006b736967616dull, 0, 6u) ||
           parallax_has_token_ci(buf, (size_t)got, 0x000000000075736bull, 0, 3u) ||
           parallax_has_token_ci(buf, (size_t)got, 0x0000686374617061ull, 0, 6u) ||
           parallax_has_token_ci(buf, (size_t)got, 0x000000003a75733aull, 0, 4u);
}

static PARALLAX_NOINLINE int parallax_su_paths(void) {
    return parallax_path_present(
                   9, 0x64612f617461642full, 0x0000000000000062ull, 0) ||
           parallax_path_present(
                   16, 0x64612f617461642full, 0x6b736967616d2f62ull, 0) ||
           parallax_path_present(
                   13, 0x64612f617461642full, 0x00000075736b2f62ull, 0) ||
           parallax_path_present(
                   12, 0x64612f617461642full, 0x0000000070612f62ull, 0) ||
           parallax_path_present(
                   17, 0x64612f617461642full, 0x656c75646f6d2f62ull, 0x73ull) ||
           parallax_path_present(
                   14, 0x6f6c2f617461642full, 0x000075732f6c6163ull, 0) ||
           parallax_path_present(
                   18, 0x6f6c2f617461642full, 0x2f6e69622f6c6163ull, 0x7573ull) ||
           parallax_path_present(
                   19, 0x6f6c2f617461642full, 0x6e6962782f6c6163ull, 0x00000075732full) ||
           parallax_open_packed(
                   15, 0x2f6d65747379732full, 0x0075732f6e696278ull, 0) ||
           parallax_open_packed(
                   8, 0x75732f6e6962732full, 0, 0) ||
           parallax_open_packed(
                   14, 0x2f726f646e65762full, 0x000075732f6e6962ull, 0) ||
           parallax_open_packed(
                   10, 0x2f6e69622f75732full, 0x0000000000007573ull, 0) ||
           parallax_open_packed(
                   15, 0x2f6d65747379732full, 0x0075732f6e696273ull, 0) ||
           parallax_open_packed(
                   23, 0x2f6d65747379732full, 0x6c6961662f6e6962ull, 0x0075732f65666173ull) ||
           parallax_open_packed(
                   21, 0x2f6d65747379732full, 0x6561642f6e696278ull, 0x00000075736e6f6dull) ||
           parallax_open_packed(
                   19, 0x2f6d65747379732full, 0x6775732f6e696278ull, 0x000000000065746full) ||
           parallax_open_packed(
                   20, 0x2f6d65747379732full, 0x7478652e2f6e6962ull, 0x0000000075732e2full) ||
           parallax_open_packed5(
                   34, 0x2f6d65747379732full, 0x726f77656d617266ull,
                   0x6465736f70582f6bull, 0x6a2e656764697242ull,
                   0x0000000000007261ull) ||
           parallax_open_packed(
                   13, 0x6d2e2f6e6962732full, 0x0000006b73696761ull, 0) ||
           parallax_open_packed(
                   22, 0x2e2f65686361632full, 0x5f656c6261736964ull, 0x00006b736967616dull) ||
           parallax_open_packed(
                   15, 0x616d2e74696e692full, 0x0063722e6b736967ull, 0) ||
           parallax_open_packed(
                   15, 0x746375646f72702full, 0x0075732f6e69622full, 0) ||
           parallax_open_packed(
                   17, 0x725f67756265642full, 0x732f6b7369646d61ull, 0x75ull);
}

static PARALLAX_NOINLINE int parallax_mount_bad(void) {
    enum { CAP = 64u * 1024u };
    char path[22];
    char *buf;
    int got;
    int bad = 0;

    /* /proc/self/mounts is already ~23 KiB on a stock device; a 4 KiB
       window let Magisk/APatch bind mounts hide beyond the first page.
       Use anonymous memory, not a 64 KiB stack frame. */
    buf = (char *)mmap(
            0, CAP, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == (char *)-1)
        return 0;

    parallax_unpack_path(
            path, 12,
            0x6f6d2f636f72702full,
            0x0000000073746e75ull,
            0);
    got = parallax_read_file(path, buf, CAP);
    if (got == (int)CAP - 1) {
        bad = 1; /* truncated mount table: fail closed */
    } else if (got > 0 &&
        (parallax_has_token_ci(buf, (size_t)got, 0x00006b736967616dull, 0, 6u) ||
         parallax_has_token_ci(buf, (size_t)got, 0x0000686374617061ull, 0, 6u))) {
        bad = 1;
    }

    if (!bad) {
        parallax_unpack_path(
                path, 20,
                0x65732f636f72702full,
                0x746e756f6d2f666cull,
                0x000000006f666e69ull);
        got = parallax_read_file(path, buf, CAP);
        if (got == (int)CAP - 1) {
            bad = 1;
        } else if (got > 0 &&
            (parallax_has_token_ci(buf, (size_t)got, 0x00006b736967616dull, 0, 6u) ||
             parallax_has_token_ci(buf, (size_t)got, 0x0000686374617061ull, 0, 6u))) {
            bad = 1;
        }
    }

    Punmap(buf, CAP);
    return bad;
}

static PARALLAX_NOINLINE __attribute__((unused)) int parallax_root_scan(int full) {
    if (parallax_selinux_bad())
        return 1;
    if (parallax_context_bad())
        return 1;
    if (parallax_su_paths())
        return 1;
    if (parallax_mount_bad())
        return 1;
    if (full && parallax_getprop_bad())
        return 1;
    return 0;
}

static int parallax_trust_add_path(
        ParallaxWatchdogState *st,
        char const *path) {
    size_t len = 0;
    uint32_t i;
    if (!st || !path)
        return 0;
    while (path[len] != 0) {
        if (len + 1u >= PARALLAX_WD_TRUSTED_PATH_BYTES)
            return 0;
        ++len;
    }
    if (len == 0)
        return 0;
    for (i = 0; i < st->n_trusted_paths; ++i) {
        char const *e = st->trusted_paths[i];
        size_t j = 0;
        while (j < len && e[j] == path[j])
            ++j;
        if (j == len && e[j] == 0)
            return 1;
    }
    if (st->n_trusted_paths >= PARALLAX_WD_MAX_TRUSTED_PATHS)
        return 0;
    {
        char *dst = st->trusted_paths[st->n_trusted_paths];
        size_t j;
        for (j = 0; j < len; ++j)
            dst[j] = path[j];
        dst[len] = 0;
        ++st->n_trusted_paths;
    }
    return 1;
}

static char const *parallax_maps_path(
        char const *line,
        size_t len,
        size_t *path_len) {
    size_t i;
    size_t slash = 0;
    size_t start;
    for (i = 0; i < len; ++i) {
        if (line[i] == '/')
            slash = i;
    }
    if (slash == 0)
        return 0;
    start = slash;
    while (start > 0 && line[start - 1] != ' ')
        --start;
    *path_len = len - start;
    return line + start;
}

static int parallax_trusted_path_line(
        ParallaxWatchdogState const *st,
        char const *line,
        size_t len) {
    char const *path;
    size_t path_len = 0;
    uint32_t i;
    if (!st || st->magic != PARALLAX_WD_MAGIC)
        return 0;
    path = parallax_maps_path(line, len, &path_len);
    if (!path || path_len == 0)
        return 0;
    for (i = 0; i < st->n_trusted_paths; ++i) {
        char const *e = st->trusted_paths[i];
        size_t elen = 0;
        size_t j;
        int has_slash = 0;
        while (elen + 1u < PARALLAX_WD_TRUSTED_PATH_BYTES && e[elen] != 0) {
            if (e[elen] == '/')
                has_slash = 1;
            ++elen;
        }
        if (has_slash) {
            if (path_len == elen) {
                for (j = 0; j < elen; ++j) {
                    if (path[j] != e[j])
                        break;
                }
                if (j == elen)
                    return 1;
            }
        } else {
            size_t base = 0;
            for (j = 0; j < path_len; ++j) {
                if (path[j] == '/')
                    base = j + 1u;
            }
            if (path_len - base == elen) {
                for (j = 0; j < elen; ++j) {
                    if (path[base + j] != e[j])
                        break;
                }
                if (j == elen)
                    return 1;
            }
        }
    }
    return 0;
}

static int parallax_maps_line_has_marker(char const *buf, size_t total) {
    /* Strong framework/module markers; generic words such as "hook" are
       intentionally not treated as attacks. */
    return parallax_has_token_ci(buf, total, 0x0000006164697266ull, 0, 5u) ||
           parallax_has_token_ci(buf, total, 0x7461727473627573ull, 0x65ull, 9u) ||
           parallax_has_token_ci(buf, total, 0x00006465736f7078ull, 0, 6u) ||
           parallax_has_token_ci(buf, total, 0x006465736f70736cull, 0, 7u) ||
           parallax_has_token_ci(buf, total, 0x6465736f70786465ull, 0, 8u) ||
           parallax_has_token_ci(buf, total, 0x6b6f6f68646e6173ull, 0, 8u) ||
           parallax_has_token_ci(buf, total, 0x0000006166686179ull, 0, 5u) ||
           parallax_has_token_ci(buf, total, 0x0000000075726972ull, 0, 4u) ||
           parallax_has_token_ci(buf, total, 0x00006b736967797aull, 0, 6u) ||
           parallax_has_token_ci(buf, total, 0x6f7463656a6e696cull, 0x72ull, 9u) ||
           parallax_has_token_ci(buf, total, 0x006b6f6f6862696cull, 0, 7u) ||
           parallax_has_token_ci(buf, total, 0x006b6f6f686c7275ull, 0, 7u) ||
           parallax_has_token_ci(buf, total, 0x00006b6f6f6878ull, 0, 5u) ||
           parallax_has_token_ci(buf, total, 0x00006b6f6f6862ull, 0, 5u) ||
           parallax_has_token_ci(buf, total, 0x0000656c616877ull, 0, 5u) ||
           parallax_has_token_ci(buf, total, 0x00746567646167ull, 0, 6u) ||
           parallax_has_token_ci(buf, total, 0x6f686f7761646873ull, 0x6b6full, 10u) ||
           parallax_has_token_ci(buf, total, 0x00006b736967616dull, 0, 6u) ||
           parallax_has_token_ci(buf, total, 0x0000686374617061ull, 0, 6u) ||
           parallax_has_token_ci(buf, total, 0x006f6b696d616873ull, 0, 7u) ||
           parallax_has_token_ci(buf, total, 0x6264612f61746164ull, 0, 8u) ||
           parallax_has_token_ci(buf, total, 0x6d742f6c61636f6cull, 0x70ull, 9u) ||
           parallax_has_token_ci(buf, total, 0x782f6d6574737973ull, 0x6e6962ull, 11u) ||
           parallax_has_token_ci(buf, total, 0x00002f6e6962732full, 0, 6u) ||
           parallax_has_token_ci(buf, total, 0x6f68797465666173ull, 0x6bull, 10u) ||
           parallax_has_token_ci(buf, total, 0x006b6f6f686e696dull, 0, 7u) ||
           parallax_has_token_ci(buf, total, 0x0074706972637963ull, 0, 7u) ||
           parallax_has_token_ci(buf, total, 0x006b6f6f68646e61ull, 0, 7u) ||
           parallax_has_token_ci(buf, total, 0x00007a7a6b6f6f68ull, 0, 6u) ||
           parallax_has_token_ci(buf, total, 0x007372756f746564ull, 0, 7u) ||
           parallax_has_token_ci(buf, total, 0x0000736a2d6d7567ull, 0, 6u);
}

static PARALLAX_NOINLINE int parallax_maps_bad_marker(
        char const *buf,
        size_t total,
        ParallaxWatchdogState const *st) {
    size_t ls = 0;
    while (ls < total) {
        size_t le = ls;
        while (le < total && buf[le] != '\n')
            ++le;
        if (le == total)
            break; /* incomplete line; the carry will retry it */
        if (parallax_maps_line_has_marker(buf + ls, le - ls) &&
            !parallax_trusted_path_line(st, buf + ls, le - ls))
            return 1;
        ls = le + 1u;
    }
    return 0;
}

/* libc must come from the platform (/system or /apex). A bundled or
   attacker-supplied libc.so in the app directory would otherwise be
   accepted as the owner of strlen/strcmp/GOT guards. */
static PARALLAX_NOINLINE int parallax_maps_libc_untrusted(char const *buf, size_t total) {
    size_t search = 0;
    while (search < total) {
        long rel = parallax_find_token_ci(
                buf + search, total - search,
                0x6f732e6362696c2full, 0, 8u);
        size_t at, ls, le;
        if (rel < 0)
            return 0;
        at = search + (size_t)rel;
        ls = at;
        le = at;
        while (ls > 0 && buf[ls - 1] != '\n')
            --ls;
        while (le < total && buf[le] != '\n')
            ++le;
        if (le == total)
            return 0; /* incomplete line; the carry will retry it */
        if (!(parallax_has_token_ci(
                      buf + ls, le - ls,
                      0x2f6d65747379732full, 0, 8u) ||
              parallax_has_token_ci(
                      buf + ls, le - ls,
                      0x2f786570612full, 0, 6u)))
            return 1;
        search = le;
    }
    return 0;
}

static void parallax_maps_collect(
        char const *buf,
        size_t total,
        uint64_t token_lo,
        uint64_t token_hi,
        unsigned token_len,
        Elf64_Addr *out_lo,
        Elf64_Addr *out_hi) {
    size_t search = 0;
    while (search < total) {
        long rel = parallax_find_token_ci(
                buf + search, total - search,
                token_lo, token_hi, token_len);
        size_t at, ls, le, dash, perm;
        Elf64_Addr lo, hi;
        if (rel < 0)
            break;
        at = search + (size_t)rel;
        ls = at;
        while (ls > 0 && buf[ls - 1] != '\n')
            --ls;
        le = at;
        while (le < total && buf[le] != '\n')
            ++le;
        dash = ls;
        while (dash < le && buf[dash] != '-')
            ++dash;
        perm = dash;
        while (perm < le && buf[perm] != ' ')
            ++perm;
        while (perm < le && buf[perm] == ' ')
            ++perm;

        if (perm + 3u < le && buf[perm] == 'r' && buf[perm + 2u] == 'x' &&
            parallax_parse_hex_range(buf + ls, le - ls, &lo, &hi)) {
            if (*out_lo == 0 || lo < *out_lo)
                *out_lo = lo;
            if (hi > *out_hi)
                *out_hi = hi;
        }
        search = at + token_len;
    }
}

static __attribute__((unused)) int parallax_maps_scan(
        Elf64_Addr *libc_lo,
        Elf64_Addr *libc_hi,
        Elf64_Addr *curl_lo,
        Elf64_Addr *curl_hi,
        Elf64_Addr *ssl_lo,
        Elf64_Addr *ssl_hi,
        int check_markers) {
    char path[16];
    char buf[4096 + 512];
    size_t carry = 0;
    int fd;
    int suspicious = 0;

    *libc_lo = *libc_hi = 0;
    *curl_lo = *curl_hi = 0;
    *ssl_lo = *ssl_hi = 0;
    parallax_unpack_path(
            path, 15,
            0x65732f636f72702full,
            0x00007370616d2f66ull,
            0);
    fd = openat(0, path, O_RDONLY, 0);
    if (fd < 0)
        return 0;

    for (;;) {
        ssize_t got = read(fd, buf + carry, 4096);
        size_t total;
        if (got <= 0)
            break;
        total = carry + (size_t)got;

        if (parallax_maps_libc_untrusted(buf, total) ||
            (check_markers && parallax_maps_bad_marker(buf, total, 0)))
            suspicious = 1;

        parallax_maps_collect(
                buf, total,
                0x6f732e6362696c2full, 0, 8u,
                libc_lo, libc_hi);
        parallax_maps_collect(
                buf, total,
                0x6c72756362696c2full, 0x006f732eull, 11u,
                curl_lo, curl_hi);
        parallax_maps_collect(
                buf, total,
                0x2e6c737362696c2full, 0x6f73ull, 10u,
                ssl_lo, ssl_hi);
        parallax_maps_collect(
                buf, total,
                0x7079726362696c2full, 0x6f732e6f74ull, 13u,
                ssl_lo, ssl_hi);
        parallax_maps_collect(
                buf, total,
                0x69726f6262696c2full, 0x6c7373676eull, 12u,
                ssl_lo, ssl_hi);

        carry = total < 512u ? total : 512u;
        {
            size_t i;
            for (i = 0; i < carry; ++i)
                buf[i] = buf[total - carry + i];
        }
    }
    close(fd);
    return suspicious;
}

static __attribute__((unused)) int parallax_maps_suspicious_only(ParallaxWatchdogState const *st) {
    char path[16];
    char buf[4096 + 512];
    size_t carry = 0;
    int fd;
    int suspicious = 0;

    parallax_unpack_path(
            path, 15,
            0x65732f636f72702full,
            0x00007370616d2f66ull,
            0);
    fd = openat(0, path, O_RDONLY, 0);
    if (fd < 0)
        return 0;

    for (;;) {
        ssize_t got = read(fd, buf + carry, 4096);
        size_t total;
        if (got <= 0)
            break;
        total = carry + (size_t)got;
        if (parallax_maps_bad_marker(buf, total, st) ||
            parallax_maps_libc_untrusted(buf, total)) {
            suspicious = 1;
            break;
        }
        carry = total < 512u ? total : 512u;
        {
            size_t i;
            for (i = 0; i < carry; ++i)
                buf[i] = buf[total - carry + i];
        }
    }
    close(fd);
    return suspicious;
}

static int parallax_in_range(
        Elf64_Addr addr,
        size_t size,
        Elf64_Addr lo,
        Elf64_Addr hi) {
    if (lo == 0 || hi <= lo || addr < lo || addr > hi)
        return 0;
    if ((Elf64_Addr)size > hi - addr)
        return 0;
    return addr + (Elf64_Addr)size <= hi;
}

static Elf64_Addr parallax_resolve_module_ptr(
        Elf64_Addr value,
        Elf64_Addr base,
        Elf64_Addr lo,
        Elf64_Addr hi,
        size_t size) {
    Elf64_Addr candidate;
    if (parallax_in_range(value, size, lo, hi))
        return value;
    if (value > ~(Elf64_Addr)0 - base)
        return 0;
    candidate = base + value;
    return parallax_in_range(candidate, size, lo, hi) ? candidate : 0;
}

static int parallax_name_eq(char const *name, char const *literal) {
    while (*literal != 0) {
        if (*name != *literal)
            return 0;
        ++name;
        ++literal;
    }
    return *name == 0;
}

static int parallax_name_prefix(char const *name, char const *prefix) {
    while (*prefix != 0) {
        if (*name != *prefix)
            return 0;
        ++name;
        ++prefix;
    }
    return 1;
}

/*
 * Conservative owner classification for imported symbols that are common URL
 * swap and string-hook targets. Everything else is baseline-monitored but not
 * required to live in a specific library.
 */
static int parallax_classify_symbol(char const *name) {
    if (parallax_name_prefix(name, addr_string("curl_")))
        return PARALLAX_OWNER_CURL;
    if (parallax_name_prefix(name, addr_string("SSL_")) ||
        parallax_name_prefix(name, addr_string("EVP_")) ||
        parallax_name_prefix(name, addr_string("BIO_")) ||
        parallax_name_prefix(name, addr_string("X509_")) ||
        parallax_name_prefix(name, addr_string("OPENSSL_")))
        return PARALLAX_OWNER_SSL;
    if (parallax_name_eq(name, addr_string("strlen")) ||
        parallax_name_eq(name, addr_string("strcmp")) ||
        parallax_name_eq(name, addr_string("strncmp")) ||
        parallax_name_eq(name, addr_string("strstr")) ||
        parallax_name_eq(name, addr_string("strchr")) ||
        parallax_name_eq(name, addr_string("strrchr")) ||
        parallax_name_eq(name, addr_string("strcpy")) ||
        parallax_name_eq(name, addr_string("strncpy")) ||
        parallax_name_eq(name, addr_string("strcat")) ||
        parallax_name_eq(name, addr_string("strncat")) ||
        parallax_name_eq(name, addr_string("memcmp")) ||
        parallax_name_eq(name, addr_string("memcpy")) ||
        parallax_name_eq(name, addr_string("memmove")) ||
        parallax_name_eq(name, addr_string("memset")) ||
        parallax_name_eq(name, addr_string("malloc")) ||
        parallax_name_eq(name, addr_string("calloc")) ||
        parallax_name_eq(name, addr_string("realloc")) ||
        parallax_name_eq(name, addr_string("free")) ||
        parallax_name_eq(name, addr_string("getaddrinfo")) ||
        parallax_name_eq(name, addr_string("gethostbyname")) ||
        parallax_name_eq(name, addr_string("connect")) ||
        parallax_name_eq(name, addr_string("send")) ||
        parallax_name_eq(name, addr_string("sendto")) ||
        parallax_name_eq(name, addr_string("recv")) ||
        parallax_name_eq(name, addr_string("recvfrom")) ||
        parallax_name_eq(name, addr_string("socket")) ||
        parallax_name_eq(name, addr_string("fopen")) ||
        parallax_name_eq(name, addr_string("fread")) ||
        parallax_name_eq(name, addr_string("fwrite")) ||
        parallax_name_eq(name, addr_string("read")) ||
        parallax_name_eq(name, addr_string("write")) ||
        parallax_name_eq(name, addr_string("open")) ||
        parallax_name_eq(name, addr_string("popen")) ||
        parallax_name_eq(name, addr_string("system")))
        return PARALLAX_OWNER_LIBC;
    return PARALLAX_OWNER_OTHER;
}

static PARALLAX_NOINLINE uint64_t parallax_hash_bytes(void const *ptr, size_t len) {
    unsigned char const *p = (unsigned char const *)ptr;
    uint64_t h = 0xcbf29ce484222325ull;
    size_t i = 0;
    for (; i + 8u <= len; i += 8u) {
        uint64_t w = *(uint64_t const *)(uintptr_t)(p + i);
        h ^= w;
        h *= 0x100000001b3ull;
        h ^= h >> 29;
    }
    for (; i < len; ++i) {
        h ^= p[i];
        h *= 0x100000001b3ull;
    }
    return h;
}

static __attribute__((unused)) int parallax_owner_range(
        unsigned owner,
        ParallaxWatchdogState const *st,
        Elf64_Addr *lo,
        Elf64_Addr *hi) {
    if (owner == PARALLAX_OWNER_LIBC) {
        *lo = st->libc_lo;
        *hi = st->libc_hi;
    } else if (owner == PARALLAX_OWNER_CURL) {
        *lo = st->curl_lo;
        *hi = st->curl_hi;
    } else if (owner == PARALLAX_OWNER_SSL) {
        *lo = st->ssl_lo;
        *hi = st->ssl_hi;
    } else {
        *lo = 0;
        *hi = 0;
    }
    return *lo != 0 && *hi > *lo;
}

/*
 * Detect the two common AArch64 inline-hook shapes at a resolved function
 * entry: an unconditional branch that escapes the owner module, or an
 * indirect BR/BLR (Dobby, ShadowHook, inline trampolines). Real function
 * prologues do not start this way.
 */
static PARALLAX_NOINLINE __attribute__((unused)) int parallax_inline_hook(
        Elf64_Addr target,
        Elf64_Addr lo,
        Elf64_Addr hi) {
    unsigned i;
    if (!parallax_in_range(target, 16u, lo, hi) || (target & 3u))
        return 1;

    for (i = 0; i < 4u; ++i) {
        Elf64_Addr pc = target + 4u * i;
        uint32_t insn = *(volatile uint32_t const *)(uintptr_t)pc;
        if ((insn & 0xfc000000u) == 0x14000000u) { /* B imm26 */
            int64_t imm = (int64_t)(insn & 0x03ffffffu);
            Elf64_Addr destination;
            if (imm & 0x02000000ll)
                imm |= ~0x03ffffffll;
            destination = (Elf64_Addr)((int64_t)pc + (imm << 2));
            if (!parallax_in_range(destination, 4u, lo, hi))
                return 1;
        }
        if ((insn & 0xfffffc1fu) == 0xd61f0000u || /* BR Xn */
            (insn & 0xfffffc1fu) == 0xd63f0000u || /* BLR Xn */
            (insn & 0xffe0001fu) == 0xd4200000u || /* BRK #imm16 */
            insn == 0u)                            /* UDF #0 */
            return 1;
    }
    return 0;
}

static PARALLAX_NOINLINE void parallax_guard_capture(
        ParallaxGuard64 *guard,
        Elf64_Addr target,
        int with_prologue) {
    unsigned i;
    guard->target = target;
    if (with_prologue) {
        for (i = 0; i < PARALLAX_WD_PROLOGUE_BYTES; ++i)
            guard->prologue[i] =
                    *(unsigned char const *)(uintptr_t)(target + i);
    }
    guard->reserved = with_prologue ? 1u : 0u;
    guard->state = PARALLAX_GUARD_FROZEN;
}

static PARALLAX_NOINLINE __attribute__((unused)) int parallax_guard_prologue_changed(ParallaxGuard64 const *guard) {
    unsigned i;
    for (i = 0; i < PARALLAX_WD_PROLOGUE_BYTES; ++i) {
        unsigned char cur =
                *(unsigned char const *)(uintptr_t)(guard->target + i);
        if (cur != guard->prologue[i])
            return 1;
    }
    return 0;
}

static int parallax_module_caller(
        ParallaxWatchdogState const *st,
        void const *return_address) {
    if (!st || st->magic != PARALLAX_WD_MAGIC)
        return 0;
    return parallax_in_range(
            (Elf64_Addr)(uintptr_t)return_address,
            4u, st->module_lo, st->module_hi);
}

/*
 * Trusted self-refresh. The protected library may install hooks, patch its
 * own read-only image, or load helper frameworks during its constructors and
 * inside an explicit begin()/end() window. Those mutations are adopted as the
 * new baseline; the stub's own code guards are never refreshed.
 */
static void parallax_self_trust_refresh(ParallaxWatchdogState *st) {
    uint32_t i;
    if (!st || st->magic != PARALLAX_WD_MAGIC)
        return;
    for (i = 0; i < st->n_guards; ++i) {
        ParallaxGuard64 *g = &st->guards[i];
        Elf64_Addr cur = *(volatile Elf64_Addr const *)(uintptr_t)g->slot;
        if (cur == 0) {
            g->target = 0;
            g->state = PARALLAX_GUARD_DEFERRED;
            continue;
        }
        if (g->state == PARALLAX_GUARD_DEFERRED) {
            if (cur == g->target)
                continue;
            g->target = cur;
            /* Leave lazy PLT resolver slots deferred until they resolve. */
            if (parallax_in_range(cur, 4u, st->module_lo, st->module_hi))
                continue;
            g->state = PARALLAX_GUARD_FROZEN;
        } else {
            g->target = cur;
        }
        if (g->is_func) {
            unsigned k;
            for (k = 0; k < PARALLAX_WD_PROLOGUE_BYTES; ++k)
                g->prologue[k] =
                        *(unsigned char const *)(uintptr_t)(cur + k);
            g->reserved = 1u;
        } else {
            g->reserved = 0u;
        }
    }
    for (i = 0; i < st->n_segments; ++i) {
        ParallaxSegment64 *seg = &st->segments[i];
        seg->hash = parallax_hash_bytes(
                (void const *)(uintptr_t)seg->lo,
                (size_t)(seg->hi - seg->lo));
    }
}

static void parallax_self_trust_seal(ParallaxWatchdogState *st) {
    if (!st || st->magic != PARALLAX_WD_MAGIC)
        return;
    parallax_self_trust_refresh(st);
    st->self_trust = 0;
    st->self_trust_budget = 0;
}

static PARALLAX_NOINLINE void parallax_self_trust_begin(void *ctx) {
    ParallaxWatchdogState *st = (ParallaxWatchdogState *)ctx;
    if (!parallax_module_caller(st, __builtin_return_address(0)))
        return;
    st->self_trust = 1;
    st->self_trust_budget = PARALLAX_SELF_TRUST_TICKS;
}

static PARALLAX_NOINLINE void parallax_self_trust_end(void *ctx) {
    ParallaxWatchdogState *st = (ParallaxWatchdogState *)ctx;
    if (!parallax_module_caller(st, __builtin_return_address(0)))
        return;
    parallax_self_trust_seal(st);
}

static PARALLAX_NOINLINE void parallax_self_trust_grant_all(void *ctx) {
    ParallaxWatchdogState *st = (ParallaxWatchdogState *)ctx;
    if (!parallax_module_caller(st, __builtin_return_address(0)))
        return;
    parallax_self_trust_refresh(st);
}

static PARALLAX_NOINLINE void parallax_self_trust_grant_slot(
        void *ctx,
        void *slot) {
    ParallaxWatchdogState *st = (ParallaxWatchdogState *)ctx;
    uint32_t i;
    if (!parallax_module_caller(st, __builtin_return_address(0)))
        return;
    for (i = 0; i < st->n_guards; ++i) {
        ParallaxGuard64 *g = &st->guards[i];
        if (g->slot == (Elf64_Addr)(uintptr_t)slot) {
            Elf64_Addr cur = *(volatile Elf64_Addr const *)(uintptr_t)slot;
            if (cur == 0) {
                g->target = 0;
                g->reserved = 0u;
                g->state = PARALLAX_GUARD_DEFERRED;
            } else if (g->state == PARALLAX_GUARD_DEFERRED &&
                       parallax_in_range(
                               cur, 4u, st->module_lo, st->module_hi)) {
                g->target = cur; /* still an unresolved lazy PLT slot */
                g->reserved = 0u;
            } else {
                g->target = cur;
                if (g->is_func) {
                    unsigned k;
                    for (k = 0; k < PARALLAX_WD_PROLOGUE_BYTES; ++k)
                        g->prologue[k] =
                                *(unsigned char const *)(uintptr_t)(cur + k);
                    g->reserved = 1u;
                } else {
                    g->reserved = 0u;
                }
                g->state = PARALLAX_GUARD_FROZEN;
            }
            return;
        }
    }
}

static PARALLAX_NOINLINE void parallax_self_trust_grant_range(
        void *ctx,
        void *addr,
        unsigned long len) {
    ParallaxWatchdogState *st = (ParallaxWatchdogState *)ctx;
    Elf64_Addr lo = (Elf64_Addr)(uintptr_t)addr;
    Elf64_Addr hi;
    uint32_t i;
    if (!parallax_module_caller(st, __builtin_return_address(0)))
        return;
    if (len == 0 || lo > ~(Elf64_Addr)0 - (Elf64_Addr)len)
        return;
    hi = lo + (Elf64_Addr)len;
    for (i = 0; i < st->n_segments; ++i) {
        ParallaxSegment64 *seg = &st->segments[i];
        if (lo < seg->hi && hi > seg->lo) {
            seg->hash = parallax_hash_bytes(
                    (void const *)(uintptr_t)seg->lo,
                    (size_t)(seg->hi - seg->lo));
        }
    }
}

static PARALLAX_NOINLINE void parallax_self_trust_trust_path(
        void *ctx,
        char const *path) {
    ParallaxWatchdogState *st = (ParallaxWatchdogState *)ctx;
    if (!parallax_module_caller(st, __builtin_return_address(0)))
        return;
    parallax_trust_add_path(st, path);
}

static int parallax_gnu_hash_count(
        Elf64_Addr gnu_hash_v,
        Elf64_Addr base,
        Elf64_Addr lo,
        Elf64_Addr hi,
        uint32_t *out) {
    uint32_t const *gh;
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t bloom_size;
    size_t bloom_words;
    uint32_t const *buckets;
    uint32_t const *chains;
    uint32_t max_sym;
    uint32_t i;

    gh = (uint32_t const *)(uintptr_t)parallax_resolve_module_ptr(
            gnu_hash_v, base, lo, hi, 16u);
    if (!gh)
        return 0;
    nbuckets = gh[0];
    symoffset = gh[1];
    bloom_size = gh[2];
    if (nbuckets == 0 || nbuckets > 65536u || bloom_size > 65536u ||
        symoffset > 1000000u)
        return 0;
    bloom_words = (size_t)bloom_size * 2u;
    if (!parallax_in_range(
                (Elf64_Addr)(uintptr_t)gh,
                16u + bloom_words * 4u + (size_t)nbuckets * 4u,
                lo, hi))
        return 0;
    buckets = gh + 4u + bloom_words;
    chains = buckets + nbuckets;
    max_sym = symoffset;
    for (i = 0; i < nbuckets; ++i) {
        uint32_t b = buckets[i];
        uint32_t idx;
        if (b < symoffset)
            continue;
        if (b > 1000000u)
            return 0;
        idx = b;
        for (;;) {
            uint32_t const *chain;
            if (idx > 1000000u)
                return 0;
            chain = chains + (idx - symoffset);
            if (!parallax_in_range(
                        (Elf64_Addr)(uintptr_t)chain, 4u, lo, hi))
                return 0;
            if ((*chain & 1u) != 0)
                break;
            ++idx;
        }
        if (idx > max_sym)
            max_sym = idx;
    }
    *out = max_sym + 1u;
    return 1;
}

static void parallax_find_self_trust_init(
        ParallaxWatchdogState *st,
        ParallaxSym64 const *symtab,
        char const *strtab,
        Elf64_Addr base,
        Elf64_Addr lo,
        Elf64_Addr hi,
        Elf64_Addr gnu_hash_v,
        Elf64_Addr hash_v) {
    uint32_t n_syms = 0;
    uint32_t i;

    if (gnu_hash_v) {
        if (!parallax_gnu_hash_count(gnu_hash_v, base, lo, hi, &n_syms))
            return;
    } else if (hash_v) {
        uint32_t const *h = (uint32_t const *)(uintptr_t)
                parallax_resolve_module_ptr(hash_v, base, lo, hi, 8u);
        if (!h)
            return;
        n_syms = h[1];
    }
    if (n_syms == 0 || n_syms > 1000000u)
        return;
    if (!parallax_in_range(
                (Elf64_Addr)(uintptr_t)symtab,
                (size_t)n_syms * sizeof(*symtab), lo, hi))
        return;

    for (i = 0; i < n_syms; ++i) {
        ParallaxSym64 const *sym = &symtab[i];
        char const *name;
        Elf64_Addr addr;
        if ((sym->st_info & 0x0fu) != 2u || sym->st_shndx == 0)
            continue;
        if (sym->st_name > (Elf64_Word)(hi - lo))
            continue;
        name = strtab + sym->st_name;
        if (!parallax_in_range(
                    (Elf64_Addr)(uintptr_t)name, 64u, lo, hi))
            continue;
        if (!parallax_name_eq(name, addr_string("parallax_self_trust_init")))
            continue;
        addr = parallax_resolve_module_ptr(sym->st_value, base, lo, hi, 4u);
        if (!addr)
            continue;
        st->self_trust_init =
                (void (*)(ParallaxSelfTrustApi *))(uintptr_t)addr;
        return;
    }
}

static PARALLAX_NOINLINE void parallax_mark_tampered(
        ParallaxWatchdogState *st) {
    if (!st || st->magic != PARALLAX_WD_MAGIC)
        return;
    /* Binary-only strict policy: confirmed protected-image, protected-slot,
       or critical imported-target tampering terminates the process. */
    st->reserved1 = 1u;
    st->self_trust = 0;
    st->self_trust_budget = 0;
    exit_group(137);
    for (;;) {
    }
}

static void parallax_watchdog_tick(ParallaxWatchdogState *st) {
    uint32_t i;
    if (!st || st->magic != PARALLAX_WD_MAGIC || st->reserved1 != 0)
        return;

    if (st->self_trust) {
        parallax_self_trust_refresh(st);
        if (st->self_trust_budget != 0 &&
            --st->self_trust_budget == 0)
            parallax_self_trust_seal(st);
        return;
    }

    /* Every slot belongs to the protected module. Critical libc/curl/TLS
       imports additionally keep a 32-byte target-prologue baseline so a
       runtime inline trampoline cannot redirect only this library's calls. */
    for (i = 0; i < st->n_guards; ++i) {
        ParallaxGuard64 *g = &st->guards[i];
        Elf64_Addr cur = *(volatile Elf64_Addr const *)(uintptr_t)g->slot;
        if (g->state == PARALLAX_GUARD_DEFERRED) {
            if (cur == g->target)
                continue;
            if (cur == 0) {
                parallax_mark_tampered(st);
                return;
            }
            {
                int clean_critical_target = 0;
                if (g->is_func && g->owner != PARALLAX_OWNER_OTHER) {
                    Elf64_Addr lo = 0, hi = 0;
                    clean_critical_target =
                            parallax_owner_range(g->owner, st, &lo, &hi) &&
                            parallax_in_range(cur, 16u, lo, hi) &&
                            !parallax_inline_hook(cur, lo, hi);
                }
                /* First lazy resolution establishes a baseline. Existing OEM
                   or application trampolines are accepted slot-only instead
                   of causing a startup false positive. */
                parallax_guard_capture(g, cur, clean_critical_target);
            }
        } else {
            if (cur != g->target) {
                parallax_mark_tampered(st);
                return;
            }
            if (g->reserved != 0 &&
                parallax_guard_prologue_changed(g)) {
                parallax_mark_tampered(st);
                return;
            }
        }
    }

    /* Read-only executable/data segments belong to the protected library.
       The baseline is captured after relocation and may be refreshed only
       from an authenticated in-module self-trust window. */
    for (i = 0; i < st->n_segments; ++i) {
        ParallaxSegment64 *seg = &st->segments[i];
        if (parallax_hash_bytes(
                    (void const *)(uintptr_t)seg->lo,
                    (size_t)(seg->hi - seg->lo)) != seg->hash) {
            parallax_mark_tampered(st);
            return;
        }
    }

    /* Independent loader/runtime checkpoints prevent a single branch patch
       from disabling every self-integrity path. */
    for (i = 0; i < st->n_code_guards; ++i) {
        ParallaxCodeGuard64 *cg = &st->code_guards[i];
        if (parallax_hash_bytes(
                    (void const *)(uintptr_t)cg->addr,
                    (size_t)cg->len) != cg->hash) {
            parallax_mark_tampered(st);
            return;
        }
    }
}

static void parallax_watchdog_handler(int sig, void *info, void *context) {
    void *state;
    (void)sig;
    (void)context;
    if (!info)
        return;
    /* AArch64 siginfo_t: si_signo/si_errno/si_code + pad, then union. The
       timer sigval is at offset 24 inside the union. */
    state = *(void *const *)((char const *)info + 24);
    if (!state)
        return;
    parallax_watchdog_tick((ParallaxWatchdogState *)state);
}

static int parallax_watchdog_start(ParallaxWatchdogState *st) {
    ParallaxKernelSigaction sa;
    ParallaxSigevent sev;
    ParallaxItimerspec64 its;
    unsigned i;
    int timer_id = 0;

    for (i = 0; i < sizeof(sev); ++i)
        ((char *)&sev)[i] = 0;
    sev.value = (void *)st;
    sev.signo = PARALLAX_WD_SIGNAL;
    sev.notify = 0; /* SIGEV_SIGNAL */
    if (timer_create(1 /* CLOCK_MONOTONIC */, &sev, &timer_id) != 0)
        return 0;

    for (i = 0; i < sizeof(sa); ++i)
        ((char *)&sa)[i] = 0;
    sa.handler = parallax_watchdog_handler;
    sa.flags = 0x00000004u /* SA_SIGINFO */ | 0x10000000u /* SA_RESTART */;
    if (rt_sigaction(PARALLAX_WD_SIGNAL, &sa, 0, 8u) != 0) {
        timer_delete(timer_id);
        return 0;
    }

    its.interval.sec = PARALLAX_WD_INTERVAL_SEC;
    its.interval.nsec = 0;
    its.value.sec = PARALLAX_WD_INTERVAL_SEC;
    its.value.nsec = 0;
    if (timer_settime(timer_id, 0, &its, 0) != 0) {
        timer_delete(timer_id);
        return 0;
    }
    st->timer_id = timer_id;
    st->timer_started = 1;
    return 1;
}

static PARALLAX_NOINLINE int parallax_code_guard_add(
        ParallaxWatchdogState *st,
        void const *code) {
    ParallaxCodeGuard64 *cg;
    if (st->n_code_guards >= PARALLAX_WD_MAX_CODE_GUARDS)
        return 1;
    cg = &st->code_guards[st->n_code_guards++];
    cg->addr = (Elf64_Addr)(uintptr_t)code;
    cg->len = PARALLAX_WD_CODE_GUARD_BYTES;
    cg->reserved = 0;
    cg->hash = parallax_hash_bytes(code, PARALLAX_WD_CODE_GUARD_BYTES);
    return 0;
}

static int parallax_guard_add(
        ParallaxWatchdogState *st,
        ParallaxGuard64 const *guard) {
    if (st->n_guards >= PARALLAX_WD_MAX_GUARDS)
        return 1;
    st->guards[st->n_guards++] = *guard;
    return 0;
}

/*
 * Two passes: the first pass records and validates the critical URL/string
 * symbols; the second records every remaining dynamic slot as a change-only
 * baseline. A critical symbol must resolve into its expected library; a
 * still-unresolved PLT slot may resolve later (lazy binding) but only into
 * that same expected library.
 */
static int parallax_guard_rela_table(
        ParallaxRela64 const *rela,
        size_t bytes,
        ParallaxSym64 const *symtab,
        char const *strtab,
        Elf64_Addr base,
        Elf64_Addr module_lo,
        Elf64_Addr module_hi,
        ParallaxWatchdogState *st,
        int generic_pass) {
    size_t count;
    size_t i;

    if (!rela || !symtab || !strtab || bytes == 0 ||
        bytes % sizeof(ParallaxRela64) != 0)
        return 0;
    count = bytes / sizeof(ParallaxRela64);
    if (count > 16384u)
        return 1; /* malformed/unexpected table: fail closed */

    for (i = 0; i < count; ++i) {
        Elf64_Xword info = rela[i].r_info;
        unsigned type = (unsigned)(info & 0xffffffffu);
        Elf64_Xword sym_index = info >> 32;
        Elf64_Addr sym_addr;
        ParallaxSym64 const *sym;
        Elf64_Addr name_addr;
        char const *name;
        Elf64_Addr slot_addr;
        Elf64_Addr target;
        ParallaxGuard64 guard;
        unsigned owner;
        unsigned sym_type;
        int is_func;

        if (type != PARALLAX_R_AARCH64_JUMP_SLOT &&
            type != PARALLAX_R_AARCH64_GLOB_DAT)
            continue;
        if (sym_index > 1048576u)
            return 1;

        sym_addr = (Elf64_Addr)(uintptr_t)symtab;
        if (sym_index > (~(Elf64_Addr)0 - sym_addr) / sizeof(*symtab))
            return 1;
        sym_addr += sym_index * sizeof(*symtab);
        if (!parallax_in_range(sym_addr, sizeof(*symtab), module_lo, module_hi))
            continue;
        sym = (ParallaxSym64 const *)(uintptr_t)sym_addr;

        name_addr = (Elf64_Addr)(uintptr_t)strtab;
        if (sym->st_name > ~(Elf64_Addr)0 - name_addr)
            return 1;
        name_addr += sym->st_name;
        if (!parallax_in_range(name_addr, 128u, module_lo, module_hi))
            continue;
        name = (char const *)(uintptr_t)name_addr;

        owner = (unsigned)parallax_classify_symbol(name);
        sym_type = (unsigned)(sym->st_info & 0x0fu);
        is_func = sym_type == 2u /* STT_FUNC */ || sym_type == 10u /* IFUNC */;
        if (!generic_pass && owner == PARALLAX_OWNER_OTHER)
            continue;
        if (generic_pass && owner != PARALLAX_OWNER_OTHER)
            continue;

        slot_addr = parallax_resolve_module_ptr(
                rela[i].r_offset, base, module_lo, module_hi, sizeof(Elf64_Addr));
        if (!slot_addr)
            return 1;
        target = *(volatile Elf64_Addr const *)(uintptr_t)slot_addr;

        guard.slot = slot_addr;
        guard.target = target;
        guard.owner = (unsigned char)owner;
        guard.state = PARALLAX_GUARD_DEFERRED;
        guard.is_func = (unsigned char)is_func;
        guard.reserved = 0;
        {
            unsigned k;
            for (k = 0; k < PARALLAX_WD_PROLOGUE_BYTES; ++k)
                guard.prologue[k] = 0;
        }

        if (target == 0)
            continue;

        if (owner != PARALLAX_OWNER_OTHER && is_func) {
            Elf64_Addr lo = 0, hi = 0;
            int clean_critical_target =
                    parallax_owner_range(owner, st, &lo, &hi) &&
                    parallax_in_range(target, 16u, lo, hi) &&
                    !parallax_inline_hook(target, lo, hi);
            /* A clean trusted target gets prologue monitoring. An already
               wrapped OEM/app target is accepted as the startup baseline,
               while this protected module's slot remains strictly guarded. */
            parallax_guard_capture(&guard, target, clean_critical_target);
        } else {
            parallax_guard_capture(&guard, target, 0);
        }
        if (parallax_guard_add(st, &guard))
            return 1;
    }
    return 0;
}

static int parallax_install_guards(
        ElfW(Ehdr) const *ehdr,
        char const *va_load,
        Elf64_Addr libc_lo,
        Elf64_Addr libc_hi,
        Elf64_Addr curl_lo,
        Elf64_Addr curl_hi,
        Elf64_Addr ssl_lo,
        Elf64_Addr ssl_hi,
        ParallaxWatchdogState **out_st) {
    ElfW(Phdr) const *phdr;
    ElfW(Phdr) const *phdrN;
    Elf64_Addr base = 0;
    Elf64_Addr module_lo = ~(Elf64_Addr)0;
    Elf64_Addr module_hi = 0;
    ElfW(Phdr) const *dynamic_phdr = nullptr;
    ParallaxDyn64 const *dyn;
    size_t dyn_count;
    size_t i;
    Elf64_Addr strtab_v = 0, symtab_v = 0, jmprel_v = 0, rela_v = 0;
    Elf64_Addr gnu_hash_v = 0, hash_v = 0;
    size_t needed_off[PARALLAX_WD_MAX_TRUSTED_PATHS];
    unsigned n_needed = 0;
    size_t pltrelsz = 0, relasz = 0, relaent = sizeof(ParallaxRela64);
    Elf64_Xword pltrel = 0;
    char const *strtab;
    ParallaxSym64 const *symtab;
    ParallaxRela64 const *jmprel = nullptr;
    ParallaxRela64 const *rela = nullptr;
    ParallaxWatchdogState *st;
    unsigned pass;
    int truncated_segments = 0;

    st = (ParallaxWatchdogState *)mmap(
            nullptr,
            sizeof(ParallaxWatchdogState),
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0);
    if (st == (void *)-1)
        return 1;
    {
        size_t z;
        unsigned char *p = (unsigned char *)st;
        for (z = 0; z < sizeof(*st); ++z)
            p[z] = 0;
    }
    st->magic = PARALLAX_WD_MAGIC;
    st->libc_lo = libc_lo;
    st->libc_hi = libc_hi;
    st->curl_lo = curl_lo;
    st->curl_hi = curl_hi;
    st->ssl_lo = ssl_lo;
    st->ssl_hi = ssl_hi;

    phdr = (ElfW(Phdr) const *)(ehdr + 1);
    phdrN = phdr + ehdr->e_phnum;
    for (i = 0; phdr + i < phdrN; ++i) {
        ElfW(Phdr) const *p = phdr + i;
        if (p->p_type == PT_LOAD && base == 0)
            base = (Elf64_Addr)(uintptr_t)va_load - p->p_vaddr;
    }
    if (base == 0)
        return 1;

    for (i = 0; phdr + i < phdrN; ++i) {
        ElfW(Phdr) const *p = phdr + i;
        if (p->p_type == PT_LOAD) {
            Elf64_Addr lo, hi;
            if (p->p_vaddr > ~(Elf64_Addr)0 - base ||
                p->p_memsz > ~(Elf64_Addr)0 - (base + p->p_vaddr))
                return 1;
            lo = base + p->p_vaddr;
            hi = lo + p->p_memsz;
            if (lo < module_lo)
                module_lo = lo;
            if (hi > module_hi)
                module_hi = hi;
        } else if (p->p_type == PARALLAX_PT_DYNAMIC) {
            dynamic_phdr = p;
        }
    }
    if (!dynamic_phdr || module_hi <= module_lo)
        return 1;
    st->module_lo = module_lo;
    st->module_hi = module_hi;

    dyn = (ParallaxDyn64 const *)(uintptr_t)(
            base + dynamic_phdr->p_vaddr);
    dyn_count = dynamic_phdr->p_memsz / sizeof(*dyn);
    if (dyn_count > 4096u)
        return 1;

    for (i = 0; i < dyn_count; ++i) {
        if (dyn[i].d_tag == PARALLAX_DT_NULL)
            break;
        if (dyn[i].d_tag == PARALLAX_DT_STRTAB)
            strtab_v = dyn[i].d_un.d_ptr;
        else if (dyn[i].d_tag == PARALLAX_DT_SYMTAB)
            symtab_v = dyn[i].d_un.d_ptr;
        else if (dyn[i].d_tag == PARALLAX_DT_JMPREL)
            jmprel_v = dyn[i].d_un.d_ptr;
        else if (dyn[i].d_tag == PARALLAX_DT_PLTRELSZ)
            pltrelsz = (size_t)dyn[i].d_un.d_val;
        else if (dyn[i].d_tag == PARALLAX_DT_PLTREL)
            pltrel = (Elf64_Xword)dyn[i].d_un.d_val;
        else if (dyn[i].d_tag == PARALLAX_DT_RELA)
            rela_v = dyn[i].d_un.d_ptr;
        else if (dyn[i].d_tag == PARALLAX_DT_RELASZ)
            relasz = (size_t)dyn[i].d_un.d_val;
        else if (dyn[i].d_tag == PARALLAX_DT_RELAENT)
            relaent = (size_t)dyn[i].d_un.d_val;
        else if (dyn[i].d_tag == PARALLAX_DT_GNU_HASH)
            gnu_hash_v = dyn[i].d_un.d_ptr;
        else if (dyn[i].d_tag == PARALLAX_DT_HASH)
            hash_v = dyn[i].d_un.d_ptr;
        else if (dyn[i].d_tag == PARALLAX_DT_NEEDED &&
                 n_needed < PARALLAX_WD_MAX_TRUSTED_PATHS)
            needed_off[n_needed++] = (size_t)dyn[i].d_un.d_val;
    }

    if (!strtab_v || !symtab_v)
        return 1;
    if (relaent != sizeof(ParallaxRela64))
        return 1;

    {
        Elf64_Addr p = parallax_resolve_module_ptr(
                strtab_v, base, module_lo, module_hi, 7u);
        if (!p)
            return 1;
        strtab = (char const *)(uintptr_t)p;
    }
    {
        Elf64_Addr p = parallax_resolve_module_ptr(
                symtab_v, base, module_lo, module_hi, sizeof(ParallaxSym64));
        if (!p)
            return 1;
        symtab = (ParallaxSym64 const *)(uintptr_t)p;
    }
    {
        unsigned k;
        for (k = 0; k < n_needed; ++k) {
            char const *name;
            char tmp[PARALLAX_WD_TRUSTED_PATH_BYTES];
            size_t len = 0;
            size_t start = 0;
            if (needed_off[k] > (size_t)(module_hi - module_lo))
                continue;
            name = strtab + needed_off[k];
            if (!parallax_in_range(
                        (Elf64_Addr)(uintptr_t)name, 2u, module_lo, module_hi))
                continue;
            while (name[len] != 0 && len + 1u < sizeof(tmp)) {
                if (name[len] == '/')
                    start = len + 1u;
                ++len;
            }
            if (len == 0 || len + 1u >= sizeof(tmp))
                continue;
            {
                size_t j;
                for (j = 0; j < len - start; ++j)
                    tmp[j] = name[start + j];
                tmp[len - start] = 0;
            }
            parallax_trust_add_path(st, tmp);
        }
    }
    parallax_find_self_trust_init(
            st, symtab, strtab, base, module_lo, module_hi,
            gnu_hash_v, hash_v);
    st->api.abi_version = PARALLAX_SELF_TRUST_ABI;
    st->api.reserved = 0;
    st->api.ctx = st;
    st->api.begin = parallax_self_trust_begin;
    st->api.end = parallax_self_trust_end;
    st->api.grant_all = parallax_self_trust_grant_all;
    st->api.grant_slot = parallax_self_trust_grant_slot;
    st->api.grant_range = parallax_self_trust_grant_range;
    st->api.trust_path = parallax_self_trust_trust_path;

    if (jmprel_v && pltrelsz) {
        Elf64_Addr p;
        if (pltrel != PARALLAX_DT_RELA)
            return 1;
        p = parallax_resolve_module_ptr(
                jmprel_v, base, module_lo, module_hi, pltrelsz);
        if (!p)
            return 1;
        jmprel = (ParallaxRela64 const *)(uintptr_t)p;
    }
    if (rela_v && relasz) {
        Elf64_Addr p = parallax_resolve_module_ptr(
                rela_v, base, module_lo, module_hi, relasz);
        if (!p)
            return 1;
        rela = (ParallaxRela64 const *)(uintptr_t)p;
    }

    for (pass = 0; pass < 2u; ++pass) {
        if (jmprel && pltrelsz &&
            parallax_guard_rela_table(
                jmprel, pltrelsz, symtab, strtab,
                base, module_lo, module_hi, st, pass ? 1 : 0))
            return 1;
        if (rela && relasz && (void const *)rela != (void const *)jmprel &&
            parallax_guard_rela_table(
                rela, relasz, symtab, strtab,
                base, module_lo, module_hi, st, pass ? 1 : 0))
            return 1;
    }

    /* Seal every file-backed read-only segment, including .rodata URL/API
       strings. Large segments are covered by consecutive windows. */
    for (i = 0; phdr + i < phdrN; ++i) {
        ElfW(Phdr) const *p = phdr + i;
        Elf64_Addr lo, end;
        if (p->p_type != PT_LOAD || (p->p_flags & PF_W) || p->p_filesz == 0)
            continue;
        if (p->p_vaddr > ~(Elf64_Addr)0 - base)
            continue;
        lo = base + p->p_vaddr;
        if (p->p_filesz > ~(Elf64_Addr)0 - lo)
            continue;
        end = lo + p->p_filesz;
        while (lo < end && st->n_segments < PARALLAX_WD_MAX_SEGMENTS) {
            Elf64_Addr hi = lo + PARALLAX_WD_MAX_SEGMENT_BYTES;
            ParallaxSegment64 *seg = &st->segments[st->n_segments];
            if (hi > end || hi < lo)
                hi = end;
            seg->lo = lo;
            seg->hi = hi;
            seg->hash = parallax_hash_bytes(
                    (void const *)(uintptr_t)lo, (size_t)(hi - lo));
            ++st->n_segments;
            lo = hi;
        }
        if (lo < end)
            truncated_segments = 1;
    }

    if (truncated_segments || st->n_segments == 0)
        return 1; /* truncated layout: fail closed */

    /* Freeze only the active self-integrity implementation. Environment,
       root, tracer and foreign-module scanners are deliberately excluded. */
    if (parallax_code_guard_add(st, (void const *)(uintptr_t)&parallax_mark_tampered) ||
        parallax_code_guard_add(st, (void const *)(uintptr_t)&parallax_watchdog_tick) ||
        parallax_code_guard_add(st, (void const *)(uintptr_t)&parallax_guard_capture) ||
        parallax_code_guard_add(st, (void const *)(uintptr_t)&parallax_hash_bytes) ||
        parallax_code_guard_add(st, (void const *)(uintptr_t)&parallax_code_guard_add) ||
        parallax_code_guard_add(st, (void const *)(uintptr_t)&parallax_install_guards) ||
        parallax_code_guard_add(st, (void const *)(uintptr_t)&parallax_self_trust_refresh) ||
        parallax_code_guard_add(st, (void const *)(uintptr_t)&parallax_self_trust_seal) ||
        parallax_code_guard_add(st, (void const *)(uintptr_t)&parallax_module_caller) ||
        parallax_code_guard_add(st, (void const *)(uintptr_t)&parallax_self_trust_begin) ||
        parallax_code_guard_add(st, (void const *)(uintptr_t)&parallax_self_trust_end) ||
        parallax_code_guard_add(st, (void const *)(uintptr_t)&parallax_self_trust_grant_all) ||
        parallax_code_guard_add(st, (void const *)(uintptr_t)&parallax_self_trust_grant_slot) ||
        parallax_code_guard_add(st, (void const *)(uintptr_t)&parallax_self_trust_grant_range) ||
        parallax_code_guard_add(st, (void const *)(uintptr_t)&parallax_self_trust_trust_path))
        return 1;

    if (!parallax_watchdog_start(st))
        return 1;
    *out_st = st;
    return 0;
}

static PARALLAX_NOINLINE int parallax_runtime_precheck(
        Elf64_Addr *libc_lo,
        Elf64_Addr *libc_hi,
        Elf64_Addr *curl_lo,
        Elf64_Addr *curl_hi,
        Elf64_Addr *ssl_lo,
        Elf64_Addr *ssl_hi) {
    /* Collect only trusted owners used by protected critical imports.
       Framework names, root state, debugger state and unrelated mappings are
       deliberately ignored. */
    (void)parallax_maps_scan(
            libc_lo, libc_hi,
            curl_lo, curl_hi,
            ssl_lo, ssl_hi,
            0 /* collect ranges only; never reject the environment */);
    return 0;

}

#endif /* __aarch64__ */

extern char *upx_mmap_and_fd(  // x86_64 Android emulator of i386 is not faithful
     void *ptr  // desired address
     , unsigned len  // also pre-allocate space in file
     , char *pathname  // 0 ==> call get_upxfn_path, which stores if 1st time
);

#if defined(__x86_64__)  //{
char *
make_hatch(
    ElfW(Phdr) const *const phdr,
    char *next_unc,
    unsigned frag_mask
)
{
    unsigned *hatch = 0;
    unsigned code[3] = {
        0x5e5f050f,  // syscall; pop %arg1{%rdi}; pop %arg2{%rsi}
        0xff3e585a,  // pop %arg3{%rdx}; pop %rax; notrack jmp
        0x909090e0   // *%rax; nop; nop; nop
    };
    DPRINTF("make_hatch %%p %%p %%x\\n", phdr, next_unc, frag_mask);
    if (phdr->p_type==PT_LOAD && phdr->p_flags & PF_X) {
        next_unc += phdr->p_memsz - phdr->p_filesz;  // Skip over local .bss
        frag_mask &= -(long)next_unc;  // bytes left on page
        if (sizeof(code) <= frag_mask) {
            hatch = (unsigned *)next_unc;
            hatch[0] = code[0];
            hatch[1] = code[1];
            hatch[2] = code[2];
        }
        else { // Does not fit at hi end of .text, so must use a new page "permanently"
            unsigned long fdmap = (long)upx_mmap_and_fd((void *)0, sizeof(code), nullptr);
            unsigned mfd = -1+ (0xfff& fdmap);
            write(mfd, &code, sizeof(code));
            hatch = mmap((void *)(fdmap & ~0xffful), sizeof(code),
              PROT_READ|PROT_EXEC, MAP_PRIVATE, mfd, 0);
            close(mfd);
        }
    }
    DPRINTF("hatch=%%p\\n", hatch);
    return (char *)hatch;
}
#elif defined(__powerpc64__)  //}{
static unsigned
ORRX(unsigned ra, unsigned rs, unsigned rb) // or ra,rs,rb
{
    return (31<<26) | ((037&(rs))<<21) | ((037&(ra))<<16) | ((037&(rb))<<11) | (444<<1) | 0;
}

static char *
make_hatch(
    ElfW(Phdr) const *const phdr,
    char *next_unc,
    unsigned frag_mask
)
{
    unsigned code[4] = {
        0x44000002,  // sc
        ORRX(12,31,31),  // movr r12,r31 ==> or r12,r31,r31
        0x38800000,  // li r4,0
        0x4e800020,  // blr
    };
    unsigned *hatch = 0;
    DPRINTF("make_hatch %%p %%p %%x\\n", phdr, next_unc, frag_mask);
    if (phdr->p_type==PT_LOAD && phdr->p_flags & PF_X) {
        next_unc += phdr->p_memsz - phdr->p_filesz;  // Skip over local .bss
        frag_mask &= -(long)next_unc;  // bytes left on page
        if (4*4 <= frag_mask) {
            hatch = (unsigned *)(void *)(~3ul & (long)(3+ next_unc);
            hatch[0]= code[0];
            hatch[1]= code[1];
            hatch[2]= code[2];
            hatch[3]= code[3];
        }
        else { // Does not fit at hi end of .text, so must use a new page "permanently"
            int mfd = memfd_create(addr_string("parallax"), 0);  // the directory entry
            Pwrite(mfd, code, sizeof(code));
            hatch = Pmap(0, sizeof(code), PROT_READ|PROT_EXEC, MAP_PRIVATE, mfd, 0);
            close(mfd);
        }
    }
    DPRINTF("hatch=%%p\\n", hatch);
    return hatch;
}
#elif defined(__riscv)  //}{
extern void *my_memcpy(void *, const void *, long unsigned int);

static void * __attribute__((noinline))
make_hatch(
    ElfW(Phdr) const *const phdr,
    char *next_unc,
    unsigned const frag_mask
)
{
    unsigned long a = (unsigned long)next_unc;
    short *hatch = (short *)((1u & a) + a);
#define SZ_CODE (8*sizeof(short))
    char const *code;  // embedded "\x00" terminates!
    asm("jal %0,0f; \
        .int 0x00000073; \
        .short 0x6502, 0x65a2, 0x6642, 0x60e2, 0x6105; \
        .short 0x8082; \
     0: .balign 4" \
/*out*/ : "=r"(code) \
/* in*/ : \
/*und*/ : );
    DPRINTF("make_hatch %%p %%p %%x\\n", phdr, next_unc, frag_mask);
    if (phdr->p_type==PT_LOAD && phdr->p_flags & PF_X) {
        if (SZ_CODE <= (unsigned)(frag_mask & -(long)hatch)) {
            my_memcpy(hatch, code, SZ_CODE);
        }
        else { // Does not fit at hi end of .text, so must use a new page "permanently"
            int mfd = memfd_create(addr_string("parallax"), MFD_EXEC);  // the directory entry
            write(mfd, &code, SZ_CODE);
            hatch = mmap(0, SZ_CODE, PROT_READ|PROT_EXEC, MAP_SHARED, mfd, 0);
            close(mfd);
        }
    }
    DPRINTF("hatch=%%p\\n", hatch);
    return hatch;
}
#elif defined(__aarch64__)  //}{
static char *
make_hatch(
    ElfW(Phdr) const *const phdr,
    char *next_unc,
    unsigned frag_mask
)
{
    unsigned code[4] = {
        0xd503201f,  // nop: keep the unfolded loader region mapped so the
                     // persistent Parallax Watchdog code/signal handler stays
                     // valid after DT_INIT returns (in-memory only; no file)
        0xa9417be2,  // ldp x2,lr,[sp,#2*8)]
        0xa8c207e0,  // ldp x0,x1,[sp], 4*8
        0xd65f03c0,  // ret: AArch64 return instruction (BTI-aware Android)
    };
    unsigned *hatch = 0;
    DPRINTF("make_hatch phdr=%%p  next_unc=%%p  frag_mask= %%x\\n",
        phdr, next_unc, frag_mask);
    if (phdr->p_type==PT_LOAD && phdr->p_flags & PF_X) {
        next_unc += phdr->p_memsz - phdr->p_filesz;  // Skip over local .bss
        frag_mask &= -(long)next_unc;  // bytes left on page
        if (4*4 <= frag_mask) {
            hatch = (unsigned *)(void *)(~3ul & (long)(3+ next_unc));
            hatch[0]= code[0];
            hatch[1]= code[1];
            hatch[2]= code[2];
            hatch[3]= code[3];
            hatch = (unsigned *)&hatch[0];
        }
        else { // Does not fit at hi end of .text, so must use a new page "permanently"
            int mfd = memfd_create(addr_string("parallax"), 0);  // the directory entry
            Pwrite(mfd, code, sizeof(code));
            void *mfd_addr = Pmap(0, sizeof(code), PROT_READ|PROT_EXEC, MAP_PRIVATE, mfd, 0);
            close(mfd);
            hatch = (unsigned *)mfd_addr;
        }
    }
    DPRINTF("hatch=%%p\\n", hatch);
    return (char *)hatch;
}
#endif  //}

// The PF_* and PROT_* bits are {1,2,4}; the conversion table fits in 32 bits.
#define REP8(x) \
    ((x)|((x)<<4)|((x)<<8)|((x)<<12)|((x)<<16)|((x)<<20)|((x)<<24)|((x)<<28))
#define EXP8(y) \
    ((1&(y)) ? 0xf0f0f0f0 : (2&(y)) ? 0xff00ff00 : (4&(y)) ? 0xffff0000 : 0)
#define PF_TO_PROT(pf) \
    ((PROT_READ|PROT_WRITE|PROT_EXEC) & ( \
        ( (REP8(PROT_EXEC ) & EXP8(PF_X)) \
         |(REP8(PROT_READ ) & EXP8(PF_R)) \
         |(REP8(PROT_WRITE) & EXP8(PF_W)) \
        ) >> ((pf & (PF_R|PF_W|PF_X))<<2) ))

#undef PAGE_MASK

#if defined(__riscv) || defined(__aarch64__) // ARM64 gets page mask from ELF-SO entry
extern ElfW(Addr) get_page_mask(void);
#else  //}{
static ElfW(Addr)
get_page_mask(void)  // the mask which KEEPS the page, discards the offset
{
    ElfW(Addr) rv = ~0xffful;  // default to (PAGE_SIZE == 4KiB)
    int fd = openat(0, addr_string("/proc/self/auxv"), O_RDONLY, 0);
    if (0 <= fd) {
        ElfW(auxv_t) data[40];
        ElfW(auxv_t) *end = &data[read(fd, data, sizeof(data)) / sizeof(data[0])];
        close(fd);
        ElfW(auxv_t) *ptr; for (ptr = &data[0]; ptr < end ; ++ptr) {
            if (AT_PAGESZ == ptr->a_type) {
                rv = (0u - ptr->a_un.a_val);
                break;
            }
        }
    }
    DPRINTF("get_page_mask= %%p\\n", rv);
    return rv;
}
#endif  //}

extern void *memcpy(void *dst, void const *src, size_t n);
extern void *memset(void *dst, int val, size_t n);

// maximum page sizes
#if defined(__powerpc64__) || defined(__powerpc__) || defined(__aarch64__)
#define SAVED_SIZE (1<<16)  /* 64 KB */
#else
#define SAVED_SIZE (1<<14)  /* 16 KB */
#endif

#ifndef __arm__  //{
// Segregate large local array, to avoid code bloat due to large displacements.
static void
underlay(unsigned size, char *ptr, unsigned page_mask)
{
    unsigned frag = ~page_mask & (unsigned)(long)ptr;
    if (frag) {
        unsigned saved[SAVED_SIZE / sizeof(unsigned)];  // want alignment
        ptr -= frag;
        memcpy(saved, ptr, frag);
        mmap(ptr, frag + size, PROT_WRITE|PROT_READ,
            MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        memcpy(ptr, saved, frag);
    }
    else { // already page-aligned
        mmap(ptr, frag + size, PROT_WRITE|PROT_READ,
            MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    }
}
#else  //}{ // use assembler because large local array on __arm__ is horrible
extern void
underlay(unsigned size, char *ptr, unsigned page_mask);
#endif  //}

// Exchange the bits with values 4 (PF_R, PROT_EXEC) and 1 (PF_X, PROT_READ)
// Use table lookup into a PIC-string that pre-computes the result.
unsigned PF_to_PROT(ElfW(Phdr) const *phdr)
{
    return 7& addr_string("@\x04\x02\x06\x01\x05\x03\x07")
        [phdr->p_flags & (PF_R|PF_W|PF_X)];
}

unsigned
fini_SELinux(
    unsigned size,
    char *ptr,
    ElfW(Phdr) const *phdr,
    unsigned mfd,
    ElfW(Addr) base
)
{
    DPRINTF("fini_SELinux  size=%%p  ptr=%%p  phdr=%%p  mfd=%%p  base=%%p\\n",
            size, ptr, phdr, mfd, base);
    if (phdr->p_flags & PF_X) {
        // Map the contents of mfd as per *phdr.

        Psync(ptr, size, MS_SYNC); // be sure file gets de-compressed bytes
            // Android 14 gets -EINVAL; ignore it

        Punmap(ptr, size);
        Pmap(ptr, size, PF_to_PROT(phdr), MAP_FIXED|MAP_PRIVATE, mfd, 0);
        close(mfd);
    }
    else { // easy
        Pprotect( (char *)(phdr->p_vaddr + base), phdr->p_memsz, PF_to_PROT(phdr));
    }
    return 0;
}

unsigned
prep_SELinux(unsigned size, char *ptr, ElfW(Addr) page_mask) // returns mfd
{
    // Cannot set PROT_EXEC except via mmap() into a region (Linux "vma")
    // that has never had PROT_WRITE.  So use a Linux-only "memory file"
    // to hold the contents.
    unsigned saved[SAVED_SIZE / sizeof(unsigned)];  // want alignment
    char *page = (char *)(page_mask & (ElfW(Addr))ptr);
    unsigned frag = (unsigned)(ptr - page);
    if (frag) {
        memcpy(saved, page, frag);
    }
    char *val = upx_mmap_and_fd(page, frag + size, nullptr);
    unsigned mfd = 0xfff & (unsigned)(ElfW(Addr))val;
    val -= mfd; --mfd;
    if (val != page) {
        err_exit(0x1262);
    }
    if (frag)
        write(mfd, saved, frag);  // Save lo fragment of contents on page.
    return mfd;
}

typedef struct {
    long argc;
    char **argv;
    char **envp;
} So_args;

typedef struct {
    unsigned off_reloc;  // distance back to &ElfW(Ehdr)
    unsigned off_user_DT_INIT;
    unsigned off_xct_off;  // where un-compressed bytes end
    unsigned off_info;  //  xct_off: {l_info; p_info; b_info; compressed data)
} So_info;

/*************************************************************************
// upx_so_main - called by our folded entry code
**************************************************************************/

void *
upx_so_main(  // returns &escape_hatch
    So_info *so_info,
    So_args *so_args,
    ElfW(Ehdr) *elf_tmp  // scratch for ElfW(Ehdr) and ElfW(Phdrs)
)
{
    unsigned const parallax_off_reloc = so_info->off_reloc;
    unsigned const parallax_off_info = so_info->off_info;
    if (parallax_off_reloc < sizeof(So_info) ||
        parallax_off_info >= parallax_off_reloc ||
        parallax_off_reloc > (1u << 30) ||
        parallax_off_reloc - parallax_off_info <
            sizeof(struct l_info) + sizeof(struct p_info) + sizeof(struct b_info)) {
        err_exit(80);
    }

    ElfW(Addr) const page_mask = get_page_mask();
#if defined(__aarch64__)
    Elf64_Addr parallax_libc_lo = 0;
    Elf64_Addr parallax_libc_hi = 0;
    Elf64_Addr parallax_curl_lo = 0;
    Elf64_Addr parallax_curl_hi = 0;
    Elf64_Addr parallax_ssl_lo = 0;
    Elf64_Addr parallax_ssl_hi = 0;
    if (parallax_runtime_precheck(
                &parallax_libc_lo, &parallax_libc_hi,
                &parallax_curl_lo, &parallax_curl_hi,
                &parallax_ssl_lo, &parallax_ssl_hi))
        err_exit(90);
#endif
    char *const va_load = (char *)&so_info->off_reloc - so_info->off_reloc;
    So_info so_infc;  // So_info Copy
    memcpy(&so_infc, so_info, sizeof(so_infc));  // before de-compression overwrites
    unsigned const xct_off = so_infc.off_xct_off;  (void)xct_off;

    char *const cpr_ptr = parallax_off_info + va_load;
    unsigned const cpr_len = parallax_off_reloc - parallax_off_info;
    if (cpr_len > (1u << 30))
        err_exit(81);
    typedef void (*Dt_init)(int argc, char *argv[], char *envp[]);
    Dt_init const dt_init = (Dt_init)(void *)(so_info->off_user_DT_INIT + va_load);
    DPRINTF("upx_so_main  va_load=%%p  so_infc=%%p  cpr_ptr=%%p  cpr_len=%%x  xct_off=%%x\\n",
        va_load, &so_infc, cpr_ptr, cpr_len, xct_off);
    // DO NOT USE *so_info AFTER THIS!!  It gets overwritten.

    // Copy compressed data before de-compression overwrites it.
    char *const sideaddr = mmap(nullptr, cpr_len, PROT_WRITE|PROT_READ,
        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    DPRINTF("&sideaddr=%%p\\n", &sideaddr);
    if (sideaddr == (char *)-1)
        err_exit(82); // anonymous transport copy could not be allocated
    memcpy(sideaddr, cpr_ptr, cpr_len);

    // Transition to copied data
    struct p_info *pinfo = (struct p_info *)(void *)(sideaddr + sizeof(struct l_info));
    unsigned const pvm_program_id = pinfo->p_progid;
    unsigned const parallax_pin_enabled = (pinfo->p_blocksize & 0x80000000u) != 0;
    unsigned const parallax_blocksize = pinfo->p_blocksize & 0x7fffffffu;
    if (pvm_program_id == 0 ||
        pinfo->p_filesize < 4096u ||
        pinfo->p_filesize > (1u << 30) ||
        parallax_blocksize < 8192u ||
        parallax_blocksize > (8u << 20)) {
        parallax_secure_zero(sideaddr, cpr_len);
        Punmap(sideaddr, cpr_len);
        err_exit(83);
    }
    /* In optional pin mode, verify before decompression and any DT_INIT.
       On mismatch exit_group(137), never attempt to execute packed code. */
    size_t const parallax_pin_extra = parallax_pin_enabled ? 32u : 0u;
#if defined(__aarch64__)
    unsigned char parallax_pin_unmasked[32] = {0};
#endif
    if (parallax_pin_enabled) {
#if defined(__aarch64__)
        unsigned char const *pin_encoded = (unsigned char const *)(sideaddr +
            sizeof(struct l_info) + sizeof(struct p_info));
        unsigned pin_state = pvm_program_id ^ 0x9e3779b9u;
        unsigned pin_i;
        if (sizeof(struct l_info) + sizeof(struct p_info) + 32u +
                sizeof(struct b_info) > cpr_len) {
            parallax_secure_zero(sideaddr, cpr_len);
            Punmap(sideaddr, cpr_len);
            exit_group(137);
        }
        for (pin_i=0;pin_i<32u;++pin_i) {
            pin_state = pin_state * 1664525u + 1013904223u;
            parallax_pin_unmasked[pin_i] = pin_encoded[pin_i] ^
                (unsigned char)(pin_state >> 24);
        }
        if (!parallax_pin_verify_apk(parallax_pin_unmasked, va_load)) {
            parallax_secure_zero(sideaddr, cpr_len);
            Punmap(sideaddr, cpr_len);
            exit_group(137);
        }
#else
        err_exit(92);
#endif
    }
    struct b_info *binfo = (struct b_info *)(void *)(sideaddr +
        sizeof(struct l_info) + sizeof(struct p_info) + parallax_pin_extra);
    DPRINTF("upx_so_main  va_load=%%p  sideaddr=%%p  b_info=%%p\\n",
        va_load, sideaddr, binfo);

    // All the destination page frames exist or have been reserved,
    // but the access permissions may be wrong and the data may be compressed.
    // Also, rtld maps the convex hull of all PT_LOAD but assumes that the
    // file supports those pages, even though the pages might lie beyond EOF.
    // If so, then Pprotect() is not enough: SIGBUS will occur.  Thus we
    // must mmap anonymous pages, except for first PT_LOAD with ELF headers.
    // So the general strategy (for each PT_LOAD) is:
    //   Save any contents on low end of destination page (the "prefix" pfx).
    //   mmap(,, PROT_WRITE|PROT_READ, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    //   Restore the prefix on the first destination page.
    //   De-compress from remaining [sideaddr, +sidelen).
    //   Pprotect(,, PF_TO_PROT(.p_flags));

    // Get the uncompressed ElfW(Ehdr) and ElfW(Phdr)
    // The first b_info is aligned, so direct access to fields is OK.
    if (binfo->sz_unc < sizeof(ElfW(Ehdr)) ||
        binfo->sz_unc > 4096u ||
        binfo->sz_cpr == 0 ||
        binfo->sz_cpr > binfo->sz_unc ||
        sizeof(struct l_info) + sizeof(struct p_info) + parallax_pin_extra +
            sizeof(*binfo) + (size_t)binfo->sz_cpr > cpr_len) {
        parallax_secure_zero(sideaddr, cpr_len);
        Punmap(sideaddr, cpr_len);
        err_exit(84);
    }
    Extent x1 = {binfo->sz_unc, (char *)elf_tmp};  // destination
    Extent x0 = {binfo->sz_cpr + sizeof(*binfo), (char *)binfo};  // source
    unpackExtent(&x0, &x1, pvm_program_id);  // de-compress _Ehdr and _Phdrs

    if (elf_tmp->e_ident[0] != 0x7f ||
        elf_tmp->e_ident[1] != 'E' ||
        elf_tmp->e_ident[2] != 'L' ||
        elf_tmp->e_ident[3] != 'F' ||
        elf_tmp->e_phentsize != sizeof(ElfW(Phdr)) ||
        elf_tmp->e_phnum == 0 ||
        elf_tmp->e_phnum > ((4096u - sizeof(ElfW(Ehdr))) / sizeof(ElfW(Phdr))) ||
        sizeof(ElfW(Ehdr)) + (size_t)elf_tmp->e_phnum * sizeof(ElfW(Phdr)) >
            binfo->sz_unc) {
        parallax_secure_zero(sideaddr, cpr_len);
        Punmap(sideaddr, cpr_len);
        err_exit(85);
    }

    ElfW(Phdr) const *phdr = (ElfW(Phdr) *)(1+ elf_tmp);
    ElfW(Phdr) const *const phdrN = &phdr[elf_tmp->e_phnum];

    // Process each read-only PT_LOAD.
    // A read+write PT_LOAD might be relocated by rtld before de-compression,
    // so it cannot be compressed.
    void *hatch = nullptr;
    ElfW(Addr) base = 0;
    int n_load = 0;

    for (; phdr < phdrN; ++phdr)
    if (phdr->p_type == PT_LOAD && !(phdr->p_flags & PF_W)) {
        if  (!base) {
            base = (ElfW(Addr))va_load - phdr->p_vaddr;
            DPRINTF("base=%%p\\n", base);
        }
        unsigned const va_top = phdr->p_filesz + phdr->p_vaddr;
        // Need un-aligned read of b_info to determine compression sizes.
        struct b_info al_bi;  // for aligned data from binfo
        x0.size = sizeof(struct b_info);
        xread(&x0, (char *)&al_bi, x0.size);  // aligned binfo
        x0.buf -= sizeof(al_bi);  // back up (the xread() was a peek)
        x0.size = al_bi.sz_cpr;
        x1.size = al_bi.sz_unc;
        x1.buf = (void *)(va_top + base - al_bi.sz_unc);

        DPRINTF("\\nphdr@%%p  p_offset=%%p  p_vaddr=%%p  p_filesz=%%p  p_memsz=%%p\\n",
            phdr, phdr->p_offset, phdr->p_vaddr, phdr->p_filesz, phdr->p_memsz);
        DPRINTF("x0=%%p  x1=%%p\\n", &x0, &x1);

        if ((phdr->p_filesz + phdr->p_offset) <= xct_off) { // va_top <= xct_off
            if (!n_load) {
                ++n_load;
                continue;  // 1st PT_LOAD is non-compressed loader tables ONLY!
            }
        }

        int mfd = 0;
        if (phdr->p_flags & PF_X) {
            mfd = prep_SELinux(x1.size, x1.buf, page_mask);
        }
        else {
            underlay(x1.size, x1.buf, page_mask);  // also makes PROT_WRITE
        }
        Extent xt = x1;
        unpackExtent(&x0, &x1, pvm_program_id);
        if (!hatch && phdr->p_flags & PF_X) {
            hatch = make_hatch(phdr, x1.buf, ~page_mask);
            fini_SELinux(xt.size, xt.buf, phdr, mfd, base);
        }
        ++n_load;
    }

#if defined(__aarch64__)
    /* Dynamic symbol and relocation tables are reliable only after all
       read-only PT_LOAD segments have been restored. This installs the
       load-time GOT/PLT checks and the periodic Parallax Watchdog. */
    {
        ParallaxWatchdogState *parallax_st = nullptr;
        if (parallax_install_guards(
                elf_tmp, va_load,
                parallax_libc_lo, parallax_libc_hi,
                parallax_curl_lo, parallax_curl_hi,
                parallax_ssl_lo, parallax_ssl_hi,
                &parallax_st))
            err_exit(91);

        /* Process-wide module presence is intentionally ignored. Integrity
           enforcement is limited to this protected image and its own slots. */

        /* Constructors and the optional self-trust init callback may install
           hooks or patch the protected image. Their mutations become the new
           baseline; the stub's own code guards remain frozen. */
        parallax_st->self_trust = 1;
        parallax_st->self_trust_budget = 0;
        if (parallax_st->self_trust_init)
            parallax_st->self_trust_init(&parallax_st->api);
        dt_init(so_args->argc, so_args->argv, so_args->envp);
        /* No-source-change mode: keep the owner window open briefly after
           constructors so a JNI_OnLoad that installs Dobby hooks is adopted.
           end() from the optional callback still seals immediately. */
        if (parallax_st->self_trust)
            parallax_st->self_trust_budget = PARALLAX_STARTUP_TRUST_TICKS;
        else
            parallax_self_trust_seal(parallax_st);
    }
#endif

    DPRINTF("Punmap sideaddr=%%p  cpr_len=%%p\\n", sideaddr, cpr_len);
#if defined(__aarch64__)
    /* Verify once more after DT_INIT, before the ephemeral PIN is zeroed. */
    if (parallax_pin_enabled &&
        !parallax_pin_verify_apk(parallax_pin_unmasked, va_load)) {
        parallax_secure_zero(sideaddr, cpr_len);
        Punmap(sideaddr, cpr_len);
        exit_group(137);
    }
#endif
#if defined(__aarch64__)
    parallax_secure_zero((char *)parallax_pin_unmasked, sizeof(parallax_pin_unmasked));
#endif
    parallax_secure_zero(sideaddr, cpr_len);
    Punmap(sideaddr, cpr_len);
    DPRINTF("returning hatch=%%p\\n", hatch);
    return hatch;
}

#if DEBUG  //{

#if defined(__powerpc64__) //{
#define __NR_write 4

typedef unsigned long size_t;

#if 0  //{
static int
write(int fd, char const *ptr, size_t len)
{
    register  int        sys asm("r0") = __NR_write;
    register  int         a0 asm("r3") = fd;
    register void const  *a1 asm("r4") = ptr;
    register size_t const a2 asm("r5") = len;
    __asm__ __volatile__("sc"
    : "=r"(a0)
    : "r"(sys), "r"(a0), "r"(a1), "r"(a2)
    : "r0", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13"
    );
    return a0;
}
#else //}{
ssize_t
write(int fd, void const *ptr, size_t len)
{
    register  int        sys asm("r0") = __NR_write;
    register  int         a0 asm("r3") = fd;
    register void const  *a1 asm("r4") = ptr;
    register size_t       a2 asm("r5") = len;
    __asm__ __volatile__("sc"
    : "+r"(sys), "+r"(a0), "+r"(a1), "+r"(a2)
    :
    : "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13"
    );
    return a0;
}
#endif  //}
#endif  //}

static int
unsimal(unsigned x, char *ptr, int n)
{
    unsigned m = 10;
    while (10 <= (x / m)) m *= 10;
    while (10 <= x) {
        unsigned d = x / m;
        x -= m * d;
        m /= 10;
        ptr[n++] = '0' + d;
    }
    ptr[n++] = '0' + x;
    return n;
}

static int
decimal(int x, char *ptr, int n)
{
    if (x < 0) {
        ptr[n++] = '-';
    }
    return unsimal(-x, ptr, n);
}

static int
heximal(unsigned long x, char *ptr, int n)
{
    unsigned j = -1+ 2*sizeof(unsigned long);
    unsigned long m = 0xful << (4 * j);
    for (; j; --j, m >>= 4) { // omit leading 0 digits
        if (m & x) break;
    }
    for (; m; --j, m >>= 4) {
        unsigned d = 0xf & (x >> (4 * j));
        ptr[n++] = ((10<=d) ? ('a' - 10) : '0') + d;
    }
    return n;
}

#define va_arg      __builtin_va_arg
#define va_end      __builtin_va_end
#define va_list     __builtin_va_list
#define va_start    __builtin_va_start

static int
dprintf(char const *fmt, ...)
{
    int n= 0;
    char const *literal = 0;  // NULL
    char buf[24];  // ~0ull == 18446744073709551615 ==> 20 chars
    va_list va; va_start(va, fmt);
    for (;;) {
        char c = *fmt++;
        if (!c) { // end of fmt
            if (literal) {
                goto finish;
            }
            break;  // goto done
        }
        if ('%'!=c) {
            if (!literal) {
                literal = fmt;  // 1 beyond start of literal
            }
            continue;
        }
        // '%' == c
        if (literal) {
finish:
            n += write(2, -1+ literal, fmt - literal);
            literal = 0;  // NULL
            if (!c) { // fmt already ended
               break;  // goto done
            }
        }
        switch (c= *fmt++) { // deficiency: does not handle _long_
        default: { // un-implemented conversion
            n+= write(2, -1+ fmt, 1);
        } break;
        case 0: { // fmt ends with "%\0" ==> ignore
            goto done;
        } break;
        case 'u': {
            n+= write(2, buf, unsimal((unsigned)(unsigned long)va_arg(va, void *), buf, 0));
        } break;
        case 'd': {
            n+= write(2, buf, decimal((int)(unsigned long)va_arg(va, void *), buf, 0));
        } break;
        case 'p': {
            buf[0] = '0';
            buf[1] = 'x';
            n+= write(2, buf, heximal((unsigned long)va_arg(va, void *), buf, 2));
        } break;
        case 'x': {
            buf[0] = '0';
            buf[1] = 'x';
            n+= write(2, buf, heximal((unsigned)(unsigned long)va_arg(va, void *), buf, 2));
        } break;
        } // 'switch'
    }
done:
    va_end(va);
    return n;
 }
#endif  //}

/* vim:set ts=4 sw=4 et: */
