/* tcmalloc_shim.c — drop-in replacement for the 2013-era
 * libtcmalloc_minimal.so.0 shipped in the csgo-lite bundle.
 *
 * WHY: run 21/22/23 (37137252174/37138133460/37142215080) die 5s after
 * launch with SIGSEGV at protobuf RepeatedPtrFieldBase::Add inside
 * libvideo.so (static protobuf, zero dynamic protobuf refs -> self-
 * contained). The rep_ backing array faults at a DETERMINISTIC offset
 * relative to libvideo.so's base (+0x37f8880 across runs with different
 * ASLR) - the signature of an allocator whose virtual-address bookkeeping
 * broke. Prime suspect: the ancient tcmalloc_minimal interposing
 * malloc/new for every engine module on Ubuntu 24.04 (glibc 2.39, Azure
 * kernel). This shim exports the same allocator surface and forwards
 * everything to glibc, neutralizing tcmalloc entirely.
 *
 * Bridge is exonerated (run 23: attempt 3 bridge-passive and attempt 4
 * no-preload crashed identically), so the allocator is the next bisect.
 */
#define _GNU_SOURCE
#include <stddef.h>
#include <string.h>

/* glibc's internal allocator entry points - exported exactly for allocator
 * shims; no dlsym, no bootstrap arena, no reentrancy hazards */
extern void *__libc_malloc(size_t);
extern void  __libc_free(void *);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void *__libc_memalign(size_t, size_t);

void *malloc(size_t n)            { return __libc_malloc(n); }
void   free(void *p)              { __libc_free(p); }
void *calloc(size_t a, size_t b)  { return __libc_calloc(a, b); }
void *realloc(void *p, size_t n)  { return __libc_realloc(p, n); }
void *memalign(size_t a, size_t n){ return __libc_memalign(a, n); }

void *valloc(size_t n)        { return __libc_memalign(4096, n); }
void *pvalloc(size_t n)       { size_t pg = 4096; return __libc_memalign(pg, (n + pg - 1) & ~(pg - 1)); }
int posix_memalign(void **out, size_t align, size_t n)
{
    void *p = __libc_memalign(align, n);
    if (!p) return 1 /*ENOMEM*/;
    *out = p; return 0;
}
void *aligned_alloc(size_t align, size_t n) { return __libc_memalign(align, n); }

size_t malloc_usable_size(void *p)
{
    /* glibc: usable size of a malloc block; emulate conservatively with the
     * malloc_trim-adjacent internal: malloc_usable_size is public in libc */
    extern size_t __libc_malloc_usable_size(void *) __attribute__((weak));
    if (__libc_malloc_usable_size) return __libc_malloc_usable_size(p);
    return 0;
}

/* ---- C++ operators (bundle tcmalloc interposes new/delete) ---- */
void *_Znwmm(size_t n, size_t pad); /* keep c89 compilers calm */
void *_Znwm(size_t n)                       { return __libc_malloc(n); }
void *_ZnwmRKSt9nothrow_t(size_t n, void *x) { (void)x; return __libc_malloc(n); }
void *_Znam(size_t n)                       { return __libc_malloc(n); }
void *_ZnamRKSt9nothrow_t(size_t n, void *x) { (void)x; return __libc_malloc(n); }
void _ZdlPv(void *p)                        { __libc_free(p); }
void _ZdlPvm(void *p, size_t n)             { (void)n; __libc_free(p); }
void _ZdlPvRKSt9nothrow_t(void *p, void *x) { (void)x; __libc_free(p); }
void _ZdaPv(void *p)                        { __libc_free(p); }
void _ZdaPvm(void *p, size_t n)             { (void)n; __libc_free(p); }
void _ZdaPvRKSt9nothrow_t(void *p, void *x) { (void)x; __libc_free(p); }
/* C++17 aligned ops (harmless if unreferenced) */
void *_ZnwmSt11align_val_t(size_t n, size_t a)             { return __libc_memalign(a, n); }
void *_ZnamSt11align_val_t(size_t n, size_t a)             { return __libc_memalign(a, n); }
void *_ZnwmSt11align_val_tRKSt9nothrow_t(size_t n, size_t a, void *x) { (void)x; return __libc_memalign(a, n); }
void *_ZnamSt11align_val_tRKSt9nothrow_t(size_t n, size_t a, void *x) { (void)x; return __libc_memalign(a, n); }
void _ZdlPvSt11align_val_t(void *p, size_t a)              { (void)a; __libc_free(p); }
void _ZdlPvmSt11align_val_t(void *p, size_t n, size_t a)   { (void)n; (void)a; __libc_free(p); }
void _ZdaPvSt11align_val_t(void *p, size_t a)              { (void)a; __libc_free(p); }
void _ZdaPvmSt11align_val_t(void *p, size_t n, size_t a)   { (void)n; (void)a; __libc_free(p); }

/* ---- tc_* aliases ---- */
void *tc_malloc(size_t n)                     { return __libc_malloc(n); }
void  tc_free(void *p)                        { __libc_free(p); }
void *tc_realloc(void *p, size_t n)           { return __libc_realloc(p, n); }
void *tc_calloc(size_t a, size_t b)           { return __libc_calloc(a, b); }
void  tc_cfree(void *p)                       { __libc_free(p); }
void *tc_memalign(size_t a, size_t n)         { return __libc_memalign(a, n); }
void *tc_valloc(size_t n)                     { return valloc(n); }
void *tc_pvalloc(size_t n)                    { return pvalloc(n); }
void *tc_new(size_t n)                        { return __libc_malloc(n); }
void *tc_newarray(size_t n)                   { return __libc_malloc(n); }
void *tc_new_nothrow(size_t n, void *x)       { (void)x; return __libc_malloc(n); }
void *tc_newarray_nothrow(size_t n, void *x)  { (void)x; return __libc_malloc(n); }
void  tc_delete(void *p)                      { __libc_free(p); }
void  tc_deletearray(void *p)                 { __libc_free(p); }
void  tc_delete_nothrow(void *p, void *x)     { (void)x; __libc_free(p); }
void  tc_deletearray_nothrow(void *p, void *x){ (void)x; __libc_free(p); }
void  tc_delete_sized(void *p, size_t n)      { (void)n; __libc_free(p); }
void  tc_deletearray_sized(void *p, size_t n) { (void)n; __libc_free(p); }
size_t tc_malloc_size(void *p)                { return malloc_usable_size(p); }
size_t tc_mallinfo(void)                      { return 0; }
size_t tc_mallinfo64(void)                    { return 0; }

/* ---- MallocExtension / MallocHook / profiler C API: inert stubs ---- */
int   MallocExtension_GetAllocatedSize(void *p)             { (void)p; return (int)malloc_usable_size(p); }
int   MallocExtension_GetEstimatedAllocatedSize(void *p)    { (void)p; return (int)malloc_usable_size(p); }
int   MallocExtension_GetOwnership(void *p)                 { (void)p; return 1; }
int   MallocExtension_GetNumericProperty(const char *s, size_t *v) { (void)s; if (v) *v = 0; return 0; }
int   MallocExtension_SetNumericProperty(const char *s, size_t v)  { (void)s; (void)v; return 0; }
void  MallocExtension_GetStats(char *b, int n)              { if (b && n > 0) b[0] = 0; }
void  MallocExtension_ReleaseFreeMemory(void)               {}
void  MallocExtension_ReleaseToSystem(size_t n)             { (void)n; }
size_t MallocExtension_GetThreadCacheSize(void)             { return 0; }
void  MallocExtension_MarkThreadIdle(void)                  {}
void  MallocExtension_MarkThreadBusy(void)                  {}
void  MallocExtension_MarkThreadTemporarilyIdle(void)       {}
int   MallocExtension_VerifyAllMemory(void)                 { return 1; }
int   MallocExtension_VerifyNewMemory(void *p)              { (void)p; return 1; }
int   MallocExtension_VerifyArrayNewMemory(void *p)         { (void)p; return 1; }
int   MallocExtension_VerifyMallocMemory(void *p)           { (void)p; return 1; }
int   MallocExtension_MallocMemoryStats(int a, int b, int c){ (void)a; (void)b; (void)c; return 1; }
int   MallocExtension_GetAllocatedSize_v2(void *p)          { return (int)malloc_usable_size(p); }
int   MallocHook_AddNewHook(void *h)                        { (void)h; return 0; }
int   MallocHook_RemoveNewHook(void *h)                     { (void)h; return 0; }
int   MallocHook_AddDeleteHook(void *h)                     { (void)h; return 0; }
int   MallocHook_RemoveDeleteHook(void *h)                  { (void)h; return 0; }
int   MallocHook_AddMmapHook(void *h)                       { (void)h; return 0; }
int   MallocHook_RemoveMmapHook(void *h)                    { (void)h; return 0; }
int   MallocHook_AddMunmapHook(void *h)                     { (void)h; return 0; }
int   MallocHook_RemoveMunmapHook(void *h)                  { (void)h; return 0; }
int   MallocHook_AddMremapHook(void *h)                     { (void)h; return 0; }
int   MallocHook_RemoveMremapHook(void *h)                  { (void)h; return 0; }
int   MallocHook_AddPreMmapHook(void *h)                    { (void)h; return 0; }
int   MallocHook_RemovePreMmapHook(void *h)                 { (void)h; return 0; }
int   MallocHook_AddSbrkHook(void *h)                       { (void)h; return 0; }
int   MallocHook_RemoveSbrkHook(void *h)                    { (void)h; return 0; }
int   MallocHook_AddPreSbrkHook(void *h)                    { (void)h; return 0; }
int   MallocHook_RemovePreSbrkHook(void *h)                 { (void)h; return 0; }
int   MallocHook_SetMmapReplacement(void *h)                { (void)h; return 0; }
int   MallocHook_RemoveMmapReplacement(void *h)             { (void)h; return 0; }
int   MallocHook_SetMunmapReplacement(void *h)              { (void)h; return 0; }
int   MallocHook_RemoveMunmapReplacement(void *h)           { (void)h; return 0; }
void *MallocHook_GetCallerStackTrace(void)                  { return 0; }
void  MallocHook_InitAtFirstAllocation_HeapLeakChecker(void){}
void  malloc_stats(void)                                    {}
struct mallinfo { int arena, ordblks, smblks, hblks, hblkhd, usmblks, fsmblks, uordblks, fordblks, keepcost; };
struct mallinfo mallinfo(void) { struct mallinfo m; memset(&m, 0, sizeof(m)); return m; }
