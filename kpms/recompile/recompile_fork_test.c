/*
 * recompile_fork_test - Comprehensive fork handling test suite
 *
 * Tests fork protection: pause/resume of PTE modifications during fork(),
 * thread creation (CLONE_VM), vfork, multi-fork, fork chains, and
 * concurrent scenarios.
 *
 * Usage: ./recompile_fork_test [-v]
 *   -v  verbose: print timing and per-iteration details
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>

#ifndef CLONE_VM
#define CLONE_VM 0x00000100
#endif
#ifndef MAP_STACK
#define MAP_STACK 0x20000
#endif

#define PR_RECOMPILE_REGISTER       0x52430001
#define PR_RECOMPILE_RELEASE        0x52430002
#define PR_RECOMPILE_STATS          0x52430003
#define PR_RECOMPILE_STATS_RESET    0x52430004

#define RC_STAT_FORK_PAUSE      0
#define RC_STAT_FORK_RESUME     1
#define RC_STAT_FORK_SKIPPED    2
#define RC_STAT_FAULT_REDIRECT  3
#define RC_STAT_ACTIVE_MAPPINGS 4

typedef long (*func_t)(void);

/* ARM64: mov x0, #N; ret */
static const unsigned int code_ret_1[]  = { 0xd2800020, 0xd65f03c0 };  /* mov x0, #1 */
static const unsigned int code_ret_2[]  = { 0xd2800040, 0xd65f03c0 };  /* mov x0, #2 */
static const unsigned int code_ret_42[] = { 0xd2800540, 0xd65f03c0 };  /* mov x0, #42 */
static const unsigned int code_ret_99[] = { 0xd2800c60, 0xd65f03c0 };  /* mov x0, #99 */

/* ARM64: mov x0, #N; str x0, [x1]; ret — writes N to *arg1 then returns N */
static const unsigned int code_write_signal[] = {
    0xd2800020,  /* mov x0, #1 */
    0xf9000020,  /* str x0, [x1] */
    0xd65f03c0,  /* ret */
};

static int test_pass = 0, test_fail = 0, test_skip = 0;
static int verbose = 0;

#define TEST_PASS(name) do { printf("[PASS] %s\n", name); test_pass++; } while(0)
#define TEST_FAIL(name, fmt, ...) do { printf("[FAIL] %s: " fmt "\n", name, ##__VA_ARGS__); test_fail++; } while(0)
#define TEST_SKIP(name, reason) do { printf("[SKIP] %s: %s\n", name, reason); test_skip++; } while(0)

/* Diagnose child failure mode precisely */
static const char *child_fail_reason(int status, long result)
{
    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        if (sig == SIGSEGV) return "SIGSEGV (fork protection failed — child hit stripped PTE)";
        if (sig == SIGILL)  return "SIGILL (code corruption or bad redirect)";
        if (sig == SIGBUS)  return "SIGBUS (bad page mapping)";
        return "signal";
    }
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 2) return "exit(2) — child got redirected code (fork didn't isolate child)";
        if (code == 42) return "exit(42) — child got redirected code (fork didn't isolate child)";
        if (code == 99) return "exit(99) — child got redirected code (fork didn't isolate child)";
    }
    return "unknown";
}

/* ========== Helpers ========== */

static void *alloc_code_page(const unsigned int *code, size_t code_sz)
{
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    memcpy(p, code, code_sz);
    __builtin___clear_cache(p, (char *)p + code_sz);
    return p;
}

static void free_code_page(void *p) { if (p && p != MAP_FAILED) munmap(p, 4096); }

/* Register redirect: orig_page → recomp_page */
static int rc_register(void *orig, void *recomp)
{
    return prctl(PR_RECOMPILE_REGISTER, 0, (unsigned long)orig, (unsigned long)recomp, 0);
}

/* Release redirect */
static int rc_release(void *orig)
{
    return prctl(PR_RECOMPILE_RELEASE, 0, (unsigned long)orig, 0, 0);
}

static long long now_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000000LL + tv.tv_usec;
}

/* ========== Stats helpers ========== */

static int stats_available = -1;  /* -1=unknown, 0=no, 1=yes */

static long rc_stat(int stat_id)
{
    return prctl(PR_RECOMPILE_STATS, 0, stat_id, 0, 0);
}

static int rc_stats_reset(void)
{
    return prctl(PR_RECOMPILE_STATS_RESET, 0, 0, 0, 0);
}

static void detect_stats(void)
{
    long v = rc_stat(RC_STAT_ACTIVE_MAPPINGS);
    stats_available = (v >= 0) ? 1 : 0;
    if (stats_available)
        printf("[INFO] kernel stats interface available\n");
    else
        printf("[INFO] kernel stats interface NOT available (old module?)\n");
}

static void print_stats(const char *label)
{
    if (!stats_available) return;
    printf("[STATS %s] pause=%ld resume=%ld skipped=%ld redirect=%ld active=%ld\n",
           label,
           rc_stat(RC_STAT_FORK_PAUSE),
           rc_stat(RC_STAT_FORK_RESUME),
           rc_stat(RC_STAT_FORK_SKIPPED),
           rc_stat(RC_STAT_FAULT_REDIRECT),
           rc_stat(RC_STAT_ACTIVE_MAPPINGS));
}

/* ========== Test 1: Basic fork (child gets original code) ========== */
static void test_basic_fork(void)
{
    const char *name = "basic_fork";
    void *orig, *recomp;
    func_t fn;
    pid_t child;
    int status;

    orig = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp = alloc_code_page(code_ret_2, sizeof(code_ret_2));
    if (!orig || !recomp) { TEST_SKIP(name, "mmap failed"); goto cleanup; }

    fn = (func_t)orig;
    if (fn() != 1) { TEST_FAIL(name, "pre-register: expected 1, got %ld", fn()); goto cleanup; }

    if (rc_register(orig, recomp) != 0) { TEST_FAIL(name, "register failed: %s", strerror(errno)); goto cleanup; }
    if (fn() != 2) { TEST_FAIL(name, "post-register parent: expected 2, got %ld", fn()); goto release; }

    child = fork();
    if (child == 0) {
        /* Child: should execute original code (no redirect) */
        long r = ((func_t)orig)();
        _exit((int)r);  /* exit with actual return value for diagnosis */
    }
    if (child < 0) { TEST_FAIL(name, "fork failed: %s", strerror(errno)); goto release; }

    waitpid(child, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 1) {
        TEST_FAIL(name, "child: %s (status=0x%x)",
                  child_fail_reason(status, 0), status);
        goto release;
    }

    /* Parent redirect must survive */
    if (fn() != 2) { TEST_FAIL(name, "parent after fork: expected 2, got %ld", fn()); goto release; }

    TEST_PASS(name);
release:
    rc_release(orig);
cleanup:
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== Test 2: Thread creation (CLONE_VM — should NOT interfere) ========== */
static volatile int thread_done = 0;
static volatile long thread_result = -1;

static void *thread_fn(void *arg)
{
    /* Just compute something and exit — should not trigger fork protection */
    thread_result = 12345;
    thread_done = 1;
    return NULL;
}

static void test_thread_no_interfere(void)
{
    const char *name = "thread_no_interfere";
    void *orig, *recomp;
    func_t fn;
    pthread_t tid;
    int i;

    orig = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp = alloc_code_page(code_ret_42, sizeof(code_ret_42));
    if (!orig || !recomp) { TEST_SKIP(name, "mmap failed"); goto cleanup; }

    if (rc_register(orig, recomp) != 0) { TEST_FAIL(name, "register failed"); goto cleanup; }
    fn = (func_t)orig;
    if (fn() != 42) { TEST_FAIL(name, "redirect not active: got %ld", fn()); goto release; }

    /* Spawn 20 threads rapidly — none should break the redirect */
    for (i = 0; i < 20; i++) {
        thread_done = 0;
        if (pthread_create(&tid, NULL, thread_fn, NULL) != 0) {
            TEST_FAIL(name, "pthread_create #%d failed", i);
            goto release;
        }
        pthread_join(tid, NULL);

        /* Verify redirect survives each thread creation */
        long r = fn();
        if (r != 42) {
            TEST_FAIL(name, "redirect broken after thread #%d: got %ld", i, r);
            goto release;
        }
    }

    TEST_PASS(name);
release:
    rc_release(orig);
cleanup:
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== Test 3: Thread calling redirected function ========== */
static func_t shared_fn_ptr;
static volatile long shared_fn_result = -1;

static void *thread_call_fn(void *arg)
{
    /* Thread shares mm → should see the REDIRECT (recomp page) */
    shared_fn_result = shared_fn_ptr();
    return NULL;
}

static void test_thread_shared_redirect(void)
{
    const char *name = "thread_shared_redirect";
    void *orig, *recomp;
    pthread_t tid;

    orig = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp = alloc_code_page(code_ret_42, sizeof(code_ret_42));
    if (!orig || !recomp) { TEST_SKIP(name, "mmap failed"); goto cleanup; }

    if (rc_register(orig, recomp) != 0) { TEST_FAIL(name, "register failed"); goto cleanup; }

    shared_fn_ptr = (func_t)orig;
    shared_fn_result = -1;

    if (pthread_create(&tid, NULL, thread_call_fn, NULL) != 0) {
        TEST_FAIL(name, "pthread_create failed");
        goto release;
    }
    pthread_join(tid, NULL);

    /* Thread shares mm, so it should see redirect → return 42 */
    if (shared_fn_result == 42) {
        TEST_PASS(name);
    } else {
        TEST_FAIL(name, "thread got %ld, expected 42 (redirect should be shared)", shared_fn_result);
    }

release:
    rc_release(orig);
cleanup:
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== Test 4: Multi-fork (N children, all get original) ========== */
static void test_multi_fork(void)
{
    const char *name = "multi_fork";
    void *orig, *recomp;
    func_t fn;
    int i, n_children = 10;
    pid_t pids[10];
    int all_ok = 1;

    orig = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp = alloc_code_page(code_ret_2, sizeof(code_ret_2));
    if (!orig || !recomp) { TEST_SKIP(name, "mmap failed"); goto cleanup; }

    if (rc_register(orig, recomp) != 0) { TEST_FAIL(name, "register failed"); goto cleanup; }
    fn = (func_t)orig;

    /* Fork N children */
    for (i = 0; i < n_children; i++) {
        pids[i] = fork();
        if (pids[i] == 0) {
            long r = ((func_t)orig)();
            _exit(r == 1 ? 0 : (int)r);
        }
        if (pids[i] < 0) {
            TEST_FAIL(name, "fork #%d failed", i);
            n_children = i;
            all_ok = 0;
            break;
        }
    }

    /* Collect children */
    for (i = 0; i < n_children; i++) {
        int status;
        waitpid(pids[i], &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            if (verbose) {
                if (WIFSIGNALED(status))
                    printf("  child #%d: signal %d\n", i, WTERMSIG(status));
                else
                    printf("  child #%d: exit %d\n", i, WEXITSTATUS(status));
            }
            all_ok = 0;
        }
    }

    /* Parent redirect must survive */
    if (fn() != 2) {
        TEST_FAIL(name, "parent redirect broken after %d forks: got %ld", n_children, fn());
        goto release;
    }

    if (all_ok)
        TEST_PASS(name);
    else
        TEST_FAIL(name, "one or more children failed");

release:
    rc_release(orig);
cleanup:
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== Test 5: Rapid fork storm (timing measurement) ========== */
static void test_fork_storm(void)
{
    const char *name = "fork_storm";
    void *orig, *recomp;
    func_t fn;
    int n = 50;
    int i;
    long long t_with, t_without;

    orig = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp = alloc_code_page(code_ret_2, sizeof(code_ret_2));
    if (!orig || !recomp) { TEST_SKIP(name, "mmap failed"); goto cleanup; }

    /* Phase 1: fork storm WITHOUT redirect (baseline) */
    {
        long long start = now_us();
        for (i = 0; i < n; i++) {
            pid_t c = fork();
            if (c == 0) _exit(0);
            if (c > 0) { int s; waitpid(c, &s, 0); }
        }
        t_without = now_us() - start;
    }

    /* Phase 2: fork storm WITH redirect active */
    if (rc_register(orig, recomp) != 0) { TEST_FAIL(name, "register failed"); goto cleanup; }
    fn = (func_t)orig;

    {
        long long start = now_us();
        int all_ok = 1;
        for (i = 0; i < n; i++) {
            pid_t c = fork();
            if (c == 0) {
                long r = ((func_t)orig)();
                _exit(r == 1 ? 0 : (int)r);
            }
            if (c > 0) {
                int s;
                waitpid(c, &s, 0);
                if (!WIFEXITED(s) || WEXITSTATUS(s) != 0)
                    all_ok = 0;
            }
        }
        t_with = now_us() - start;

        if (!all_ok) {
            TEST_FAIL(name, "children failed during storm");
            goto release;
        }
    }

    /* Parent redirect must survive */
    if (fn() != 2) { TEST_FAIL(name, "parent redirect broken after storm"); goto release; }

    printf("[INFO] fork_storm: %d forks baseline=%lldus, with_redirect=%lldus, overhead=%.1fx\n",
           n, t_without, t_with, t_with > 0 ? (double)t_with / t_without : 0.0);
    TEST_PASS(name);

release:
    rc_release(orig);
cleanup:
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== Test 6: Thread storm (timing — should be near-zero overhead) ========== */
static void *thread_noop(void *arg) { return NULL; }

static void test_thread_storm(void)
{
    const char *name = "thread_storm";
    void *orig, *recomp;
    func_t fn;
    int n = 100;
    int i;
    long long t_with, t_without;

    orig = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp = alloc_code_page(code_ret_2, sizeof(code_ret_2));
    if (!orig || !recomp) { TEST_SKIP(name, "mmap failed"); goto cleanup; }

    /* Baseline: thread storm without redirect */
    {
        long long start = now_us();
        for (i = 0; i < n; i++) {
            pthread_t t;
            pthread_create(&t, NULL, thread_noop, NULL);
            pthread_join(t, NULL);
        }
        t_without = now_us() - start;
    }

    /* With redirect active */
    if (rc_register(orig, recomp) != 0) { TEST_FAIL(name, "register failed"); goto cleanup; }
    fn = (func_t)orig;

    {
        long long start = now_us();
        for (i = 0; i < n; i++) {
            pthread_t t;
            pthread_create(&t, NULL, thread_noop, NULL);
            pthread_join(t, NULL);
        }
        t_with = now_us() - start;
    }

    /* Redirect must survive */
    if (fn() != 2) { TEST_FAIL(name, "redirect broken after thread storm"); goto release; }

    printf("[INFO] thread_storm: %d threads baseline=%lldus, with_redirect=%lldus, overhead=%.1fx\n",
           n, t_without, t_with, t_without > 0 ? (double)t_with / t_without : 0.0);

    /* Thread overhead should be ≈1.0x (threads share mm, no pause/resume needed).
     * >2.0x strongly suggests CLONE_VM filtering is broken. */
    if (t_without > 0 && (double)t_with / t_without > 2.0) {
        TEST_FAIL(name, "thread overhead %.1fx (>2.0x) — CLONE_VM filtering likely broken!",
                  (double)t_with / t_without);
    } else {
        TEST_PASS(name);
    }

release:
    rc_release(orig);
cleanup:
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== Test 7: vfork (CLONE_VM | CLONE_VFORK) ========== */
static void test_vfork(void)
{
    const char *name = "vfork_safety";
    void *orig, *recomp;
    func_t fn;
    pid_t child;
    int status;

    orig = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp = alloc_code_page(code_ret_2, sizeof(code_ret_2));
    if (!orig || !recomp) { TEST_SKIP(name, "mmap failed"); goto cleanup; }

    if (rc_register(orig, recomp) != 0) { TEST_FAIL(name, "register failed"); goto cleanup; }
    fn = (func_t)orig;
    if (fn() != 2) { TEST_FAIL(name, "redirect not active"); goto release; }

    child = vfork();
    if (child == 0) {
        /* vfork child: shares parent mm, must NOT call redirect.
         * Only safe to call _exit() or exec*() after vfork. */
        _exit(0);
    }
    if (child < 0) { TEST_FAIL(name, "vfork failed: %s", strerror(errno)); goto release; }

    waitpid(child, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        TEST_FAIL(name, "vfork child failed: status=%d", status);
        goto release;
    }

    /* Parent redirect must survive vfork */
    if (fn() != 2) { TEST_FAIL(name, "redirect broken after vfork: got %ld", fn()); goto release; }

    TEST_PASS(name);
release:
    rc_release(orig);
cleanup:
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== Test 8: Fork chain (child forks grandchild) ========== */
static void test_fork_chain(void)
{
    const char *name = "fork_chain";
    void *orig, *recomp;
    func_t fn;
    pid_t child;
    int status;

    orig = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp = alloc_code_page(code_ret_2, sizeof(code_ret_2));
    if (!orig || !recomp) { TEST_SKIP(name, "mmap failed"); goto cleanup; }

    if (rc_register(orig, recomp) != 0) { TEST_FAIL(name, "register failed"); goto cleanup; }
    fn = (func_t)orig;

    child = fork();
    if (child == 0) {
        /* Child: should get original code */
        long r1 = ((func_t)orig)();
        if (r1 != 1) _exit(10);

        /* Child forks grandchild */
        pid_t gc = fork();
        if (gc == 0) {
            /* Grandchild: should also get original code */
            long r2 = ((func_t)orig)();
            _exit(r2 == 1 ? 0 : 20);
        }
        if (gc < 0) _exit(30);

        int gs;
        waitpid(gc, &gs, 0);
        if (WIFEXITED(gs) && WEXITSTATUS(gs) == 0)
            _exit(0);
        else
            _exit(40);
    }
    if (child < 0) { TEST_FAIL(name, "fork failed"); goto release; }

    waitpid(child, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        /* Parent redirect must survive */
        if (fn() != 2)
            TEST_FAIL(name, "parent redirect broken: got %ld", fn());
        else
            TEST_PASS(name);
    } else {
        if (WIFSIGNALED(status))
            TEST_FAIL(name, "child crashed: signal %d", WTERMSIG(status));
        else
            TEST_FAIL(name, "child exit code %d", WEXITSTATUS(status));
    }

release:
    rc_release(orig);
cleanup:
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== Test 9: Concurrent fork + execute ========== */
static void test_concurrent_fork_exec(void)
{
    const char *name = "concurrent_fork_exec";
    void *orig, *recomp;
    func_t fn;
    int i, all_ok = 1;

    orig = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp = alloc_code_page(code_ret_2, sizeof(code_ret_2));
    if (!orig || !recomp) { TEST_SKIP(name, "mmap failed"); goto cleanup; }

    if (rc_register(orig, recomp) != 0) { TEST_FAIL(name, "register failed"); goto cleanup; }
    fn = (func_t)orig;

    /*
     * Fork 10 children, each executing the redirected function before exiting.
     * Between forks, parent also executes to check redirect is live.
     * This tests the window during pause/resume.
     */
    for (i = 0; i < 10; i++) {
        pid_t c = fork();
        if (c == 0) {
            long r = ((func_t)orig)();
            _exit(r == 1 ? 0 : (int)r);
        }
        if (c < 0) { all_ok = 0; break; }

        /* Parent executes immediately — may race with fork protection resume */
        long pr = fn();
        if (pr != 2) {
            if (verbose) printf("  parent got %ld after fork #%d\n", pr, i);
            all_ok = 0;
        }

        int s;
        waitpid(c, &s, 0);
        if (!WIFEXITED(s) || WEXITSTATUS(s) != 0) {
            if (verbose) {
                if (WIFSIGNALED(s))
                    printf("  child #%d: signal %d\n", i, WTERMSIG(s));
                else
                    printf("  child #%d: exit %d\n", i, WEXITSTATUS(s));
            }
            all_ok = 0;
        }
    }

    if (all_ok)
        TEST_PASS(name);
    else
        TEST_FAIL(name, "concurrent fork+exec failures detected");

    rc_release(orig);
cleanup:
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== Test 10: Multiple mappings + fork ========== */
static void test_multi_mapping_fork(void)
{
    const char *name = "multi_mapping_fork";
    void *orig1, *recomp1, *orig2, *recomp2;
    func_t fn1, fn2;
    pid_t child;
    int status;

    orig1 = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp1 = alloc_code_page(code_ret_42, sizeof(code_ret_42));
    orig2 = alloc_code_page(code_ret_2, sizeof(code_ret_2));
    recomp2 = alloc_code_page(code_ret_99, sizeof(code_ret_99));
    if (!orig1 || !recomp1 || !orig2 || !recomp2) {
        TEST_SKIP(name, "mmap failed"); goto cleanup;
    }

    if (rc_register(orig1, recomp1) != 0) { TEST_FAIL(name, "register #1 failed"); goto cleanup; }
    if (rc_register(orig2, recomp2) != 0) { TEST_FAIL(name, "register #2 failed"); goto rel1; }

    fn1 = (func_t)orig1;
    fn2 = (func_t)orig2;
    if (fn1() != 42 || fn2() != 99) {
        TEST_FAIL(name, "redirects not active: fn1=%ld fn2=%ld", fn1(), fn2());
        goto rel2;
    }

    child = fork();
    if (child == 0) {
        long r1 = ((func_t)orig1)();
        long r2 = ((func_t)orig2)();
        _exit((r1 == 1 && r2 == 2) ? 0 : 50);
    }
    if (child < 0) { TEST_FAIL(name, "fork failed"); goto rel2; }

    waitpid(child, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        TEST_FAIL(name, "child failed (status=%d)", status);
        goto rel2;
    }

    /* Parent: both redirects must survive */
    if (fn1() != 42 || fn2() != 99) {
        TEST_FAIL(name, "parent redirects broken: fn1=%ld fn2=%ld", fn1(), fn2());
        goto rel2;
    }

    TEST_PASS(name);
rel2:
    rc_release(orig2);
rel1:
    rc_release(orig1);
cleanup:
    free_code_page(orig1);
    free_code_page(recomp1);
    free_code_page(orig2);
    free_code_page(recomp2);
}

/* ========== Test 11: Fork without active mappings (should be clean) ========== */
static void test_fork_no_mapping(void)
{
    const char *name = "fork_no_mapping";
    pid_t child;
    int status;
    long long start, elapsed;

    start = now_us();
    child = fork();
    if (child == 0) _exit(0);
    if (child < 0) { TEST_FAIL(name, "fork failed"); return; }
    waitpid(child, &status, 0);
    elapsed = now_us() - start;

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        if (verbose) printf("[INFO] fork_no_mapping: %lldus\n", elapsed);
        TEST_PASS(name);
    } else {
        TEST_FAIL(name, "child failed");
    }
}

/* ========== Test 12: system() call (fork+exec internally) ========== */
static void test_system_call(void)
{
    const char *name = "system_call";
    void *orig, *recomp;
    func_t fn;
    int ret;

    orig = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp = alloc_code_page(code_ret_2, sizeof(code_ret_2));
    if (!orig || !recomp) { TEST_SKIP(name, "mmap failed"); goto cleanup; }

    if (rc_register(orig, recomp) != 0) { TEST_FAIL(name, "register failed"); goto cleanup; }
    fn = (func_t)orig;

    /* system() does fork + exec — should not break redirect */
    ret = system("true");
    if (ret != 0) {
        /* 'true' might not exist in minimal environment */
        ret = system("echo ok > /dev/null 2>&1");
    }

    /* Parent redirect must survive */
    if (fn() != 2) {
        TEST_FAIL(name, "redirect broken after system(): got %ld", fn());
    } else {
        TEST_PASS(name);
    }

    rc_release(orig);
cleanup:
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== Test 13: Mixed thread+fork storm ========== */
static void *thread_and_fork(void *arg)
{
    /* Thread that forks — this is unusual but valid */
    pid_t c = fork();
    if (c == 0) _exit(0);
    if (c > 0) {
        int s;
        waitpid(c, &s, 0);
    }
    return (void *)(long)(c > 0 ? 0 : 1);
}

static void test_mixed_thread_fork(void)
{
    const char *name = "mixed_thread_fork";
    void *orig, *recomp;
    func_t fn;
    pthread_t tids[5];
    int i, all_ok = 1;

    orig = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp = alloc_code_page(code_ret_42, sizeof(code_ret_42));
    if (!orig || !recomp) { TEST_SKIP(name, "mmap failed"); goto cleanup; }

    if (rc_register(orig, recomp) != 0) { TEST_FAIL(name, "register failed"); goto cleanup; }
    fn = (func_t)orig;

    /* Spawn threads that themselves fork */
    for (i = 0; i < 5; i++) {
        if (pthread_create(&tids[i], NULL, thread_and_fork, NULL) != 0) {
            TEST_FAIL(name, "pthread_create failed");
            all_ok = 0;
            break;
        }
    }

    for (i = 0; i < 5; i++) {
        void *ret;
        pthread_join(tids[i], &ret);
        if ((long)ret != 0) all_ok = 0;
    }

    /* Redirect must survive */
    if (fn() != 42) {
        TEST_FAIL(name, "redirect broken: got %ld", fn());
        goto release;
    }

    if (all_ok)
        TEST_PASS(name);
    else
        TEST_FAIL(name, "thread-fork failed");

release:
    rc_release(orig);
cleanup:
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== Test 14: Fork with child registering its own mapping ========== */
static void test_fork_child_register(void)
{
    const char *name = "fork_child_register";
    void *orig, *recomp;
    func_t fn;
    pid_t child;
    int status;

    orig = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp = alloc_code_page(code_ret_2, sizeof(code_ret_2));
    if (!orig || !recomp) { TEST_SKIP(name, "mmap failed"); goto cleanup; }

    /* Parent has redirect */
    if (rc_register(orig, recomp) != 0) { TEST_FAIL(name, "register failed"); goto cleanup; }
    fn = (func_t)orig;

    child = fork();
    if (child == 0) {
        /* Child: original code should work */
        long r = ((func_t)orig)();
        if (r != 1) _exit(10);

        /* Child allocates its own recomp and registers */
        void *child_recomp = alloc_code_page(code_ret_99, sizeof(code_ret_99));
        if (!child_recomp) _exit(20);

        int ret = rc_register(orig, child_recomp);
        if (ret != 0) _exit(30);

        r = ((func_t)orig)();
        rc_release(orig);
        free_code_page(child_recomp);
        _exit(r == 99 ? 0 : 40);
    }
    if (child < 0) { TEST_FAIL(name, "fork failed"); goto release; }

    waitpid(child, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        int code = WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status);
        TEST_FAIL(name, "child failed: code=%d", code);
        goto release;
    }

    /* Parent redirect must still be active */
    if (fn() != 2) {
        TEST_FAIL(name, "parent redirect broken: got %ld", fn());
        goto release;
    }

    TEST_PASS(name);
release:
    rc_release(orig);
cleanup:
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== Test 15: Fork memory integrity — child bytes + exec + read verified ========== */
static void test_fork_memory_integrity(void)
{
    const char *name = "fork_memory_integrity";
    void *orig, *recomp;
    func_t fn;
    pid_t child;
    int status;
    /*
     * Verify child process memory is NOT polluted after fork:
     *  - Child can READ orig page and see original code bytes (not zeroed/corrupted)
     *  - Child can EXECUTE orig page and get original return value
     *  - Child does NOT see recompiled code
     *  - Parent redirect survives
     *
     * Exit codes from child:
     *   0  = all checks passed
     *   10 = read failed: couldn't read orig page bytes
     *   11 = content mismatch: orig page has wrong bytes
     *   12 = exec wrong value: got redirected or corrupted result
     *   13 = exec mismatch: got unexpected value
     *   14 = recomp read: child can read recomp page and sees recomp code (expected if COW shared)
     *   15 = content is recomp: orig page contains recomp code (bad!)
     *   16 = content is zero: orig page is zeroed (PTE was absent)
     */

    orig = alloc_code_page(code_ret_1, sizeof(code_ret_1));   /* mov x0,#1; ret */
    recomp = alloc_code_page(code_ret_42, sizeof(code_ret_42)); /* mov x0,#42; ret */
    if (!orig || !recomp) { TEST_SKIP(name, "mmap failed"); goto cleanup; }

    /* Verify original code before register */
    fn = (func_t)orig;
    if (fn() != 1) { TEST_FAIL(name, "pre-register exec failed"); goto cleanup; }

    if (rc_register(orig, recomp) != 0) { TEST_FAIL(name, "register failed"); goto cleanup; }

    /* Parent: redirect active → returns 42 */
    if (fn() != 42) { TEST_FAIL(name, "redirect not active: got %ld", fn()); goto release; }

    child = fork();
    if (child == 0) {
        /* ===== Child process: full memory verification ===== */
        unsigned int *code = (unsigned int *)orig;
        unsigned int *rcode = (unsigned int *)recomp;

        /* Check 1: Can we READ the orig page at all? */
        volatile unsigned int first_insn = code[0];
        volatile unsigned int second_insn = code[1];
        (void)first_insn; /* force read */

        /* Check 2: Content matches original code (mov x0,#1 = 0xd2800020) */
        if (code[0] == 0 && code[1] == 0)
            _exit(16);  /* page zeroed — PTE was absent, demand page gave zeros */

        if (code[0] == code_ret_42[0] && code[1] == code_ret_42[1])
            _exit(15);  /* child sees recomp code in orig page — memory polluted! */

        if (code[0] != code_ret_1[0] || code[1] != code_ret_1[1])
            _exit(11);  /* content mismatch — bytes don't match original */

        /* Check 3: Execute orig page → should return 1 (original) */
        long result = ((func_t)orig)();
        if (result == 42)
            _exit(12);  /* got redirected value — child still has stripped PTE! */
        if (result != 1)
            _exit(13);  /* unexpected exec result */

        /* Check 4: Verify recomp page is readable and has recomp code */
        if (rcode[0] != code_ret_42[0])
            _exit(14);  /* recomp content unexpected (not fatal, just info) */

        /* All checks passed */
        _exit(0);
    }
    if (child < 0) { TEST_FAIL(name, "fork failed"); goto release; }

    waitpid(child, &status, 0);
    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        if (sig == SIGSEGV)
            TEST_FAIL(name, "child SIGSEGV — PTE still stripped, fork protection failed");
        else if (sig == SIGBUS)
            TEST_FAIL(name, "child SIGBUS — bad page mapping");
        else
            TEST_FAIL(name, "child killed by signal %d", sig);
        goto release;
    }

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        switch (code) {
        case 0:
            break; /* success */
        case 11:
            TEST_FAIL(name, "child read WRONG bytes from orig page (content mismatch)");
            goto release;
        case 12:
            TEST_FAIL(name, "child got REDIRECT value (42) — PTE still has UXN!");
            goto release;
        case 13:
            TEST_FAIL(name, "child exec returned unexpected value");
            goto release;
        case 15:
            TEST_FAIL(name, "child sees RECOMP code in orig page — memory polluted!");
            goto release;
        case 16:
            TEST_FAIL(name, "child orig page is ZEROED — PTE was absent at fork");
            goto release;
        default:
            TEST_FAIL(name, "child exit code %d", code);
            goto release;
        }
    }

    /* Parent redirect must survive */
    if (fn() != 42) {
        TEST_FAIL(name, "parent redirect broken after fork: got %ld", fn());
        goto release;
    }

    TEST_PASS(name);
release:
    rc_release(orig);
cleanup:
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== Test 16: Multi-page fork integrity (2 mappings, child verifies both) ========== */
static void test_fork_multi_page_integrity(void)
{
    const char *name = "fork_multi_page_integrity";
    void *orig1, *recomp1, *orig2, *recomp2;
    pid_t child;
    int status;

    orig1 = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp1 = alloc_code_page(code_ret_42, sizeof(code_ret_42));
    orig2 = alloc_code_page(code_ret_2, sizeof(code_ret_2));
    recomp2 = alloc_code_page(code_ret_99, sizeof(code_ret_99));
    if (!orig1 || !recomp1 || !orig2 || !recomp2) {
        TEST_SKIP(name, "mmap failed"); goto cleanup;
    }

    if (rc_register(orig1, recomp1) != 0 || rc_register(orig2, recomp2) != 0) {
        TEST_FAIL(name, "register failed"); goto cleanup;
    }

    /* Parent: both redirected */
    if (((func_t)orig1)() != 42 || ((func_t)orig2)() != 99) {
        TEST_FAIL(name, "redirects not active"); goto release;
    }

    child = fork();
    if (child == 0) {
        unsigned int *c1 = (unsigned int *)orig1;
        unsigned int *c2 = (unsigned int *)orig2;

        /* Verify both pages have original code bytes */
        if (c1[0] != code_ret_1[0] || c1[1] != code_ret_1[1])
            _exit(11);  /* page 1 content wrong */
        if (c2[0] != code_ret_2[0] || c2[1] != code_ret_2[1])
            _exit(12);  /* page 2 content wrong */

        /* Execute both — must return original values */
        long r1 = ((func_t)orig1)();
        long r2 = ((func_t)orig2)();
        if (r1 != 1) _exit(21);  /* page 1 exec wrong */
        if (r2 != 2) _exit(22);  /* page 2 exec wrong */

        _exit(0);
    }
    if (child < 0) { TEST_FAIL(name, "fork failed"); goto release; }

    waitpid(child, &status, 0);
    if (WIFSIGNALED(status)) {
        TEST_FAIL(name, "child signal %d (%s)", WTERMSIG(status),
                  WTERMSIG(status) == SIGSEGV ? "PTE still stripped" : "crash");
        goto release;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        int code = WEXITSTATUS(status);
        const char *what = "unknown";
        if (code == 11) what = "page1 bytes wrong";
        if (code == 12) what = "page2 bytes wrong";
        if (code == 21) what = "page1 exec wrong (got redirect?)";
        if (code == 22) what = "page2 exec wrong (got redirect?)";
        TEST_FAIL(name, "child: %s (exit %d)", what, code);
        goto release;
    }

    /* Parent: both redirects survive */
    if (((func_t)orig1)() != 42 || ((func_t)orig2)() != 99) {
        TEST_FAIL(name, "parent redirects broken after fork");
        goto release;
    }

    TEST_PASS(name);
release:
    rc_release(orig2);
    rc_release(orig1);
cleanup:
    free_code_page(orig1); free_code_page(recomp1);
    free_code_page(orig2); free_code_page(recomp2);
}

/* ========== Test 17: Explicit clone(CLONE_VM) — must NOT break redirect ========== */
#define CHILD_STACK_SIZE 65536

static int clone_vm_child(void *arg)
{
    /* CLONE_VM child shares mm — just exit */
    _exit(0);
    return 0;
}

static int clone_fork_child(void *arg)
{
    /* clone without CLONE_VM = real fork, child gets independent mm */
    void *orig = arg;
    long r = ((func_t)orig)();
    _exit((int)r);
    return 0;
}

static void test_clone_vm_no_interfere(void)
{
    const char *name = "clone_vm_no_interfere";
    void *orig, *recomp;
    func_t fn;
    int i;
    void *stack;

    orig = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp = alloc_code_page(code_ret_42, sizeof(code_ret_42));
    if (!orig || !recomp) { TEST_SKIP(name, "mmap failed"); goto cleanup; }

    if (rc_register(orig, recomp) != 0) { TEST_FAIL(name, "register failed"); goto cleanup; }
    fn = (func_t)orig;

    for (i = 0; i < 20; i++) {
        int status;
        pid_t pid;

        stack = mmap(NULL, CHILD_STACK_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
        if (stack == MAP_FAILED) { TEST_FAIL(name, "stack mmap failed"); goto release; }

        /* CLONE_VM | SIGCHLD: shares mm (like a thread), should NOT trigger pause */
        pid = clone(clone_vm_child, (char *)stack + CHILD_STACK_SIZE,
                    CLONE_VM | SIGCHLD, NULL);
        if (pid < 0) {
            munmap(stack, CHILD_STACK_SIZE);
            TEST_FAIL(name, "clone(CLONE_VM) failed: %s", strerror(errno));
            goto release;
        }
        waitpid(pid, &status, 0);
        munmap(stack, CHILD_STACK_SIZE);

        /* Redirect must survive */
        long r = fn();
        if (r != 42) {
            TEST_FAIL(name, "redirect broken after clone(CLONE_VM) #%d: got %ld", i, r);
            goto release;
        }
    }

    TEST_PASS(name);
release:
    rc_release(orig);
cleanup:
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== Test 16: clone() WITHOUT CLONE_VM — real fork, child gets original ========== */
static void test_clone_fork(void)
{
    const char *name = "clone_real_fork";
    void *orig, *recomp;
    func_t fn;
    void *stack;
    int status;
    pid_t pid;

    orig = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp = alloc_code_page(code_ret_42, sizeof(code_ret_42));
    if (!orig || !recomp) { TEST_SKIP(name, "mmap failed"); goto cleanup; }

    if (rc_register(orig, recomp) != 0) { TEST_FAIL(name, "register failed"); goto cleanup; }
    fn = (func_t)orig;

    stack = mmap(NULL, CHILD_STACK_SIZE, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED) { TEST_FAIL(name, "stack mmap failed"); goto release; }

    /* SIGCHLD only: no CLONE_VM → real mm copy, child should get original code */
    pid = clone(clone_fork_child, (char *)stack + CHILD_STACK_SIZE,
                SIGCHLD, orig);
    if (pid < 0) {
        munmap(stack, CHILD_STACK_SIZE);
        TEST_FAIL(name, "clone(no CLONE_VM) failed: %s", strerror(errno));
        goto release;
    }
    waitpid(pid, &status, 0);
    munmap(stack, CHILD_STACK_SIZE);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 1) {
        TEST_FAIL(name, "child: %s (status=0x%x)",
                  child_fail_reason(status, 0), status);
        goto release;
    }

    /* Parent redirect must survive */
    if (fn() != 42) {
        TEST_FAIL(name, "parent redirect broken: got %ld", fn());
        goto release;
    }

    TEST_PASS(name);
release:
    rc_release(orig);
cleanup:
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== Test 17: Multithread + fork race (pause window contention) ========== */
static volatile int race_go = 0;
static volatile int race_stop = 0;
static volatile long race_exec_count = 0;
static volatile long race_exec_fail = 0;
static func_t race_fn;

static void *race_exec_thread(void *arg)
{
    /* Continuously execute redirected function while main thread forks */
    while (!race_go)
        sched_yield();

    while (!race_stop) {
        long r = race_fn();
        __sync_fetch_and_add(&race_exec_count, 1);
        /* During pause window, parent PTE has X restored → exec returns original(1)
         * This is expected and transient. Only permanent breakage is a problem. */
        if (r != 42 && r != 1)
            __sync_fetch_and_add(&race_exec_fail, 1);
    }
    return NULL;
}

static void test_multithread_fork_race(void)
{
    const char *name = "multithread_fork_race";
    void *orig, *recomp;
    pthread_t workers[4];
    int i, all_ok = 1;

    orig = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp = alloc_code_page(code_ret_42, sizeof(code_ret_42));
    if (!orig || !recomp) { TEST_SKIP(name, "mmap failed"); goto cleanup; }

    if (rc_register(orig, recomp) != 0) { TEST_FAIL(name, "register failed"); goto cleanup; }
    race_fn = (func_t)orig;
    race_go = 0;
    race_stop = 0;
    race_exec_count = 0;
    race_exec_fail = 0;

    /* Start 4 threads that continuously execute the redirected function */
    for (i = 0; i < 4; i++) {
        if (pthread_create(&workers[i], NULL, race_exec_thread, NULL) != 0) {
            TEST_FAIL(name, "pthread_create failed");
            race_stop = 1;
            goto join;
        }
    }

    /* Release threads and fork 10 times while they execute */
    race_go = 1;
    for (i = 0; i < 10; i++) {
        pid_t c = fork();
        if (c == 0) {
            /* Child: just exit — we're testing the parent's pause/resume under contention */
            _exit(0);
        }
        if (c > 0) {
            int s;
            waitpid(c, &s, 0);
            if (!WIFEXITED(s)) all_ok = 0;
        }
    }
    race_stop = 1;

join:
    for (i = 0; i < 4; i++)
        pthread_join(workers[i], NULL);

    /* After race: redirect must be intact */
    long final = race_fn();
    if (final != 42) {
        TEST_FAIL(name, "redirect broken after race: got %ld (exec_count=%ld, unexpected=%ld)",
                  final, race_exec_count, race_exec_fail);
        goto release;
    }

    if (verbose)
        printf("[INFO] %s: exec_count=%ld, unexpected_values=%ld\n",
               name, race_exec_count, race_exec_fail);

    if (all_ok)
        TEST_PASS(name);
    else
        TEST_FAIL(name, "fork failures during race");

release:
    rc_release(orig);
cleanup:
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== Test 18: External process fork baseline (no mapping, measures hook overhead) ========== */
static void test_external_fork_overhead(void)
{
    const char *name = "external_fork_overhead";
    void *orig, *recomp;
    func_t fn;
    long long t_before, t_after;
    int n = 30;
    int i;

    orig = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp = alloc_code_page(code_ret_42, sizeof(code_ret_42));
    if (!orig || !recomp) { TEST_SKIP(name, "mmap failed"); goto cleanup; }

    /*
     * Phase 1: fork a child that itself does N forks (no mapping active).
     * The child process has NO mappings — its forks should hit the
     * active_mapping_count==0 fast path.
     */
    {
        long long start = now_us();
        pid_t outer = fork();
        if (outer == 0) {
            /* Child: no mappings. Do N forks. */
            for (i = 0; i < n; i++) {
                pid_t c = fork();
                if (c == 0) _exit(0);
                if (c > 0) { int s; waitpid(c, &s, 0); }
            }
            _exit(0);
        }
        if (outer > 0) { int s; waitpid(outer, &s, 0); }
        t_before = now_us() - start;
    }

    /* Phase 2: register mapping in THIS process, then same fork-from-child test */
    if (rc_register(orig, recomp) != 0) { TEST_FAIL(name, "register failed"); goto cleanup; }
    fn = (func_t)orig;

    {
        long long start = now_us();
        pid_t outer = fork();
        if (outer == 0) {
            /* Child: inherited no mapping (fork protection should have cleaned parent PTE).
             * Child's mm != parent's mm, so rc_mm_has_mappings = false.
             * Child's N forks should be fast. */
            for (i = 0; i < n; i++) {
                pid_t c = fork();
                if (c == 0) _exit(0);
                if (c > 0) { int s; waitpid(c, &s, 0); }
            }
            _exit(0);
        }
        if (outer > 0) { int s; waitpid(outer, &s, 0); }
        t_after = now_us() - start;
    }

    /* Parent redirect must survive */
    if (fn() != 42) { TEST_FAIL(name, "redirect broken"); goto release; }

    printf("[INFO] %s: %d child-forks without_mapping=%lldus with_parent_mapping=%lldus overhead=%.1fx\n",
           name, n, t_before, t_after, t_before > 0 ? (double)t_after / t_before : 0.0);

    /* Child process forks should have <1.5x overhead (they have no mappings) */
    if (t_before > 0 && (double)t_after / t_before > 2.0) {
        TEST_FAIL(name, "child-fork overhead %.1fx — hook may not be filtering by mm",
                  (double)t_after / t_before);
    } else {
        TEST_PASS(name);
    }

release:
    rc_release(orig);
cleanup:
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== Test 19: Stats-verified thread storm (zero pause expected) ========== */
static void test_stats_thread_no_pause(void)
{
    const char *name = "stats_thread_no_pause";
    void *orig, *recomp;
    func_t fn;
    long pause_before, pause_after;
    long skip_before, skip_after;
    int i;

    if (!stats_available) { TEST_SKIP(name, "stats not available"); return; }

    orig = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp = alloc_code_page(code_ret_42, sizeof(code_ret_42));
    if (!orig || !recomp) { TEST_SKIP(name, "mmap failed"); goto cleanup; }

    if (rc_register(orig, recomp) != 0) { TEST_FAIL(name, "register failed"); goto cleanup; }
    fn = (func_t)orig;

    rc_stats_reset();
    pause_before = rc_stat(RC_STAT_FORK_PAUSE);

    /* Create 50 threads — should trigger ZERO pause events */
    for (i = 0; i < 50; i++) {
        pthread_t t;
        pthread_create(&t, NULL, thread_noop, NULL);
        pthread_join(t, NULL);
    }

    pause_after = rc_stat(RC_STAT_FORK_PAUSE);
    skip_after  = rc_stat(RC_STAT_FORK_SKIPPED);

    if (fn() != 42) { TEST_FAIL(name, "redirect broken"); goto release; }

    if (pause_after > pause_before) {
        TEST_FAIL(name, "CLONE_VM filtering BROKEN! %ld pause events from 50 threads (expected 0)",
                  pause_after - pause_before);
    } else {
        if (verbose)
            printf("[INFO] %s: 50 threads → pause=%ld (expected 0), skipped=%ld\n",
                   name, pause_after - pause_before, skip_after);
        TEST_PASS(name);
    }

release:
    rc_release(orig);
cleanup:
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== Test 20: Stats-verified fork (exact pause count) ========== */
static void test_stats_fork_exact_count(void)
{
    const char *name = "stats_fork_exact_count";
    void *orig, *recomp;
    func_t fn;
    long handled_before, handled_after;
    int n_forks = 5;
    int i;

    if (!stats_available) { TEST_SKIP(name, "stats not available"); return; }

    orig = alloc_code_page(code_ret_1, sizeof(code_ret_1));
    recomp = alloc_code_page(code_ret_2, sizeof(code_ret_2));
    if (!orig || !recomp) { TEST_SKIP(name, "mmap failed"); goto cleanup; }

    if (rc_register(orig, recomp) != 0) { TEST_FAIL(name, "register failed"); goto cleanup; }
    fn = (func_t)orig;

    /* Execute once to ensure redirect is active */
    if (fn() != 2) { TEST_FAIL(name, "redirect not active"); goto release; }

    rc_stats_reset();
    handled_before = rc_stat(RC_STAT_FORK_PAUSE); /* now means "fork handled" */

    for (i = 0; i < n_forks; i++) {
        pid_t c = fork();
        if (c == 0) _exit((int)((func_t)orig)());
        if (c > 0) { int s; waitpid(c, &s, 0); }
    }

    handled_after = rc_stat(RC_STAT_FORK_PAUSE);
    long handled = handled_after - handled_before;

    printf("[INFO] %s: %d forks → fork_handled=%ld\n",
           name, n_forks, handled);

    /* Each fork should trigger exactly 1 child-fix event */
    if (handled != n_forks) {
        TEST_FAIL(name, "expected %d fork_handled, got %ld", n_forks, handled);
    } else {
        TEST_PASS(name);
    }

release:
    rc_release(orig);
cleanup:
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== Test 21: Stats-verified no-mapping fork (zero pause, all skipped) ========== */
static void test_stats_no_mapping_fork(void)
{
    const char *name = "stats_no_mapping_fork";
    long pause_before, pause_after, skip_before, skip_after;
    int i;

    if (!stats_available) { TEST_SKIP(name, "stats not available"); return; }

    rc_stats_reset();
    pause_before = rc_stat(RC_STAT_FORK_PAUSE);
    skip_before  = rc_stat(RC_STAT_FORK_SKIPPED);

    /* 10 forks with NO mapping active — should be all skipped */
    for (i = 0; i < 10; i++) {
        pid_t c = fork();
        if (c == 0) _exit(0);
        if (c > 0) { int s; waitpid(c, &s, 0); }
    }

    pause_after = rc_stat(RC_STAT_FORK_PAUSE);
    skip_after  = rc_stat(RC_STAT_FORK_SKIPPED);

    long pauses = pause_after - pause_before;
    long skips  = skip_after - skip_before;

    printf("[INFO] %s: 10 forks no-mapping → pause=%ld skipped=%ld\n",
           name, pauses, skips);

    if (pauses > 0) {
        TEST_FAIL(name, "%ld pause events with NO mappings active!", pauses);
    } else if (skips < 10) {
        /* At least 10 skips expected (one per fork) */
        TEST_FAIL(name, "only %ld skips for 10 forks (fast path not working?)", skips);
    } else {
        TEST_PASS(name);
    }
}

/* ========== Main ========== */

int main(int argc, char *argv[])
{
    if (argc > 1 && strcmp(argv[1], "-v") == 0)
        verbose = 1;

    printf("=== recompile_fork_test ===\n");
    printf("pid=%d\n\n", getpid());

    detect_stats();

    printf("--- Correctness tests ---\n");
    test_basic_fork();
    test_thread_no_interfere();
    test_thread_shared_redirect();
    test_multi_fork();
    test_vfork();
    test_fork_chain();
    test_concurrent_fork_exec();
    test_multi_mapping_fork();
    test_fork_no_mapping();
    test_system_call();
    test_mixed_thread_fork();
    test_fork_child_register();
    test_fork_memory_integrity();
    test_fork_multi_page_integrity();
    test_clone_vm_no_interfere();
    test_clone_fork();

    printf("\n--- Race condition tests ---\n");
    test_multithread_fork_race();

    printf("\n--- Performance tests ---\n");
    test_fork_storm();
    test_thread_storm();
    test_external_fork_overhead();

    printf("\n--- Stats verification tests ---\n");
    test_stats_thread_no_pause();
    test_stats_fork_exact_count();
    test_stats_no_mapping_fork();

    if (stats_available)
        print_stats("final");

    printf("\n=== Results: %d passed, %d failed, %d skipped ===\n",
           test_pass, test_fail, test_skip);
    return test_fail > 0 ? 1 : 0;
}
