/*
 * recompile_test - Test program for recompile redirect module
 *
 * Test 1-5: Basic tests (page already faulted in)
 * Test 6-7: Demand paging tests (PTE absent at register time)
 * Test 8:   Cross-process rejection
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

#define PR_RECOMPILE_REGISTER   0x52430001
#define PR_RECOMPILE_RELEASE    0x52430002

typedef long (*func_t)(void);

/* ARM64 machine code */
static const unsigned int code_ret1[] = {
    0xd2800020,  /* mov x0, #1 */
    0xd65f03c0,  /* ret */
};
static const unsigned int code_ret2[] = {
    0xd2800040,  /* mov x0, #2 */
    0xd65f03c0,  /* ret */
};
static const unsigned int code_ret3[] = {
    0xd2800060,  /* mov x0, #3 */
    0xd65f03c0,  /* ret */
};

static int test_pass = 0, test_fail = 0;

static void check(const char *name, long got, long expect)
{
    int ok = (got == expect);
    printf("[%s] got=%ld expect=%ld ... %s\n", name, got, expect, ok ? "PASS" : "FAIL");
    if (ok) test_pass++; else test_fail++;
}

static void check_ret(const char *name, int ret, int expect_ok)
{
    int ok = expect_ok ? (ret == 0) : (ret != 0);
    printf("[%s] ret=%d errno=%d ... %s\n", name, ret, errno, ok ? "PASS" : "FAIL");
    if (ok) test_pass++; else test_fail++;
}

int main(void)
{
    void *orig_page, *recomp_page;
    func_t fn;
    long result;
    int ret;

    printf("=== recompile_test ===\n");
    printf("pid = %d\n\n", getpid());

    /* ============ Test 1-5: Basic (page already faulted in) ============ */
    printf("--- Basic tests (page pre-faulted) ---\n");

    orig_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    recomp_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (orig_page == MAP_FAILED || recomp_page == MAP_FAILED) {
        perror("mmap"); return 1;
    }

    memcpy(orig_page, code_ret1, sizeof(code_ret1));
    memcpy(recomp_page, code_ret2, sizeof(code_ret2));
    __builtin___clear_cache(orig_page, (char *)orig_page + sizeof(code_ret1));
    __builtin___clear_cache(recomp_page, (char *)recomp_page + sizeof(code_ret2));

    printf("orig=%p  recomp=%p\n", orig_page, recomp_page);

    fn = (func_t)orig_page;
    check("Test 1 before register", fn(), 1);

    ret = prctl(PR_RECOMPILE_REGISTER, 0,
                (unsigned long)orig_page, (unsigned long)recomp_page, 0);
    check_ret("Test 2 register", ret, 1);
    if (ret == 0) {
        check("Test 2 after register", fn(), 2);
        check("Test 3 stable redirect", fn(), 2);

        ret = prctl(PR_RECOMPILE_RELEASE, 0, (unsigned long)orig_page, 0, 0);
        check_ret("Test 4 release", ret, 1);
        check("Test 4 after release", fn(), 1);

        ret = prctl(PR_RECOMPILE_REGISTER, 0,
                    (unsigned long)orig_page, (unsigned long)recomp_page, 0);
        check_ret("Test 5 re-register", ret, 1);
        if (ret == 0) {
            check("Test 5 redirect", fn(), 2);
            prctl(PR_RECOMPILE_RELEASE, 0, (unsigned long)orig_page, 0, 0);
            check("Test 5 after release", fn(), 1);
        }
    }

    munmap(orig_page, 4096);
    munmap(recomp_page, 4096);

    /* ============ Test 6: Demand paging via file-backed mmap ============ */
    printf("\n--- Demand paging test (file-backed, PTE absent) ---\n");
    {
        int fd;
        void *file_page, *recomp2;
        char tmpfile[] = "/tmp/rc_test_XXXXXX";

        fd = mkstemp(tmpfile);
        if (fd < 0) {
            /* /tmp might not exist in minimal initramfs, try current dir */
            strcpy(tmpfile, "./rc_test_XXXXXX");
            fd = mkstemp(tmpfile);
        }
        if (fd < 0) {
            printf("[Test 6] SKIP - mkstemp failed: %s\n", strerror(errno));
            goto test7;
        }

        /* Write code to file (pad to page size) */
        {
            char buf[4096];
            memset(buf, 0, sizeof(buf));
            memcpy(buf, code_ret1, sizeof(code_ret1));
            write(fd, buf, sizeof(buf));
        }

        /* mmap the file as read+exec, do NOT access it */
        file_page = mmap(NULL, 4096, PROT_READ | PROT_EXEC,
                         MAP_PRIVATE, fd, 0);
        close(fd);
        unlink(tmpfile);

        if (file_page == MAP_FAILED) {
            printf("[Test 6] SKIP - mmap failed: %s\n", strerror(errno));
            goto test7;
        }

        /* Allocate recomp page */
        recomp2 = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (recomp2 == MAP_FAILED) {
            munmap(file_page, 4096);
            printf("[Test 6] SKIP - mmap recomp failed\n");
            goto test7;
        }
        memcpy(recomp2, code_ret3, sizeof(code_ret3));
        __builtin___clear_cache(recomp2, (char *)recomp2 + sizeof(code_ret3));

        printf("file_page=%p (NOT accessed, PTE should be absent)\n", file_page);
        printf("recomp2=%p   (code: mov x0,#3; ret)\n", recomp2);

        /* Register with PTE absent — should trigger demand fault-in */
        ret = prctl(PR_RECOMPILE_REGISTER, 0,
                    (unsigned long)file_page, (unsigned long)recomp2, 0);
        check_ret("Test 6 register (demand page)", ret, 1);

        if (ret == 0) {
            /* Execute — should be redirected to recomp2 */
            fn = (func_t)file_page;
            check("Test 6 redirect", fn(), 3);

            prctl(PR_RECOMPILE_RELEASE, 0, (unsigned long)file_page, 0, 0);

            /* After release, should execute original file code (ret 1) */
            check("Test 6 after release", fn(), 1);
        }

        munmap(file_page, 4096);
        munmap(recomp2, 4096);
    }

test7:
    /* ============ Test 7: Demand paging via madvise(MADV_DONTNEED) ============ */
    printf("\n--- Demand paging test (madvise drop, PTE cleared) ---\n");
    {
        void *page_a, *page_b;

        page_a = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        page_b = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page_a == MAP_FAILED || page_b == MAP_FAILED) {
            printf("[Test 7] SKIP - mmap failed\n");
            goto test8;
        }

        /* Write code and execute to populate PTE */
        memcpy(page_a, code_ret1, sizeof(code_ret1));
        memcpy(page_b, code_ret2, sizeof(code_ret2));
        __builtin___clear_cache(page_a, (char *)page_a + sizeof(code_ret1));
        __builtin___clear_cache(page_b, (char *)page_b + sizeof(code_ret2));

        fn = (func_t)page_a;
        result = fn();  /* populate PTE */
        printf("page_a=%p fn()=%ld (pre-madvise)\n", page_a, result);

        /* Drop the PTE via madvise — simulates demand paging state */
        ret = madvise(page_a, 4096, MADV_DONTNEED);
        printf("madvise(MADV_DONTNEED) = %d\n", ret);

        /* Now page_a PTE is absent (anonymous → zeroed on re-fault).
         * Register should fault it in via copy_from_user.
         * After fault-in, the page content is zeroed (anonymous),
         * but redirect to page_b still works. */
        ret = prctl(PR_RECOMPILE_REGISTER, 0,
                    (unsigned long)page_a, (unsigned long)page_b, 0);
        check_ret("Test 7 register (after madvise)", ret, 1);

        if (ret == 0) {
            fn = (func_t)page_a;
            check("Test 7 redirect", fn(), 2);

            prctl(PR_RECOMPILE_RELEASE, 0, (unsigned long)page_a, 0, 0);
        }

        munmap(page_a, 4096);
        munmap(page_b, 4096);
    }

test8:
    /* ============ Test 8: Cross-process rejected ============ */
    printf("\n--- Cross-process rejection test ---\n");
    {
        ret = prctl(PR_RECOMPILE_REGISTER, 1 /* pid=1 */, 0x1000, 0x2000, 0);
        check_ret("Test 8 cross-process rejected", ret, 0 /* expect failure */);
    }

    /* ============ Test 9: Fork safety ============ */
    printf("\n--- Fork safety test ---\n");
    {
        void *fp, *rp;
        pid_t child;
        int status;

        fp = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        rp = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (fp == MAP_FAILED || rp == MAP_FAILED) {
            printf("[Test 9] SKIP - mmap failed\n");
            goto done;
        }

        memcpy(fp, code_ret1, sizeof(code_ret1));   /* returns 1 */
        memcpy(rp, code_ret2, sizeof(code_ret2));   /* returns 2 */
        __builtin___clear_cache(fp, (char *)fp + sizeof(code_ret1));
        __builtin___clear_cache(rp, (char *)rp + sizeof(code_ret2));

        /* Register redirect: fp → rp */
        ret = prctl(PR_RECOMPILE_REGISTER, 0,
                    (unsigned long)fp, (unsigned long)rp, 0);
        check_ret("Test 9 register", ret, 1);
        if (ret != 0) goto fork_cleanup;

        /* Verify parent redirect works */
        fn = (func_t)fp;
        check("Test 9 parent redirect", fn(), 2);

        /* Fork child — child should NOT crash, should run original code */
        printf("[Test 9] forking...\n");
        child = fork();
        if (child == 0) {
            /* Child process — first test: just exit to verify fork works */
            fn = (func_t)fp;
            result = fn();
            _exit(result == 1 ? 0 : 99);
        }
        printf("[Test 9] fork returned child=%d\n", child);

        if (child > 0) {
            waitpid(child, &status, 0);
            if (WIFEXITED(status)) {
                int code = WEXITSTATUS(status);
                printf("[Test 9 child exit] code=%d ... %s\n",
                       code, code == 0 ? "PASS" : "FAIL");
                if (code == 0) test_pass++; else test_fail++;
            } else {
                printf("[Test 9 child exit] signal=%d ... FAIL (crashed!)\n",
                       WTERMSIG(status));
                test_fail++;
            }

            /* Verify parent redirect still works after fork */
            check("Test 9 parent after fork", fn(), 2);
        } else {
            printf("[Test 9] fork failed: %s\n", strerror(errno));
            test_fail++;
        }

        prctl(PR_RECOMPILE_RELEASE, 0, (unsigned long)fp, 0, 0);
fork_cleanup:
        munmap(fp, 4096);
        munmap(rp, 4096);
    }

done:
    /* ============ Summary ============ */
    printf("\n=== Results: %d passed, %d failed ===\n", test_pass, test_fail);
    return test_fail > 0 ? 1 : 0;
}
