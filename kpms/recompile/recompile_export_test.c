/*
 * recompile_export_test - Verify PC export sanitization surfaces
 *
 * Covers:
 *   1. Signal-frame export via ucontext_t (setup_sigframe / do_signal hook)
 *   2. ptrace GETREGSET NT_PRSTATUS export (regset hooks)
 *   3. ptrace single-step PC export (single_step_handler hook)
 *   4. perf IP sampling export (perf_instruction_pointer hook)
 *   5. perf register sampling export (perf_reg_value hook)
 */

#define _GNU_SOURCE
#include <asm/ptrace.h>
#include <elf.h>
#include <errno.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#define PR_RECOMPILE_REGISTER   0x52430001
#define PR_RECOMPILE_RELEASE    0x52430002

#define PAGE_SIZE 4096UL
#define PAGE_MASK (~(PAGE_SIZE - 1))

typedef void (*spin_t)(void);

static const unsigned int code_spin[] = {
    0x14000000,  /* b . */
};

static int test_pass = 0;
static int test_fail = 0;
static int test_skip = 0;

#define TEST_PASS(name) do { printf("[PASS] %s\n", name); test_pass++; } while (0)
#define TEST_FAIL(name, fmt, ...) do { printf("[FAIL] %s: " fmt "\n", name, ##__VA_ARGS__); test_fail++; } while (0)
#define TEST_SKIP(name, reason) do { printf("[SKIP] %s: %s\n", name, reason); test_skip++; } while (0)

struct sig_report {
    unsigned long pc;
    int page_matches_orig;
    int page_matches_recomp;
};

static int sig_pipe_fd = -1;
static unsigned long sig_orig_page;
static unsigned long sig_recomp_page;

static void *alloc_spin_page(void)
{
    void *p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return NULL;
    memcpy(p, code_spin, sizeof(code_spin));
    __builtin___clear_cache(p, (char *)p + sizeof(code_spin));
    return p;
}

static void free_code_page(void *p)
{
    if (p && p != MAP_FAILED)
        munmap(p, PAGE_SIZE);
}

static int rc_register(void *orig, void *recomp)
{
    return prctl(PR_RECOMPILE_REGISTER, 0, (unsigned long)orig, (unsigned long)recomp, 0);
}

static int rc_release(void *orig)
{
    return prctl(PR_RECOMPILE_RELEASE, 0, (unsigned long)orig, 0, 0);
}

static ssize_t full_read(int fd, void *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t rc = read(fd, (char *)buf + done, len - done);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (rc == 0)
            break;
        done += (size_t)rc;
    }
    return (ssize_t)done;
}

static ssize_t full_write(int fd, const void *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t rc = write(fd, (const char *)buf + done, len - done);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        done += (size_t)rc;
    }
    return (ssize_t)done;
}

static void signal_pc_handler(int signo, siginfo_t *info, void *uctx)
{
    ucontext_t *uc = (ucontext_t *)uctx;
    struct sig_report report;

    (void)signo;
    (void)info;

    memset(&report, 0, sizeof(report));
    report.pc = (unsigned long)uc->uc_mcontext.pc;
    report.page_matches_orig = ((report.pc & PAGE_MASK) == sig_orig_page);
    report.page_matches_recomp = ((report.pc & PAGE_MASK) == sig_recomp_page);

    if (sig_pipe_fd >= 0)
        full_write(sig_pipe_fd, &report, sizeof(report));
    _exit(report.page_matches_orig && !report.page_matches_recomp ? 0 : 1);
}

static void test_signal_frame_pc_export(void)
{
    const char *name = "signal_frame_pc_export";
    void *orig = NULL, *recomp = NULL;
    int pipefd[2] = { -1, -1 };
    pid_t child;
    int status;
    struct sig_report report;
    char ready = 0;

    orig = alloc_spin_page();
    recomp = alloc_spin_page();
    if (!orig || !recomp) {
        TEST_SKIP(name, "mmap failed");
        goto cleanup;
    }

    if (pipe(pipefd) != 0) {
        TEST_SKIP(name, "pipe failed");
        goto cleanup;
    }

    child = fork();
    if (child < 0) {
        TEST_FAIL(name, "fork failed: %s", strerror(errno));
        goto cleanup;
    }

    if (child == 0) {
        struct sigaction sa;

        close(pipefd[0]);
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = signal_pc_handler;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sig_pipe_fd = pipefd[1];
        sig_orig_page = (unsigned long)orig & PAGE_MASK;
        sig_recomp_page = (unsigned long)recomp & PAGE_MASK;

        if (sigaction(SIGALRM, &sa, NULL) != 0)
            _exit(2);
        if (rc_register(orig, recomp) != 0)
            _exit(3);

        ready = 'R';
        if (full_write(pipefd[1], &ready, 1) != 1)
            _exit(4);

        ualarm(100000, 0);
        ((spin_t)orig)();
        _exit(5);
    }

    close(pipefd[1]);
    if (full_read(pipefd[0], &ready, 1) != 1 || ready != 'R') {
        TEST_FAIL(name, "child did not report ready");
        goto wait_child;
    }

    if (full_read(pipefd[0], &report, sizeof(report)) != sizeof(report)) {
        TEST_FAIL(name, "failed to read signal report");
        goto wait_child;
    }

wait_child:
    waitpid(child, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        TEST_FAIL(name, "child exit status=0x%x pc=%#lx orig_page=%#lx recomp_page=%#lx",
                  status, report.pc, (unsigned long)orig & PAGE_MASK,
                  (unsigned long)recomp & PAGE_MASK);
        goto cleanup;
    }

    if (!report.page_matches_orig || report.page_matches_recomp) {
        TEST_FAIL(name, "handler pc=%#lx orig_match=%d recomp_match=%d",
                  report.pc, report.page_matches_orig, report.page_matches_recomp);
        goto cleanup;
    }

    TEST_PASS(name);

cleanup:
    if (pipefd[0] >= 0)
        close(pipefd[0]);
    if (pipefd[1] >= 0)
        close(pipefd[1]);
    free_code_page(orig);
    free_code_page(recomp);
}

static void test_ptrace_getregset_pc_export(void)
{
    const char *name = "ptrace_getregset_pc_export";
    void *orig = NULL, *recomp = NULL;
    int pipefd[2] = { -1, -1 };
    pid_t child;
    int status;
    char ready = 0;
    struct user_pt_regs regs;
    struct iovec iov;

    orig = alloc_spin_page();
    recomp = alloc_spin_page();
    if (!orig || !recomp) {
        TEST_SKIP(name, "mmap failed");
        goto cleanup;
    }

    if (pipe(pipefd) != 0) {
        TEST_SKIP(name, "pipe failed");
        goto cleanup;
    }

    child = fork();
    if (child < 0) {
        TEST_FAIL(name, "fork failed: %s", strerror(errno));
        goto cleanup;
    }

    if (child == 0) {
        close(pipefd[0]);
        if (rc_register(orig, recomp) != 0)
            _exit(2);
        ready = 'R';
        if (full_write(pipefd[1], &ready, 1) != 1)
            _exit(3);
        ((spin_t)orig)();
        _exit(4);
    }

    close(pipefd[1]);
    if (full_read(pipefd[0], &ready, 1) != 1 || ready != 'R') {
        TEST_FAIL(name, "child did not report ready");
        goto kill_child;
    }

    usleep(100000);
    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) != 0) {
        TEST_FAIL(name, "PTRACE_ATTACH failed: %s", strerror(errno));
        goto kill_child;
    }
    if (waitpid(child, &status, 0) < 0) {
        TEST_FAIL(name, "waitpid after attach failed: %s", strerror(errno));
        goto kill_child;
    }
    if (!WIFSTOPPED(status)) {
        TEST_FAIL(name, "child not stopped after attach: status=0x%x", status);
        goto detach_child;
    }

    memset(&regs, 0, sizeof(regs));
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_GETREGSET, child, (void *)NT_PRSTATUS, &iov) != 0) {
        TEST_FAIL(name, "PTRACE_GETREGSET failed: %s", strerror(errno));
        goto detach_child;
    }

    if ((regs.pc & PAGE_MASK) != ((unsigned long)orig & PAGE_MASK) ||
        (regs.pc & PAGE_MASK) == ((unsigned long)recomp & PAGE_MASK)) {
        TEST_FAIL(name, "exported pc=%#llx orig_page=%#lx recomp_page=%#lx",
                  (unsigned long long)regs.pc,
                  (unsigned long)orig & PAGE_MASK,
                  (unsigned long)recomp & PAGE_MASK);
        goto detach_child;
    }

    TEST_PASS(name);

detach_child:
    ptrace(PTRACE_KILL, child, NULL, NULL);
    waitpid(child, &status, 0);
    goto cleanup;

kill_child:
    kill(child, SIGKILL);
    waitpid(child, &status, 0);

cleanup:
    if (pipefd[0] >= 0)
        close(pipefd[0]);
    if (pipefd[1] >= 0)
        close(pipefd[1]);
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== ptrace single-step test ========== */

static void test_ptrace_singlestep_pc(void)
{
    const char *name = "ptrace_singlestep_pc_export";
    void *orig = NULL, *recomp = NULL;
    int pipefd[2] = { -1, -1 };
    pid_t child;
    int status;
    char ready = 0;
    struct user_pt_regs regs;
    struct iovec iov;
    unsigned long orig_page, recomp_page;
    int i, leaked = 0;

    orig = alloc_spin_page();
    recomp = alloc_spin_page();
    if (!orig || !recomp) {
        TEST_SKIP(name, "mmap failed");
        goto cleanup;
    }
    orig_page = (unsigned long)orig & PAGE_MASK;
    recomp_page = (unsigned long)recomp & PAGE_MASK;

    if (pipe(pipefd) != 0) {
        TEST_SKIP(name, "pipe failed");
        goto cleanup;
    }

    child = fork();
    if (child < 0) {
        TEST_FAIL(name, "fork failed");
        goto cleanup;
    }

    if (child == 0) {
        close(pipefd[0]);
        if (rc_register(orig, recomp) != 0)
            _exit(2);
        ready = 'R';
        full_write(pipefd[1], &ready, 1);
        ((spin_t)orig)();
        _exit(0);
    }

    close(pipefd[1]);
    pipefd[1] = -1;
    if (full_read(pipefd[0], &ready, 1) != 1 || ready != 'R') {
        TEST_FAIL(name, "child not ready");
        goto kill_child;
    }
    usleep(50000);

    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) != 0) {
        TEST_FAIL(name, "PTRACE_ATTACH failed: %s", strerror(errno));
        goto kill_child;
    }
    if (waitpid(child, &status, 0) < 0 || !WIFSTOPPED(status)) {
        TEST_FAIL(name, "child not stopped after attach");
        goto kill_child;
    }

    /* Single-step 10 times and check PC each time */
    for (i = 0; i < 10; i++) {
        if (ptrace(PTRACE_SINGLESTEP, child, NULL, NULL) != 0) {
            TEST_FAIL(name, "PTRACE_SINGLESTEP failed: %s", strerror(errno));
            goto detach;
        }
        if (waitpid(child, &status, 0) < 0 || !WIFSTOPPED(status))
            break;

        memset(&regs, 0, sizeof(regs));
        iov.iov_base = &regs;
        iov.iov_len = sizeof(regs);
        if (ptrace(PTRACE_GETREGSET, child, (void *)NT_PRSTATUS, &iov) != 0)
            continue;

        if ((regs.pc & PAGE_MASK) == recomp_page)
            leaked++;
    }

    if (leaked > 0) {
        TEST_FAIL(name, "%d/%d steps leaked recomp_page", leaked, i);
    } else {
        TEST_PASS(name);
    }

detach:
    ptrace(PTRACE_KILL, child, NULL, NULL);
    waitpid(child, &status, 0);
    goto cleanup;

kill_child:
    kill(child, SIGKILL);
    waitpid(child, &status, 0);

cleanup:
    if (pipefd[0] >= 0) close(pipefd[0]);
    if (pipefd[1] >= 0) close(pipefd[1]);
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== perf IP sampling test ========== */

#define PERF_MMAP_PAGES 4
#define PERF_MMAP_SIZE ((1 + PERF_MMAP_PAGES) * PAGE_SIZE)

static long sys_perf_event_open(struct perf_event_attr *attr, pid_t pid,
                                int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void test_perf_ip_export(void)
{
    const char *name = "perf_ip_sampling_export";
    void *orig = NULL, *recomp = NULL;
    int pipefd[2] = { -1, -1 };
    pid_t child;
    int status, perf_fd = -1;
    char ready = 0;
    void *mmap_buf = MAP_FAILED;
    unsigned long orig_page, recomp_page;
    struct perf_event_attr attr;

    orig = alloc_spin_page();
    recomp = alloc_spin_page();
    if (!orig || !recomp) {
        TEST_SKIP(name, "mmap failed");
        goto cleanup;
    }
    orig_page = (unsigned long)orig & PAGE_MASK;
    recomp_page = (unsigned long)recomp & PAGE_MASK;

    if (pipe(pipefd) != 0) {
        TEST_SKIP(name, "pipe failed");
        goto cleanup;
    }

    child = fork();
    if (child < 0) {
        TEST_FAIL(name, "fork failed");
        goto cleanup;
    }

    if (child == 0) {
        close(pipefd[0]);
        if (rc_register(orig, recomp) != 0)
            _exit(2);
        ready = 'R';
        full_write(pipefd[1], &ready, 1);
        ((spin_t)orig)();
        _exit(0);
    }

    close(pipefd[1]);
    pipefd[1] = -1;
    if (full_read(pipefd[0], &ready, 1) != 1 || ready != 'R') {
        TEST_FAIL(name, "child not ready");
        goto kill_child;
    }
    usleep(50000);

    /* Open perf event targeting child */
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_TASK_CLOCK;
    attr.sample_type = PERF_SAMPLE_IP;
    attr.sample_period = 100000; /* ~100us */
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;

    perf_fd = (int)sys_perf_event_open(&attr, child, -1, -1, 0);
    if (perf_fd < 0) {
        TEST_SKIP(name, "perf_event_open failed (no perf support?)");
        goto kill_child;
    }

    mmap_buf = mmap(NULL, PERF_MMAP_SIZE, PROT_READ | PROT_WRITE,
                    MAP_SHARED, perf_fd, 0);
    if (mmap_buf == MAP_FAILED) {
        TEST_SKIP(name, "perf mmap failed");
        goto kill_child;
    }

    ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    usleep(300000); /* collect samples */
    ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);

    /* Parse ring buffer */
    {
        struct perf_event_mmap_page *mp = (struct perf_event_mmap_page *)mmap_buf;
        char *data = (char *)mmap_buf + PAGE_SIZE;
        uint64_t data_size = PERF_MMAP_PAGES * PAGE_SIZE;
        uint64_t head = mp->data_head;
        uint64_t tail = mp->data_tail;
        int total = 0, leaked = 0, on_orig = 0;

        __sync_synchronize(); /* rmb */

        while (tail < head) {
            struct perf_event_header *ev =
                (struct perf_event_header *)(data + (tail % data_size));
            if (ev->type == PERF_RECORD_SAMPLE && ev->size >= sizeof(*ev) + sizeof(uint64_t)) {
                uint64_t ip = *(uint64_t *)((char *)ev + sizeof(*ev));
                total++;
                if ((ip & PAGE_MASK) == recomp_page)
                    leaked++;
                if ((ip & PAGE_MASK) == orig_page)
                    on_orig++;
            }
            tail += ev->size;
        }

        if (total == 0) {
            TEST_SKIP(name, "no perf samples collected");
        } else if (leaked > 0) {
            TEST_FAIL(name, "%d/%d samples leaked recomp_page (orig=%d)", leaked, total, on_orig);
        } else {
            printf("[INFO] %s: %d samples, %d on orig_page\n", name, total, on_orig);
            TEST_PASS(name);
        }
    }

    goto kill_child;

kill_child:
    kill(child, SIGKILL);
    waitpid(child, &status, 0);

cleanup:
    if (mmap_buf != MAP_FAILED)
        munmap(mmap_buf, PERF_MMAP_SIZE);
    if (perf_fd >= 0)
        close(perf_fd);
    if (pipefd[0] >= 0) close(pipefd[0]);
    if (pipefd[1] >= 0) close(pipefd[1]);
    free_code_page(orig);
    free_code_page(recomp);
}

/* ========== perf register sampling (PC) test ========== */

#define PERF_REG_ARM64_PC 32

static void test_perf_regs_pc_export(void)
{
    const char *name = "perf_regs_pc_sampling_export";
    void *orig = NULL, *recomp = NULL;
    int pipefd[2] = { -1, -1 };
    pid_t child;
    int status, perf_fd = -1;
    char ready = 0;
    void *mmap_buf = MAP_FAILED;
    unsigned long orig_page, recomp_page;
    struct perf_event_attr attr;

    orig = alloc_spin_page();
    recomp = alloc_spin_page();
    if (!orig || !recomp) {
        TEST_SKIP(name, "mmap failed");
        goto cleanup;
    }
    orig_page = (unsigned long)orig & PAGE_MASK;
    recomp_page = (unsigned long)recomp & PAGE_MASK;

    if (pipe(pipefd) != 0) {
        TEST_SKIP(name, "pipe failed");
        goto cleanup;
    }

    child = fork();
    if (child < 0) {
        TEST_FAIL(name, "fork failed");
        goto cleanup;
    }

    if (child == 0) {
        close(pipefd[0]);
        if (rc_register(orig, recomp) != 0)
            _exit(2);
        ready = 'R';
        full_write(pipefd[1], &ready, 1);
        ((spin_t)orig)();
        _exit(0);
    }

    close(pipefd[1]);
    pipefd[1] = -1;
    if (full_read(pipefd[0], &ready, 1) != 1 || ready != 'R') {
        TEST_FAIL(name, "child not ready");
        goto kill_child;
    }
    usleep(50000);

    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_TASK_CLOCK;
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_USER;
    attr.sample_regs_user = (1ULL << PERF_REG_ARM64_PC);
    attr.sample_period = 100000;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;

    perf_fd = (int)sys_perf_event_open(&attr, child, -1, -1, 0);
    if (perf_fd < 0) {
        TEST_SKIP(name, "perf_event_open failed");
        goto kill_child;
    }

    mmap_buf = mmap(NULL, PERF_MMAP_SIZE, PROT_READ | PROT_WRITE,
                    MAP_SHARED, perf_fd, 0);
    if (mmap_buf == MAP_FAILED) {
        TEST_SKIP(name, "perf mmap failed");
        goto kill_child;
    }

    ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    usleep(300000);
    ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);

    {
        struct perf_event_mmap_page *mp = (struct perf_event_mmap_page *)mmap_buf;
        char *data = (char *)mmap_buf + PAGE_SIZE;
        uint64_t data_size = PERF_MMAP_PAGES * PAGE_SIZE;
        uint64_t head = mp->data_head;
        uint64_t tail = mp->data_tail;
        int total = 0, leaked_ip = 0, leaked_reg = 0;

        __sync_synchronize();

        while (tail < head) {
            struct perf_event_header *ev =
                (struct perf_event_header *)(data + (tail % data_size));
            if (ev->type == PERF_RECORD_SAMPLE) {
                char *p = (char *)ev + sizeof(*ev);
                /* PERF_SAMPLE_IP */
                uint64_t ip = *(uint64_t *)p;
                p += sizeof(uint64_t);
                /* PERF_SAMPLE_REGS_USER: u64 abi, then u64 regs[] */
                uint64_t abi = *(uint64_t *)p;
                p += sizeof(uint64_t);
                if (abi != 0) {
                    uint64_t reg_pc = *(uint64_t *)p;
                    total++;
                    if ((ip & PAGE_MASK) == recomp_page)
                        leaked_ip++;
                    if ((reg_pc & PAGE_MASK) == recomp_page)
                        leaked_reg++;
                }
            }
            tail += ev->size;
        }

        if (total == 0) {
            TEST_SKIP(name, "no perf samples with regs collected");
        } else if (leaked_ip > 0 || leaked_reg > 0) {
            TEST_FAIL(name, "%d samples: ip_leaked=%d reg_pc_leaked=%d",
                      total, leaked_ip, leaked_reg);
        } else {
            printf("[INFO] %s: %d samples checked\n", name, total);
            TEST_PASS(name);
        }
    }

    goto kill_child;

kill_child:
    kill(child, SIGKILL);
    waitpid(child, &status, 0);

cleanup:
    if (mmap_buf != MAP_FAILED)
        munmap(mmap_buf, PERF_MMAP_SIZE);
    if (perf_fd >= 0)
        close(perf_fd);
    if (pipefd[0] >= 0) close(pipefd[0]);
    if (pipefd[1] >= 0) close(pipefd[1]);
    free_code_page(orig);
    free_code_page(recomp);
}

int main(void)
{
    printf("=== recompile_export_test ===\n");
    printf("pid=%d\n\n", getpid());

    test_signal_frame_pc_export();
    test_ptrace_getregset_pc_export();
    test_ptrace_singlestep_pc();
    test_perf_ip_export();
    test_perf_regs_pc_export();

    printf("\n=== Results: %d passed, %d failed, %d skipped ===\n",
           test_pass, test_fail, test_skip);
    return test_fail > 0 ? 1 : 0;
}
