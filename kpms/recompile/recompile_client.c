/*
 * recompile_client - Recompile Redirect Client Tool
 *
 * Usage:
 *   recompile_client -p <pid> -a <orig_addr> -t <recomp_addr>  # Register mapping
 *   recompile_client -p <pid> -a <orig_addr> -R                # Release mapping
 *   recompile_client -p <pid> -b <lib> -o <offset> -t <addr>   # Use lib+offset
 *   recompile_client -p <pid> -m                               # Show executable maps
 *
 * Copyright (C) 2024
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <errno.h>
#include <getopt.h>

/* prctl options */
#define PR_RECOMPILE_REGISTER   0x52430001
#define PR_RECOMPILE_RELEASE    0x52430002

static void print_usage(const char *prog)
{
    printf("recompile_client - Recompile Redirect Client\n\n");
    printf("Usage:\n");
    printf("  %s -p <pid> -a <orig_addr> -t <recomp_addr>  Register page redirect\n", prog);
    printf("  %s -p <pid> -a <orig_addr> -R                Release page redirect\n", prog);
    printf("  %s -p <pid> -b <lib> -o <offset> -t <addr>   Use lib+offset as orig_addr\n", prog);
    printf("  %s -p <pid> -m                               Show executable maps\n", prog);
    printf("\nOptions:\n");
    printf("  -p, --pid <pid>       Target process ID (0 for self)\n");
    printf("  -a, --addr <addr>     Original page address (hex)\n");
    printf("  -t, --target <addr>   Recompiled page address (hex)\n");
    printf("  -b, --base <lib>      Library name to find base address\n");
    printf("  -o, --offset <off>    Offset from library base (hex)\n");
    printf("  -R, --release         Release mapping at address\n");
    printf("  -m, --maps            Show executable memory regions\n");
    printf("  -h, --help            Show this help\n");
    printf("\nExamples:\n");
    printf("  %s -p 1234 -a 0x7000000000 -t 0x7100000000\n", prog);
    printf("  %s -p 1234 -b libc.so -o 0x50000 -t 0x7100050000\n", prog);
    printf("  %s -p 1234 -a 0x7000000000 -R\n", prog);
    printf("  %s -p 1234 -m\n", prog);
    printf("\nNotes:\n");
    printf("  Addresses are page-aligned (4K). Offsets within a page are preserved.\n");
    printf("  When executing at orig_page+N, PC is redirected to recomp_page+N.\n");
}

static FILE *open_maps_file(pid_t pid)
{
    char path[256];
    if (pid == 0)
        snprintf(path, sizeof(path), "/proc/self/maps");
    else
        snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    return fopen(path, "r");
}

static void show_executable_maps(pid_t pid)
{
    FILE *f = open_maps_file(pid);
    char line[512];

    if (!f) {
        fprintf(stderr, "Cannot open maps for pid %d: %s\n", pid, strerror(errno));
        return;
    }

    printf("Executable regions for pid %d:\n", pid ? pid : getpid());
    printf("%-18s %-18s %-6s %s\n", "START", "END", "PERM", "MAPPING");
    printf("-----------------------------------------------------------\n");

    while (fgets(line, sizeof(line), f)) {
        unsigned long start, end;
        char perms[8], path[256];
        int n;

        path[0] = '\0';
        n = sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]",
                   &start, &end, perms, path);
        if (n < 3) continue;

        /* Show only executable regions */
        if (perms[2] == 'x') {
            printf("0x%016lx 0x%016lx %-6s %s\n", start, end, perms, path);
        }
    }
    fclose(f);
}

static unsigned long find_lib_base(pid_t pid, const char *lib_name)
{
    FILE *f = open_maps_file(pid);
    char line[512];

    if (!f) return 0;

    while (fgets(line, sizeof(line), f)) {
        unsigned long start;
        char perms[8], path[256];

        path[0] = '\0';
        unsigned long end_unused;
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]",
                   &start, &end_unused, perms, path) < 3)
            continue;

        if (perms[2] == 'x' && strstr(path, lib_name)) {
            fclose(f);
            return start;
        }
    }
    fclose(f);
    return 0;
}

int main(int argc, char *argv[])
{
    pid_t pid = -1;
    unsigned long addr = 0;
    unsigned long target = 0;
    const char *lib_name = NULL;
    unsigned long offset = 0;
    int do_release = 0;
    int do_maps = 0;
    int has_addr = 0;
    int has_target = 0;
    int ret;

    static struct option long_opts[] = {
        {"pid",     required_argument, 0, 'p'},
        {"addr",    required_argument, 0, 'a'},
        {"target",  required_argument, 0, 't'},
        {"base",    required_argument, 0, 'b'},
        {"offset",  required_argument, 0, 'o'},
        {"release", no_argument,       0, 'R'},
        {"maps",    no_argument,       0, 'm'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:a:t:b:o:Rmh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            pid = atoi(optarg);
            break;
        case 'a':
            addr = strtoull(optarg, NULL, 0);
            has_addr = 1;
            break;
        case 't':
            target = strtoull(optarg, NULL, 0);
            has_target = 1;
            break;
        case 'b':
            lib_name = optarg;
            break;
        case 'o':
            offset = strtoull(optarg, NULL, 0);
            break;
        case 'R':
            do_release = 1;
            break;
        case 'm':
            do_maps = 1;
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    if (pid < 0) {
        fprintf(stderr, "Error: -p <pid> is required\n\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Show maps */
    if (do_maps) {
        show_executable_maps(pid);
        return 0;
    }

    /* Resolve lib+offset to address */
    if (lib_name) {
        unsigned long base = find_lib_base(pid, lib_name);
        if (!base) {
            fprintf(stderr, "Error: library '%s' not found in pid %d maps\n",
                    lib_name, pid);
            return 1;
        }
        addr = base + offset;
        has_addr = 1;
        printf("Resolved: %s + 0x%lx = 0x%lx\n", lib_name, offset, addr);
    }

    if (!has_addr) {
        fprintf(stderr, "Error: address required (-a or -b/-o)\n\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Release */
    if (do_release) {
        printf("Releasing mapping at 0x%lx for pid %d...\n", addr, pid);
        ret = prctl(PR_RECOMPILE_RELEASE, pid, addr, 0, 0);
        if (ret < 0) {
            fprintf(stderr, "prctl(RELEASE) failed: %s (ret=%d, errno=%d)\n",
                    strerror(errno), ret, errno);
            return 1;
        }
        printf("OK: released mapping at 0x%lx\n", addr);
        return 0;
    }

    /* Register */
    if (!has_target) {
        fprintf(stderr, "Error: -t <recomp_addr> required for register\n\n");
        print_usage(argv[0]);
        return 1;
    }

    printf("Registering redirect: 0x%lx -> 0x%lx for pid %d...\n",
           addr, target, pid);
    ret = prctl(PR_RECOMPILE_REGISTER, pid, addr, target, 0);
    if (ret < 0) {
        fprintf(stderr, "prctl(REGISTER) failed: %s (ret=%d, errno=%d)\n",
                strerror(errno), ret, errno);
        return 1;
    }
    printf("OK: registered redirect 0x%lx -> 0x%lx\n", addr, target);
    return 0;
}
