add_kpm_module(recompile
    core/capabilities.c
    core/runtime.c
    fork_guard/guard.c
    pc_guard/export_guard.c
    module/dynamic_probe.c
    module/module.c
)

# Build client tool (userspace)
add_executable(recompile_client recompile_client.c)
target_link_options(recompile_client PRIVATE -static -s)

# Build test program (userspace)
add_executable(recompile_test recompile_test.c)
target_link_options(recompile_test PRIVATE -static -s)

# Build comprehensive fork test (userspace)
add_executable(recompile_fork_test recompile_fork_test.c)
target_link_options(recompile_fork_test PRIVATE -static -s -pthread)

# Build PC export test (userspace)
add_executable(recompile_export_test recompile_export_test.c)
target_link_options(recompile_export_test PRIVATE -static -s)
