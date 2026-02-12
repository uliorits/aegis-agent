#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "telemetry/aegis_telemetry.h"
#include "telemetry/telemetry.h"

typedef struct telemetry_state {
    int initialized;
    int has_last_timestamp;
    uint64_t last_timestamp_ns;
} telemetry_state_t;

static telemetry_state_t g_state;
static const double k_rate_epsilon_seconds = 1e-6;

static uint64_t monotonic_now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0U;
    }

    if (ts.tv_sec < 0) {
        return 0U;
    }

    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static double elapsed_seconds(uint64_t now_ns, uint64_t prev_ns)
{
    if (now_ns <= prev_ns) {
        return 0.0;
    }

    return (double)(now_ns - prev_ns) / 1000000000.0;
}

int telemetry_init(const char *root_path)
{
    if (root_path == NULL || root_path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    if (g_state.initialized) {
        telemetry_shutdown();
    }

    memset(&g_state, 0, sizeof(g_state));

    if (init_fs_monitor(root_path) != 0) {
        return -1;
    }

    g_state.initialized = 1;
    return 0;
}

int telemetry_collect(telemetry_sample_t *sample)
{
    uint64_t now_ns;
    double dt_seconds = 0.0;
    struct cpu_metrics cpu;
    struct fs_metrics fs;
    struct process_metrics proc;
    struct io_metrics io;

    if (sample == NULL || !g_state.initialized) {
        errno = EINVAL;
        return -1;
    }

    memset(sample, 0, sizeof(*sample));
    sample->aes_instructions_per_sec = -1.0;

    now_ns = monotonic_now_ns();
    if (now_ns == 0U) {
        return -1;
    }

    sample->timestamp_ns = now_ns;

    if (g_state.has_last_timestamp) {
        dt_seconds = elapsed_seconds(now_ns, g_state.last_timestamp_ns);
        if (dt_seconds < k_rate_epsilon_seconds) {
            dt_seconds = k_rate_epsilon_seconds;
        }
    }

    memset(&cpu, 0, sizeof(cpu));
    cpu.aes_instructions_per_sec = -1.0;
    collect_cpu_metrics(&cpu);
    sample->cycles_per_sec = cpu.cycles_per_sec;
    sample->instructions_per_sec = cpu.instructions_per_sec;
    sample->cache_miss_rate = cpu.cache_miss_rate;
    sample->aes_instructions_per_sec = cpu.aes_supported ? cpu.aes_instructions_per_sec : -1.0;

    memset(&fs, 0, sizeof(fs));
    collect_fs_metrics(&fs);
    if (g_state.has_last_timestamp) {
        sample->files_modified_per_sec = (double)fs.files_modified / dt_seconds;
        sample->files_renamed_per_sec = (double)fs.files_renamed / dt_seconds;
        sample->files_deleted_per_sec = (double)fs.files_deleted / dt_seconds;
    }

    memset(&proc, 0, sizeof(proc));
    get_top_crypto_process(&proc);
    sample->top_pid = proc.top_pid;
    proc.top_comm[sizeof(proc.top_comm) - 1U] = '\0';
    (void)snprintf(sample->top_comm, sizeof(sample->top_comm), "%s", proc.top_comm);

    memset(&io, 0, sizeof(io));
    collect_io_metrics(&io);
    sample->disk_read_bytes_per_sec = io.disk_read_rate;
    sample->disk_write_bytes_per_sec = io.disk_write_rate;

    g_state.last_timestamp_ns = now_ns;
    g_state.has_last_timestamp = 1;

    return 0;
}

void telemetry_shutdown(void)
{
    if (!g_state.initialized) {
        return;
    }

    shutdown_fs_monitor();
    memset(&g_state, 0, sizeof(g_state));
}
