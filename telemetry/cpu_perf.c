#include <errno.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "telemetry/aegis_telemetry.h"

typedef struct cpu_perf_state {
    int init_attempted;
    int initialized;
    int disabled;
    int have_prev;
    long cpu_count;
    int *fd_cycles;
    int *fd_instructions;
    int *fd_cache_misses;
    int cycles_available;
    int instructions_available;
    int cache_misses_available;
    uint64_t last_cycles;
    uint64_t last_instructions;
    uint64_t last_cache_misses;
    uint64_t last_ts_ns;
} cpu_perf_state_t;

typedef struct perf_read_value {
    uint64_t value;
    uint64_t time_enabled;
    uint64_t time_running;
} perf_read_value_t;

static cpu_perf_state_t g_state = {
    .init_attempted = 0,
    .initialized = 0,
    .disabled = 0,
    .have_prev = 0,
    .cpu_count = 0,
    .fd_cycles = NULL,
    .fd_instructions = NULL,
    .fd_cache_misses = NULL,
    .cycles_available = 0,
    .instructions_available = 0,
    .cache_misses_available = 0,
    .last_cycles = 0U,
    .last_instructions = 0U,
    .last_cache_misses = 0U,
    .last_ts_ns = 0U,
};

static int g_warned_perf_open_failure = 0;

static int perf_event_open_wrapper(struct perf_event_attr *attr,
                                   pid_t pid,
                                   int cpu,
                                   int group_fd,
                                   unsigned long flags)
{
    return (int)syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void warn_open_failure_once(const char *counter_name, int errnum)
{
    if (g_warned_perf_open_failure) {
        return;
    }

    fprintf(stderr,
            "cpu_perf: perf_event_open failed (%s): %s\n",
            counter_name,
            strerror(errnum));
    g_warned_perf_open_failure = 1;
}

static int open_counter_on_cpu(uint32_t type, uint64_t config, int cpu)
{
    struct perf_event_attr attr;
    int fd;

    memset(&attr, 0, sizeof(attr));
    attr.type = type;
    attr.size = sizeof(attr);
    attr.config = config;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;

    fd = perf_event_open_wrapper(&attr, -1, cpu, -1, 0);
    if (fd < 0) {
        return -1;
    }

    (void)ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    (void)ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    return fd;
}

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

static uint64_t saturating_add_u64(uint64_t a, uint64_t b)
{
    if (UINT64_MAX - a < b) {
        return UINT64_MAX;
    }

    return a + b;
}

static int read_counter_scaled_fd(int fd, uint64_t *value)
{
    ssize_t nread;
    perf_read_value_t read_value;
    long double scaled_value;

    if (fd < 0 || value == NULL) {
        return -1;
    }

    nread = read(fd, &read_value, sizeof(read_value));
    if (nread != (ssize_t)sizeof(read_value)) {
        return -1;
    }

    if (read_value.time_running == 0U) {
        return -1;
    }

    scaled_value = (long double)read_value.value;
    if (read_value.time_running < read_value.time_enabled) {
        scaled_value *= (long double)read_value.time_enabled / (long double)read_value.time_running;
    }

    if (scaled_value < 0.0L) {
        *value = 0U;
    } else if (scaled_value > (long double)UINT64_MAX) {
        *value = UINT64_MAX;
    } else {
        *value = (uint64_t)(scaled_value + 0.5L);
    }

    return 0;
}

static int read_counter_sum_scaled(const int *fds, long cpu_count, uint64_t *value)
{
    long cpu_idx;
    uint64_t total = 0U;
    int read_any = 0;

    if (fds == NULL || value == NULL || cpu_count <= 0) {
        return -1;
    }

    for (cpu_idx = 0; cpu_idx < cpu_count; ++cpu_idx) {
        uint64_t current_value;

        if (fds[cpu_idx] < 0) {
            continue;
        }

        if (read_counter_scaled_fd(fds[cpu_idx], &current_value) != 0) {
            continue;
        }

        total = saturating_add_u64(total, current_value);
        read_any = 1;
    }

    if (!read_any) {
        return -1;
    }

    *value = total;
    return 0;
}

static uint64_t delta_counter(uint64_t current, uint64_t previous)
{
    if (current < previous) {
        return 0U;
    }

    return current - previous;
}

static void close_fd_array(int **fd_array, long cpu_count)
{
    long cpu_idx;

    if (fd_array == NULL || *fd_array == NULL) {
        return;
    }

    for (cpu_idx = 0; cpu_idx < cpu_count; ++cpu_idx) {
        if ((*fd_array)[cpu_idx] >= 0) {
            (void)close((*fd_array)[cpu_idx]);
            (*fd_array)[cpu_idx] = -1;
        }
    }

    free(*fd_array);
    *fd_array = NULL;
}

static int *alloc_fd_array(long cpu_count)
{
    int *fd_array;
    long cpu_idx;

    fd_array = (int *)malloc((size_t)cpu_count * sizeof(int));
    if (fd_array == NULL) {
        return NULL;
    }

    for (cpu_idx = 0; cpu_idx < cpu_count; ++cpu_idx) {
        fd_array[cpu_idx] = -1;
    }

    return fd_array;
}

static void cpu_perf_shutdown_internal(void)
{
    close_fd_array(&g_state.fd_cycles, g_state.cpu_count);
    close_fd_array(&g_state.fd_instructions, g_state.cpu_count);
    close_fd_array(&g_state.fd_cache_misses, g_state.cpu_count);

    g_state.init_attempted = 0;
    g_state.initialized = 0;
    g_state.disabled = 0;
    g_state.have_prev = 0;
    g_state.cpu_count = 0;
    g_state.cycles_available = 0;
    g_state.instructions_available = 0;
    g_state.cache_misses_available = 0;
    g_state.last_cycles = 0U;
    g_state.last_instructions = 0U;
    g_state.last_cache_misses = 0U;
    g_state.last_ts_ns = 0U;
    g_warned_perf_open_failure = 0;
}

void cpu_perf_shutdown(void)
{
    cpu_perf_shutdown_internal();
}

static void ensure_initialized(void)
{
    long cpu_count;
    long cpu_idx;
    int first_open_errno = 0;

    if (g_state.initialized || g_state.disabled) {
        return;
    }

    g_state.init_attempted = 1;

    cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpu_count <= 0) {
        cpu_count = 1;
    }

    g_state.cpu_count = cpu_count;
    g_state.fd_cycles = alloc_fd_array(cpu_count);
    g_state.fd_instructions = alloc_fd_array(cpu_count);
    g_state.fd_cache_misses = alloc_fd_array(cpu_count);

    if (g_state.fd_cycles == NULL || g_state.fd_instructions == NULL || g_state.fd_cache_misses == NULL) {
        close_fd_array(&g_state.fd_cycles, g_state.cpu_count);
        close_fd_array(&g_state.fd_instructions, g_state.cpu_count);
        close_fd_array(&g_state.fd_cache_misses, g_state.cpu_count);
        g_state.cpu_count = 0;
        g_state.disabled = 1;
        return;
    }

    for (cpu_idx = 0; cpu_idx < cpu_count; ++cpu_idx) {
        int fd;

        fd = open_counter_on_cpu(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, (int)cpu_idx);
        if (fd >= 0) {
            g_state.fd_cycles[cpu_idx] = fd;
            g_state.cycles_available += 1;
        } else {
            if (first_open_errno == 0) {
                first_open_errno = errno;
            }
            warn_open_failure_once("cycles", errno);
        }

        fd = open_counter_on_cpu(PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS, (int)cpu_idx);
        if (fd >= 0) {
            g_state.fd_instructions[cpu_idx] = fd;
            g_state.instructions_available += 1;
        } else {
            if (first_open_errno == 0) {
                first_open_errno = errno;
            }
            warn_open_failure_once("instructions", errno);
        }

        fd = open_counter_on_cpu(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES, (int)cpu_idx);
        if (fd >= 0) {
            g_state.fd_cache_misses[cpu_idx] = fd;
            g_state.cache_misses_available += 1;
        } else {
            if (first_open_errno == 0) {
                first_open_errno = errno;
            }
            warn_open_failure_once("cache-misses", errno);
        }
    }

    if (g_state.cycles_available == 0 &&
        g_state.instructions_available == 0 &&
        g_state.cache_misses_available == 0) {
        if (first_open_errno != 0) {
            warn_open_failure_once("all-counters", first_open_errno);
        }

        close_fd_array(&g_state.fd_cycles, g_state.cpu_count);
        close_fd_array(&g_state.fd_instructions, g_state.cpu_count);
        close_fd_array(&g_state.fd_cache_misses, g_state.cpu_count);
        g_state.cpu_count = 0;
        g_state.disabled = 1;
        return;
    }

    g_state.initialized = 1;
}

void collect_cpu_metrics(struct cpu_metrics *out)
{
    uint64_t now_ns;
    double elapsed_seconds;
    uint64_t cycles_now = 0U;
    uint64_t instructions_now = 0U;
    uint64_t cache_misses_now = 0U;

    if (out == NULL) {
        return;
    }

    memset(out, 0, sizeof(*out));
    out->aes_instructions_per_sec = -1.0;
    out->aes_supported = 0;

    ensure_initialized();
    if (!g_state.initialized || g_state.disabled) {
        return;
    }

    now_ns = monotonic_now_ns();
    if (now_ns == 0U) {
        return;
    }

    if (g_state.cycles_available > 0 &&
        read_counter_sum_scaled(g_state.fd_cycles, g_state.cpu_count, &cycles_now) != 0) {
        cycles_now = g_state.last_cycles;
    }

    if (g_state.instructions_available > 0 &&
        read_counter_sum_scaled(g_state.fd_instructions, g_state.cpu_count, &instructions_now) != 0) {
        instructions_now = g_state.last_instructions;
    }

    if (g_state.cache_misses_available > 0 &&
        read_counter_sum_scaled(g_state.fd_cache_misses, g_state.cpu_count, &cache_misses_now) != 0) {
        cache_misses_now = g_state.last_cache_misses;
    }

    if (!g_state.have_prev || now_ns <= g_state.last_ts_ns) {
        g_state.last_cycles = cycles_now;
        g_state.last_instructions = instructions_now;
        g_state.last_cache_misses = cache_misses_now;
        g_state.last_ts_ns = now_ns;
        g_state.have_prev = 1;
        return;
    }

    elapsed_seconds = (double)(now_ns - g_state.last_ts_ns) / 1000000000.0;
    if (elapsed_seconds <= 0.0) {
        g_state.last_cycles = cycles_now;
        g_state.last_instructions = instructions_now;
        g_state.last_cache_misses = cache_misses_now;
        g_state.last_ts_ns = now_ns;
        return;
    }

    if (g_state.cycles_available > 0) {
        out->cycles_per_sec = (double)delta_counter(cycles_now, g_state.last_cycles) / elapsed_seconds;
    }

    if (g_state.instructions_available > 0) {
        out->instructions_per_sec =
            (double)delta_counter(instructions_now, g_state.last_instructions) / elapsed_seconds;
    }

    if (g_state.instructions_available > 0 && g_state.cache_misses_available > 0) {
        uint64_t instruction_delta = delta_counter(instructions_now, g_state.last_instructions);
        uint64_t cache_miss_delta = delta_counter(cache_misses_now, g_state.last_cache_misses);

        if (instruction_delta > 0U) {
            out->cache_miss_rate = (double)cache_miss_delta / (double)instruction_delta;
        }
    }

    out->aes_instructions_per_sec = -1.0;

    g_state.last_cycles = cycles_now;
    g_state.last_instructions = instructions_now;
    g_state.last_cache_misses = cache_misses_now;
    g_state.last_ts_ns = now_ns;
}
