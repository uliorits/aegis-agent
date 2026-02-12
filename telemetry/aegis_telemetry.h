#ifndef AEGIS_TELEMETRY_INTERNAL_H
#define AEGIS_TELEMETRY_INTERNAL_H

#include <stdint.h>
#include <sys/types.h>

struct cpu_metrics {
    double cycles_per_sec;
    double instructions_per_sec;
    double cache_miss_rate;
    double aes_instructions_per_sec;
    int aes_supported;
};

struct fs_metrics {
    uint64_t files_modified;
    uint64_t files_renamed;
    uint64_t files_deleted;
};

struct process_metrics {
    pid_t top_pid;
    char top_comm[64];
};

struct io_metrics {
    double disk_read_rate;
    double disk_write_rate;
};

void collect_cpu_metrics(struct cpu_metrics *out);
int init_fs_monitor(const char *root_path);
void shutdown_fs_monitor(void);
void collect_fs_metrics(struct fs_metrics *out);
void get_top_crypto_process(struct process_metrics *out);
void collect_io_metrics(struct io_metrics *out);

#endif
