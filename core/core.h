#ifndef AEGIS_CORE_H
#define AEGIS_CORE_H

#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <sys/types.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef enum agent_mode {
    AGENT_MODE_BASELINE = 0,
    AGENT_MODE_DETECT = 1
} agent_mode_t;

typedef struct agent_config {
    unsigned int sampling_interval_ms;
    char telemetry_root_path[PATH_MAX];
    char cloud_endpoint_url[1024];
    char baseline_db_path[PATH_MAX];
    agent_mode_t mode;
} agent_config_t;

typedef struct telemetry_sample {
    uint64_t timestamp_ns;
    double cycles_per_sec;
    double instructions_per_sec;
    double cache_miss_rate;
    double aes_instructions_per_sec;
    double files_modified_per_sec;
    double files_renamed_per_sec;
    double files_deleted_per_sec;
    pid_t top_pid;
    char top_comm[64];
    double disk_read_bytes_per_sec;
    double disk_write_bytes_per_sec;
} telemetry_sample_t;

typedef struct anomaly_result {
    int is_anomalous;
    double z_score;
    double anomaly_score;
    uint32_t flags;
} anomaly_result_t;

#define ANOMALY_FLAG_CRYPTO_SPIKE (1u << 0)
#define ANOMALY_FLAG_WRITE_STORM  (1u << 1)
#define ANOMALY_FLAG_RENAME_STORM (1u << 2)
#define ANOMALY_FLAG_DELETE_STORM (1u << 3)

typedef enum verdict_kind {
    VERDICT_SAFE = 0,
    VERDICT_SUSPICIOUS = 1,
    VERDICT_RANSOMWARE = 2
} verdict_kind_t;

typedef struct classifier_result {
    verdict_kind_t verdict;
    double confidence;
    double ransomware_score;
} classifier_result_t;

int config_load(const char *path, agent_config_t *out_cfg);
int agent_loop_run(const agent_config_t *cfg, const volatile sig_atomic_t *stop_flag);

#endif
