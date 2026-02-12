#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#include "anomaly/anomaly.h"

#define Z_THRESHOLD_FLAG 3.0
#define Z_STDDEV_EPSILON 1e-9
#define ANOMALY_SCORE_THRESHOLD 0.7

/*
 * anomaly_score = 1 - exp(-k * max_abs_z)
 * k ~= -ln(0.05)/3 ~= 0.9986 so z=3 maps to ~0.95.
 */
#define ANOMALY_SCORE_K 1.0

#define HARD_FILES_MODIFIED_PER_SEC 500.0
#define HARD_FILES_RENAMED_PER_SEC 200.0
#define HARD_DISK_WRITE_BPS (50.0 * 1024.0 * 1024.0)

static int value_is_valid(double value)
{
    return isfinite(value) ? 1 : 0;
}

static double metric_abs_z(double value, const anomaly_metric_view_t *metric)
{
    double z;

    if (metric == NULL || !value_is_valid(value) || metric->ready == 0) {
        return 0.0;
    }

    if (!value_is_valid(metric->mean) || !value_is_valid(metric->stddev) ||
        metric->stddev <= Z_STDDEV_EPSILON) {
        return 0.0;
    }

    z = (value - metric->mean) / metric->stddev;
    if (!value_is_valid(z)) {
        return 0.0;
    }

    return fabs(z);
}

static void set_hard_threshold_flags(const telemetry_sample_t *sample, uint32_t *flags)
{
    if (sample == NULL || flags == NULL) {
        return;
    }

    if (value_is_valid(sample->files_modified_per_sec) &&
        sample->files_modified_per_sec > HARD_FILES_MODIFIED_PER_SEC) {
        *flags |= ANOMALY_FLAG_WRITE_STORM;
    }

    if (value_is_valid(sample->files_renamed_per_sec) &&
        sample->files_renamed_per_sec > HARD_FILES_RENAMED_PER_SEC) {
        *flags |= ANOMALY_FLAG_RENAME_STORM;
    }

    if (value_is_valid(sample->disk_write_bytes_per_sec) &&
        sample->disk_write_bytes_per_sec > HARD_DISK_WRITE_BPS) {
        *flags |= ANOMALY_FLAG_WRITE_STORM;
    }
}

int anomaly_init(void)
{
    return anomaly_models_init();
}

int anomaly_evaluate(const telemetry_sample_t *sample, anomaly_result_t *out)
{
    anomaly_model_view_t model;
    double z_aes;
    double z_cycles;
    double z_instructions;
    double z_cache_miss;
    double z_files_modified;
    double z_files_renamed;
    double z_files_deleted;
    double z_disk_write;
    double max_abs_z;
    double cpu_proxy_z;
    uint32_t flags = 0U;
    int aes_supported;

    if (sample == NULL || out == NULL) {
        errno = EINVAL;
        return -1;
    }

    memset(out, 0, sizeof(*out));

    if (anomaly_models_snapshot_and_update(sample, &model) != 0) {
        return -1;
    }

    z_aes = metric_abs_z(sample->aes_instructions_per_sec, &model.aes);
    z_cycles = metric_abs_z(sample->cycles_per_sec, &model.cycles);
    z_instructions = metric_abs_z(sample->instructions_per_sec, &model.instructions);
    z_cache_miss = metric_abs_z(sample->cache_miss_rate, &model.cache_miss_rate);
    z_files_modified = metric_abs_z(sample->files_modified_per_sec, &model.files_modified);
    z_files_renamed = metric_abs_z(sample->files_renamed_per_sec, &model.files_renamed);
    z_files_deleted = metric_abs_z(sample->files_deleted_per_sec, &model.files_deleted);
    z_disk_write = metric_abs_z(sample->disk_write_bytes_per_sec, &model.disk_write);

    max_abs_z = 0.0;
    if (z_aes > max_abs_z) {
        max_abs_z = z_aes;
    }
    if (z_cycles > max_abs_z) {
        max_abs_z = z_cycles;
    }
    if (z_instructions > max_abs_z) {
        max_abs_z = z_instructions;
    }
    if (z_cache_miss > max_abs_z) {
        max_abs_z = z_cache_miss;
    }
    if (z_files_modified > max_abs_z) {
        max_abs_z = z_files_modified;
    }
    if (z_files_renamed > max_abs_z) {
        max_abs_z = z_files_renamed;
    }
    if (z_files_deleted > max_abs_z) {
        max_abs_z = z_files_deleted;
    }
    if (z_disk_write > max_abs_z) {
        max_abs_z = z_disk_write;
    }

    if (max_abs_z > 0.0) {
        out->anomaly_score = 1.0 - exp(-ANOMALY_SCORE_K * max_abs_z);
    } else {
        out->anomaly_score = 0.0;
    }
    out->z_score = max_abs_z;

    aes_supported = (sample->aes_instructions_per_sec != -1.0) ? 1 : 0;
    if (aes_supported) {
        if (z_aes >= Z_THRESHOLD_FLAG) {
            flags |= ANOMALY_FLAG_CRYPTO_SPIKE;
        }
    } else {
        cpu_proxy_z = z_cycles;
        if (z_instructions > cpu_proxy_z) {
            cpu_proxy_z = z_instructions;
        }

        if (cpu_proxy_z >= Z_THRESHOLD_FLAG && z_disk_write >= Z_THRESHOLD_FLAG) {
            flags |= ANOMALY_FLAG_CRYPTO_SPIKE;
        }
    }

    if (z_files_modified >= Z_THRESHOLD_FLAG || z_disk_write >= Z_THRESHOLD_FLAG) {
        flags |= ANOMALY_FLAG_WRITE_STORM;
    }
    if (z_files_renamed >= Z_THRESHOLD_FLAG) {
        flags |= ANOMALY_FLAG_RENAME_STORM;
    }
    if (z_files_deleted >= Z_THRESHOLD_FLAG) {
        flags |= ANOMALY_FLAG_DELETE_STORM;
    }

    /*
     * Absolute fallback thresholds when baseline is unready or stddev collapses:
     *   files_modified_per_sec > 500
     *   files_renamed_per_sec > 200
     *   disk_write_bytes_per_sec > 50 MB/s
     */
    set_hard_threshold_flags(sample, &flags);

    out->flags = flags;
    out->is_anomalous =
        (out->anomaly_score >= ANOMALY_SCORE_THRESHOLD || flags != 0U) ? 1 : 0;

    return 0;
}

void anomaly_shutdown(void)
{
    anomaly_models_shutdown();
}
