#include <math.h>
#include <stdint.h>
#include <string.h>

#include "anomaly/anomaly.h"

#define MODEL_READY_MIN_SAMPLES 300U

typedef struct running_metric {
    uint64_t count;
    double mean;
    double m2;
} running_metric_t;

typedef struct model_state {
    int initialized;
    running_metric_t aes;
    running_metric_t cycles;
    running_metric_t instructions;
    running_metric_t cache_miss_rate;
    running_metric_t files_modified;
    running_metric_t files_renamed;
    running_metric_t files_deleted;
    running_metric_t disk_write;
} model_state_t;

static model_state_t g_model_state;

static int value_is_valid(double value)
{
    return isfinite(value) ? 1 : 0;
}

static void running_update(running_metric_t *metric, double value)
{
    double count_d;
    double delta;
    double delta2;

    if (metric == NULL) {
        return;
    }

    metric->count += 1U;
    count_d = (double)metric->count;
    delta = value - metric->mean;
    metric->mean += delta / count_d;
    delta2 = value - metric->mean;
    metric->m2 += delta * delta2;
}

static double running_stddev(const running_metric_t *metric)
{
    double variance;

    if (metric == NULL || metric->count < 2U) {
        return 0.0;
    }

    variance = metric->m2 / (double)(metric->count - 1U);
    if (!isfinite(variance) || variance <= 0.0) {
        return 0.0;
    }

    return sqrt(variance);
}

static void snapshot_metric(const running_metric_t *src, anomaly_metric_view_t *dst)
{
    if (src == NULL || dst == NULL) {
        return;
    }

    dst->count = src->count;
    dst->mean = src->mean;
    dst->stddev = running_stddev(src);
    dst->ready = (src->count >= MODEL_READY_MIN_SAMPLES) ? 1 : 0;
}

static void snapshot_all(anomaly_model_view_t *out)
{
    snapshot_metric(&g_model_state.aes, &out->aes);
    snapshot_metric(&g_model_state.cycles, &out->cycles);
    snapshot_metric(&g_model_state.instructions, &out->instructions);
    snapshot_metric(&g_model_state.cache_miss_rate, &out->cache_miss_rate);
    snapshot_metric(&g_model_state.files_modified, &out->files_modified);
    snapshot_metric(&g_model_state.files_renamed, &out->files_renamed);
    snapshot_metric(&g_model_state.files_deleted, &out->files_deleted);
    snapshot_metric(&g_model_state.disk_write, &out->disk_write);
}

static void update_from_sample(const telemetry_sample_t *sample)
{
    if (sample->aes_instructions_per_sec != -1.0 &&
        value_is_valid(sample->aes_instructions_per_sec)) {
        running_update(&g_model_state.aes, sample->aes_instructions_per_sec);
    }

    if (value_is_valid(sample->cycles_per_sec)) {
        running_update(&g_model_state.cycles, sample->cycles_per_sec);
    }
    if (value_is_valid(sample->instructions_per_sec)) {
        running_update(&g_model_state.instructions, sample->instructions_per_sec);
    }
    if (value_is_valid(sample->cache_miss_rate)) {
        running_update(&g_model_state.cache_miss_rate, sample->cache_miss_rate);
    }
    if (value_is_valid(sample->files_modified_per_sec)) {
        running_update(&g_model_state.files_modified, sample->files_modified_per_sec);
    }
    if (value_is_valid(sample->files_renamed_per_sec)) {
        running_update(&g_model_state.files_renamed, sample->files_renamed_per_sec);
    }
    if (value_is_valid(sample->files_deleted_per_sec)) {
        running_update(&g_model_state.files_deleted, sample->files_deleted_per_sec);
    }
    if (value_is_valid(sample->disk_write_bytes_per_sec)) {
        running_update(&g_model_state.disk_write, sample->disk_write_bytes_per_sec);
    }
}

int anomaly_models_init(void)
{
    memset(&g_model_state, 0, sizeof(g_model_state));
    g_model_state.initialized = 1;
    return 0;
}

int anomaly_models_snapshot_and_update(const telemetry_sample_t *sample, anomaly_model_view_t *out)
{
    if (sample == NULL || out == NULL || !g_model_state.initialized) {
        return -1;
    }

    memset(out, 0, sizeof(*out));

    /*
     * Baseline fallback: keep local rolling statistics, because baseline internals
     * are intentionally opaque to this module.
     */
    snapshot_all(out);
    update_from_sample(sample);
    return 0;
}

void anomaly_models_shutdown(void)
{
    memset(&g_model_state, 0, sizeof(g_model_state));
}
