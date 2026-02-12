#ifndef AEGIS_ANOMALY_H
#define AEGIS_ANOMALY_H

#include <stdint.h>

#include "core/core.h"

int anomaly_init(void);
int anomaly_evaluate(const telemetry_sample_t *sample, anomaly_result_t *out);
void anomaly_shutdown(void);

/*
 * Internal model API used by anomaly.c and models.c.
 * This provides a baseline view without depending on baseline internals.
 */
typedef struct anomaly_metric_view {
    uint64_t count;
    double mean;
    double stddev;
    int ready;
} anomaly_metric_view_t;

typedef struct anomaly_model_view {
    anomaly_metric_view_t aes;
    anomaly_metric_view_t cycles;
    anomaly_metric_view_t instructions;
    anomaly_metric_view_t cache_miss_rate;
    anomaly_metric_view_t files_modified;
    anomaly_metric_view_t files_renamed;
    anomaly_metric_view_t files_deleted;
    anomaly_metric_view_t disk_write;
} anomaly_model_view_t;

int anomaly_models_init(void);
int anomaly_models_snapshot_and_update(const telemetry_sample_t *sample, anomaly_model_view_t *out);
void anomaly_models_shutdown(void);

#endif
