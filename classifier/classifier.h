#ifndef AEGIS_CLASSIFIER_H
#define AEGIS_CLASSIFIER_H

#include "anomaly/anomaly.h"
#include "core/core.h"

int classifier_init(void);
int classifier_classify(const telemetry_sample_t *sample,
                        const anomaly_result_t *anomaly,
                        classifier_result_t *out);
void classifier_shutdown(void);

/*
 * Internal helpers shared across classifier implementation files.
 */
double classifier_compute_ransomware_score(const anomaly_result_t *anomaly);
verdict_kind_t classifier_score_to_verdict(double score);

#endif
