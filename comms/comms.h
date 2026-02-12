#ifndef AEGIS_COMMS_H
#define AEGIS_COMMS_H

#include <stdio.h>

#include "anomaly/anomaly.h"
#include "classifier/classifier.h"
#include "core/core.h"

int comms_init(const char *endpoint_url);
int comms_send_telemetry(const telemetry_sample_t *sample,
                         const anomaly_result_t *anomaly,
                         const classifier_result_t *result);
int comms_send_alert(const telemetry_sample_t *sample,
                     const anomaly_result_t *anomaly,
                     const classifier_result_t *result);
void comms_shutdown(void);

/* Internal helper used by comms implementation files. */
int comms_internal_get_stream(FILE **out_stream);

#endif
