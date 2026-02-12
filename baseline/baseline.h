#ifndef AEGIS_BASELINE_H
#define AEGIS_BASELINE_H

#include "core/core.h"

int baseline_init(const char *db_path);
int baseline_update(const telemetry_sample_t *sample);
int baseline_ready(void);
void baseline_shutdown(void);
int baseline_save(void);
int baseline_load(void);

#endif
