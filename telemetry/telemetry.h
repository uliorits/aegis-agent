#ifndef AEGIS_TELEMETRY_H
#define AEGIS_TELEMETRY_H

#include "core/core.h"

int telemetry_init(const char *root_path);
int telemetry_collect(telemetry_sample_t *sample);
void telemetry_shutdown(void);

#endif
