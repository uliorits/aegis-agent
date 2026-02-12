#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "core/core.h"

/* External module interfaces (implemented outside core/). */
int telemetry_init(const char *root_path);
int telemetry_collect(telemetry_sample_t *sample);
void telemetry_shutdown(void);

int baseline_init(const char *db_path);
int baseline_update(const telemetry_sample_t *sample);
int baseline_ready(void);
void baseline_shutdown(void);

int anomaly_init(void);
int anomaly_evaluate(const telemetry_sample_t *sample, anomaly_result_t *result);
void anomaly_shutdown(void);

int classifier_init(void);
int classifier_classify(const telemetry_sample_t *sample,
                        const anomaly_result_t *anomaly,
                        classifier_result_t *result);
void classifier_shutdown(void);

int comms_init(const char *endpoint_url);
int comms_send_telemetry(const telemetry_sample_t *sample,
                         const anomaly_result_t *anomaly,
                         const classifier_result_t *result);
int comms_send_alert(const telemetry_sample_t *sample,
                     const anomaly_result_t *anomaly,
                     const classifier_result_t *result);
void comms_shutdown(void);

static int sleep_interruptible_ms(unsigned int ms, const volatile sig_atomic_t *stop_flag)
{
    struct timespec req;
    struct timespec rem;

    req.tv_sec = (time_t)(ms / 1000U);
    req.tv_nsec = (long)((ms % 1000U) * 1000000UL);

    while (nanosleep(&req, &rem) != 0) {
        if (errno == EINTR) {
            if (stop_flag != NULL && *stop_flag != 0) {
                return 0;
            }
            req = rem;
            continue;
        }

        perror("agent_loop: nanosleep");
        return -1;
    }

    return 0;
}

int agent_loop_run(const agent_config_t *cfg, const volatile sig_atomic_t *stop_flag)
{
    telemetry_sample_t sample;
    anomaly_result_t anomaly;
    classifier_result_t classification;
    int rc = -1;
    int baseline_not_ready_logged = 0;

    if (cfg == NULL) {
        fprintf(stderr, "agent_loop_run: cfg is NULL\n");
        return -1;
    }

    if (telemetry_init(cfg->telemetry_root_path) != 0) {
        fprintf(stderr, "agent_loop_run: telemetry_init failed\n");
        return -1;
    }

    if (baseline_init(cfg->baseline_db_path) != 0) {
        fprintf(stderr, "agent_loop_run: baseline_init failed\n");
        goto cleanup_telemetry;
    }

    if (anomaly_init() != 0) {
        fprintf(stderr, "agent_loop_run: anomaly_init failed\n");
        goto cleanup_baseline;
    }

    if (classifier_init() != 0) {
        fprintf(stderr, "agent_loop_run: classifier_init failed\n");
        goto cleanup_anomaly;
    }

    if (comms_init(cfg->cloud_endpoint_url) != 0) {
        fprintf(stderr, "agent_loop_run: comms_init failed\n");
        goto cleanup_classifier;
    }

    while (stop_flag == NULL || *stop_flag == 0) {
        memset(&sample, 0, sizeof(sample));

        if (telemetry_collect(&sample) != 0) {
            fprintf(stderr, "agent_loop_run: telemetry_collect failed\n");
            goto cleanup_comms;
        }

        if (cfg->mode == AGENT_MODE_BASELINE) {
            if (baseline_update(&sample) != 0) {
                fprintf(stderr, "agent_loop_run: baseline_update failed\n");
                goto cleanup_comms;
            }

            if (comms_send_telemetry(&sample, NULL, NULL) != 0) {
                fprintf(stderr, "agent_loop_run: comms_send_telemetry failed in baseline mode\n");
            }
        } else {
            if (!baseline_ready()) {
                if (baseline_update(&sample) != 0) {
                    fprintf(stderr, "agent_loop_run: baseline_update failed while waiting for baseline readiness\n");
                    goto cleanup_comms;
                }

                if (!baseline_not_ready_logged) {
                    fprintf(stderr,
                            "agent_loop_run: baseline is not ready in detect mode; continuing learning until ready\n");
                    baseline_not_ready_logged = 1;
                }

                if (comms_send_telemetry(&sample, NULL, NULL) != 0) {
                    fprintf(stderr,
                            "agent_loop_run: comms_send_telemetry failed while waiting for baseline readiness\n");
                }

                if (sleep_interruptible_ms(cfg->sampling_interval_ms, stop_flag) != 0) {
                    goto cleanup_comms;
                }

                continue;
            }

            if (baseline_not_ready_logged) {
                fprintf(stderr, "agent_loop_run: baseline is ready; enabling anomaly and classifier pipeline\n");
                baseline_not_ready_logged = 0;
            }

            memset(&anomaly, 0, sizeof(anomaly));
            if (anomaly_evaluate(&sample, &anomaly) != 0) {
                fprintf(stderr, "agent_loop_run: anomaly_evaluate failed\n");
                goto cleanup_comms;
            }

            memset(&classification, 0, sizeof(classification));
            if (classifier_classify(&sample, &anomaly, &classification) != 0) {
                fprintf(stderr, "agent_loop_run: classifier_classify failed\n");
                goto cleanup_comms;
            }

            if (comms_send_telemetry(&sample, &anomaly, &classification) != 0) {
                fprintf(stderr, "agent_loop_run: comms_send_telemetry failed in detect mode\n");
            }

            if (classification.verdict == VERDICT_RANSOMWARE) {
                if (comms_send_alert(&sample, &anomaly, &classification) != 0) {
                    fprintf(stderr, "agent_loop_run: comms_send_alert failed\n");
                }
            }
        }

        if (sleep_interruptible_ms(cfg->sampling_interval_ms, stop_flag) != 0) {
            goto cleanup_comms;
        }
    }

    rc = 0;

cleanup_comms:
    comms_shutdown();
cleanup_classifier:
    classifier_shutdown();
cleanup_anomaly:
    anomaly_shutdown();
cleanup_baseline:
    baseline_shutdown();
cleanup_telemetry:
    telemetry_shutdown();
    return rc;
}
