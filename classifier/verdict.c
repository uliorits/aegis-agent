#include <errno.h>
#include <string.h>

#include "classifier/classifier.h"

static int g_classifier_initialized = 0;

verdict_kind_t classifier_score_to_verdict(double score)
{
    if (score >= 0.85) {
        return VERDICT_RANSOMWARE;
    }
    if (score >= 0.55) {
        return VERDICT_SUSPICIOUS;
    }
    return VERDICT_SAFE;
}

int classifier_init(void)
{
    g_classifier_initialized = 1;
    return 0;
}

int classifier_classify(const telemetry_sample_t *sample,
                        const anomaly_result_t *anomaly,
                        classifier_result_t *out)
{
    double score;

    (void)sample;

    if (!g_classifier_initialized || anomaly == NULL || out == NULL) {
        errno = EINVAL;
        return -1;
    }

    memset(out, 0, sizeof(*out));

    score = classifier_compute_ransomware_score(anomaly);
    out->ransomware_score = score;
    out->confidence = score;
    out->verdict = classifier_score_to_verdict(score);

    return 0;
}

void classifier_shutdown(void)
{
    g_classifier_initialized = 0;
}
