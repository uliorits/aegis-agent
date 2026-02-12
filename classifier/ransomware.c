#include <errno.h>
#include <stddef.h>

#include "classifier/classifier.h"

static double clamp_unit(double value)
{
    if (value < 0.0) {
        return 0.0;
    }
    if (value > 1.0) {
        return 1.0;
    }
    return value;
}

double classifier_compute_ransomware_score(const anomaly_result_t *anomaly)
{
    double score;

    if (anomaly == NULL) {
        errno = EINVAL;
        return 0.0;
    }

    score = 0.5 * clamp_unit(anomaly->anomaly_score);

    if ((anomaly->flags & ANOMALY_FLAG_WRITE_STORM) != 0U) {
        score += 0.2;
    }
    if ((anomaly->flags & ANOMALY_FLAG_RENAME_STORM) != 0U) {
        score += 0.15;
    }
    if ((anomaly->flags & ANOMALY_FLAG_DELETE_STORM) != 0U) {
        score += 0.1;
    }
    if ((anomaly->flags & ANOMALY_FLAG_CRYPTO_SPIKE) != 0U) {
        score += 0.25;
    }

    return clamp_unit(score);
}
