#include <errno.h>
#include <inttypes.h>
#include <string.h>

#include "comms/comms.h"

static const char *verdict_to_string(verdict_kind_t verdict)
{
    if (verdict == VERDICT_RANSOMWARE) {
        return "RANSOMWARE";
    }
    if (verdict == VERDICT_SUSPICIOUS) {
        return "SUSPICIOUS";
    }
    return "SAFE";
}

static int write_json_escaped_string(FILE *stream, const char *s)
{
    const unsigned char *p;

    if (stream == NULL || s == NULL) {
        return -1;
    }

    if (fputc('\"', stream) == EOF) {
        return -1;
    }

    p = (const unsigned char *)s;
    while (*p != '\0') {
        unsigned char c = *p++;
        int rc;

        if (c == '\"' || c == '\\') {
            rc = fprintf(stream, "\\%c", c);
        } else if (c == '\b') {
            rc = fputs("\\b", stream);
        } else if (c == '\f') {
            rc = fputs("\\f", stream);
        } else if (c == '\n') {
            rc = fputs("\\n", stream);
        } else if (c == '\r') {
            rc = fputs("\\r", stream);
        } else if (c == '\t') {
            rc = fputs("\\t", stream);
        } else if (c < 0x20U) {
            rc = fprintf(stream, "\\u%04x", (unsigned int)c);
        } else {
            rc = fputc((int)c, stream);
        }

        if (rc == EOF || rc < 0) {
            return -1;
        }
    }

    return (fputc('\"', stream) == EOF) ? -1 : 0;
}

int comms_send_telemetry(const telemetry_sample_t *sample,
                         const anomaly_result_t *anomaly,
                         const classifier_result_t *result)
{
    FILE *stream;
    char top_comm_safe[65];

    if (sample == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (comms_internal_get_stream(&stream) != 0) {
        return -1;
    }

    memcpy(top_comm_safe, sample->top_comm, sizeof(sample->top_comm));
    top_comm_safe[sizeof(top_comm_safe) - 1U] = '\0';

    if (fprintf(stream,
                "{\"type\":\"telemetry\","
                "\"timestamp_ns\":%" PRIu64 ","
                "\"cycles_per_sec\":%.6f,"
                "\"cache_miss_rate\":%.6f,"
                "\"files_modified_per_sec\":%.6f,"
                "\"disk_write_bytes_per_sec\":%.6f,"
                "\"top_pid\":%ld,"
                "\"top_comm\":",
                sample->timestamp_ns,
                sample->cycles_per_sec,
                sample->cache_miss_rate,
                sample->files_modified_per_sec,
                sample->disk_write_bytes_per_sec,
                (long)sample->top_pid) < 0) {
        return -1;
    }

    if (write_json_escaped_string(stream, top_comm_safe) != 0) {
        return -1;
    }

    if (anomaly != NULL) {
        if (fprintf(stream,
                    ",\"anomaly_score\":%.6f,"
                    "\"z_score\":%.6f,"
                    "\"flags\":%u",
                    anomaly->anomaly_score,
                    anomaly->z_score,
                    anomaly->flags) < 0) {
            return -1;
        }
    }

    if (result != NULL) {
        if (fprintf(stream,
                    ",\"verdict\":\"%s\","
                    "\"confidence\":%.6f,"
                    "\"ransomware_score\":%.6f",
                    verdict_to_string(result->verdict),
                    result->confidence,
                    result->ransomware_score) < 0) {
            return -1;
        }
    }

    if (fputs("}\n", stream) == EOF) {
        return -1;
    }

    if (fflush(stream) != 0) {
        return -1;
    }

    return 0;
}

int comms_send_alert(const telemetry_sample_t *sample,
                     const anomaly_result_t *anomaly,
                     const classifier_result_t *result)
{
    FILE *stream;
    uint32_t flags = 0U;

    if (result == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (result->verdict != VERDICT_RANSOMWARE) {
        return 0;
    }

    if (anomaly != NULL) {
        flags = anomaly->flags;
    }

    if (comms_internal_get_stream(&stream) != 0) {
        return -1;
    }

    if (sample != NULL) {
        if (fprintf(stream,
                    "{\"type\":\"alert\","
                    "\"timestamp_ns\":%" PRIu64 ","
                    "\"ransomware_score\":%.6f,"
                    "\"flags\":%u,"
                    "\"confidence\":%.6f}\n",
                    sample->timestamp_ns,
                    result->ransomware_score,
                    flags,
                    result->confidence) < 0) {
            return -1;
        }
    } else {
        if (fprintf(stream,
                    "{\"type\":\"alert\","
                    "\"ransomware_score\":%.6f,"
                    "\"flags\":%u,"
                    "\"confidence\":%.6f}\n",
                    result->ransomware_score,
                    flags,
                    result->confidence) < 0) {
            return -1;
        }
    }

    if (fflush(stream) != 0) {
        return -1;
    }

    return 0;
}
