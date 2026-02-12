#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/core.h"

static void trim_inplace(char *s)
{
    char *start;
    char *end;

    if (s == NULL || *s == '\0') {
        return;
    }

    start = s;
    while (*start != '\0' && isspace((unsigned char)*start)) {
        start++;
    }

    if (start != s) {
        memmove(s, start, strlen(start) + 1U);
    }

    if (*s == '\0') {
        return;
    }

    end = s + strlen(s) - 1;
    while (end >= s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
}

static int parse_mode(const char *value, agent_mode_t *mode)
{
    if (value == NULL || mode == NULL) {
        return -1;
    }

    if (strcmp(value, "baseline") == 0) {
        *mode = AGENT_MODE_BASELINE;
        return 0;
    }

    if (strcmp(value, "detect") == 0) {
        *mode = AGENT_MODE_DETECT;
        return 0;
    }

    return -1;
}

static int parse_uint_ms(const char *value, unsigned int *out)
{
    char *end = NULL;
    unsigned long parsed;

    if (value == NULL || out == NULL || *value == '\0') {
        return -1;
    }

    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        return -1;
    }

    if (parsed == 0UL || parsed > 3600000UL) {
        return -1;
    }

    *out = (unsigned int)parsed;
    return 0;
}

int config_load(const char *path, agent_config_t *out_cfg)
{
    FILE *fp;
    char line[2048];
    unsigned int found_interval = 0;
    unsigned int found_root = 0;
    unsigned int found_endpoint = 0;
    unsigned int found_baseline_db = 0;
    unsigned int found_mode = 0;

    if (path == NULL || out_cfg == NULL) {
        return -1;
    }

    memset(out_cfg, 0, sizeof(*out_cfg));

    fp = fopen(path, "r");
    if (fp == NULL) {
        perror("config_load: fopen");
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *eq;
        char *key;
        char *value;

        trim_inplace(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        eq = strchr(line, '=');
        if (eq == NULL) {
            fprintf(stderr, "config_load: invalid line (missing '='): %s\n", line);
            fclose(fp);
            return -1;
        }

        *eq = '\0';
        key = line;
        value = eq + 1;
        trim_inplace(key);
        trim_inplace(value);

        if (strcmp(key, "sampling_interval_ms") == 0) {
            if (parse_uint_ms(value, &out_cfg->sampling_interval_ms) != 0) {
                fprintf(stderr, "config_load: invalid sampling_interval_ms: %s\n", value);
                fclose(fp);
                return -1;
            }
            found_interval = 1;
        } else if (strcmp(key, "telemetry_root_path") == 0) {
            if (value[0] == '\0' || strlen(value) >= sizeof(out_cfg->telemetry_root_path)) {
                fprintf(stderr, "config_load: invalid telemetry_root_path\n");
                fclose(fp);
                return -1;
            }
            (void)snprintf(out_cfg->telemetry_root_path, sizeof(out_cfg->telemetry_root_path), "%s", value);
            found_root = 1;
        } else if (strcmp(key, "cloud_endpoint_url") == 0) {
            if (value[0] == '\0' || strlen(value) >= sizeof(out_cfg->cloud_endpoint_url)) {
                fprintf(stderr, "config_load: invalid cloud_endpoint_url\n");
                fclose(fp);
                return -1;
            }
            (void)snprintf(out_cfg->cloud_endpoint_url, sizeof(out_cfg->cloud_endpoint_url), "%s", value);
            found_endpoint = 1;
        } else if (strcmp(key, "baseline_db_path") == 0) {
            if (value[0] == '\0' || strlen(value) >= sizeof(out_cfg->baseline_db_path)) {
                fprintf(stderr, "config_load: invalid baseline_db_path\n");
                fclose(fp);
                return -1;
            }
            (void)snprintf(out_cfg->baseline_db_path, sizeof(out_cfg->baseline_db_path), "%s", value);
            found_baseline_db = 1;
        } else if (strcmp(key, "mode") == 0) {
            if (parse_mode(value, &out_cfg->mode) != 0) {
                fprintf(stderr, "config_load: invalid mode: %s (expected baseline|detect)\n", value);
                fclose(fp);
                return -1;
            }
            found_mode = 1;
        } else {
            /* Unknown keys are ignored for forward compatibility. */
        }
    }

    if (ferror(fp) != 0) {
        perror("config_load: fgets");
        fclose(fp);
        return -1;
    }

    fclose(fp);

    if (!found_interval || !found_root || !found_endpoint || !found_baseline_db || !found_mode) {
        fprintf(stderr,
                "config_load: missing required key(s): sampling_interval_ms=%u telemetry_root_path=%u "
                "cloud_endpoint_url=%u baseline_db_path=%u mode=%u\n",
                found_interval,
                found_root,
                found_endpoint,
                found_baseline_db,
                found_mode);
        return -1;
    }

    return 0;
}
