#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "baseline/baseline.h"

#define BASELINE_VERSION 1U
#define BASELINE_MIN_SAMPLES 300U

/*
 * Binary file format (little-endian):
 *   - 8 bytes magic: "AEGBL001"
 *   - uint32_t version
 *   - uint32_t endian_marker (0x01020304)
 *   - 7 metric blocks in fixed order:
 *       aes_instructions_per_sec
 *       cycles_per_sec
 *       cache_miss_rate
 *       files_modified_per_sec
 *       files_renamed_per_sec
 *       files_deleted_per_sec
 *       disk_write_bytes_per_sec
 *   - each metric block:
 *       uint64_t accepted_count
 *       double mean
 *       double m2
 *       double variance
 *       double stddev
 */
static const unsigned char k_baseline_magic[8] = {'A', 'E', 'G', 'B', 'L', '0', '0', '1'};
static const uint32_t k_endian_marker = 0x01020304U;

typedef struct metric_stat {
    uint64_t count;
    double mean;
    double m2;
    double variance;
    double stddev;
} metric_stat_t;

typedef struct baseline_state {
    int initialized;
    char db_path[PATH_MAX];
    metric_stat_t aes;
    metric_stat_t cycles;
    metric_stat_t cache_miss_rate;
    metric_stat_t files_modified;
    metric_stat_t files_renamed;
    metric_stat_t files_deleted;
    metric_stat_t disk_write;
} baseline_state_t;

static baseline_state_t g_state;
static pthread_mutex_t g_baseline_lock = PTHREAD_MUTEX_INITIALIZER;

static void clear_metrics_locked(void)
{
    memset(&g_state.aes, 0, sizeof(g_state.aes));
    memset(&g_state.cycles, 0, sizeof(g_state.cycles));
    memset(&g_state.cache_miss_rate, 0, sizeof(g_state.cache_miss_rate));
    memset(&g_state.files_modified, 0, sizeof(g_state.files_modified));
    memset(&g_state.files_renamed, 0, sizeof(g_state.files_renamed));
    memset(&g_state.files_deleted, 0, sizeof(g_state.files_deleted));
    memset(&g_state.disk_write, 0, sizeof(g_state.disk_write));
}

static int is_little_endian(void)
{
    const uint16_t probe = 0x1U;
    return (*(const uint8_t *)&probe) == 0x1U;
}

static uint32_t bswap32(uint32_t v)
{
    return ((v & 0x000000FFU) << 24) |
           ((v & 0x0000FF00U) << 8) |
           ((v & 0x00FF0000U) >> 8) |
           ((v & 0xFF000000U) >> 24);
}

static uint64_t bswap64(uint64_t v)
{
    return ((v & 0x00000000000000FFULL) << 56) |
           ((v & 0x000000000000FF00ULL) << 40) |
           ((v & 0x0000000000FF0000ULL) << 24) |
           ((v & 0x00000000FF000000ULL) << 8) |
           ((v & 0x000000FF00000000ULL) >> 8) |
           ((v & 0x0000FF0000000000ULL) >> 24) |
           ((v & 0x00FF000000000000ULL) >> 40) |
           ((v & 0xFF00000000000000ULL) >> 56);
}

static uint32_t host_to_le32(uint32_t v)
{
    return is_little_endian() ? v : bswap32(v);
}

static uint32_t le32_to_host(uint32_t v)
{
    return is_little_endian() ? v : bswap32(v);
}

static uint64_t host_to_le64(uint64_t v)
{
    return is_little_endian() ? v : bswap64(v);
}

static uint64_t le64_to_host(uint64_t v)
{
    return is_little_endian() ? v : bswap64(v);
}

static uint64_t double_to_u64(double d)
{
    uint64_t bits = 0U;
    memcpy(&bits, &d, sizeof(bits));
    return bits;
}

static double u64_to_double(uint64_t bits)
{
    double d = 0.0;
    memcpy(&d, &bits, sizeof(d));
    return d;
}

static int write_u32_le(FILE *fp, uint32_t v)
{
    uint32_t le = host_to_le32(v);
    return (fwrite(&le, sizeof(le), 1U, fp) == 1U) ? 0 : -1;
}

static int write_u64_le(FILE *fp, uint64_t v)
{
    uint64_t le = host_to_le64(v);
    return (fwrite(&le, sizeof(le), 1U, fp) == 1U) ? 0 : -1;
}

static int write_f64_le(FILE *fp, double v)
{
    return write_u64_le(fp, double_to_u64(v));
}

static int read_u32_le(FILE *fp, uint32_t *v)
{
    uint32_t le;

    if (v == NULL) {
        return -1;
    }

    if (fread(&le, sizeof(le), 1U, fp) != 1U) {
        return -1;
    }

    *v = le32_to_host(le);
    return 0;
}

static int read_u64_le(FILE *fp, uint64_t *v)
{
    uint64_t le;

    if (v == NULL) {
        return -1;
    }

    if (fread(&le, sizeof(le), 1U, fp) != 1U) {
        return -1;
    }

    *v = le64_to_host(le);
    return 0;
}

static int read_f64_le(FILE *fp, double *v)
{
    uint64_t bits;

    if (v == NULL) {
        return -1;
    }

    if (read_u64_le(fp, &bits) != 0) {
        return -1;
    }

    *v = u64_to_double(bits);
    return 0;
}

static int write_metric(FILE *fp, const metric_stat_t *m)
{
    if (fp == NULL || m == NULL) {
        return -1;
    }

    if (write_u64_le(fp, m->count) != 0 ||
        write_f64_le(fp, m->mean) != 0 ||
        write_f64_le(fp, m->m2) != 0 ||
        write_f64_le(fp, m->variance) != 0 ||
        write_f64_le(fp, m->stddev) != 0) {
        return -1;
    }

    return 0;
}

static int read_metric(FILE *fp, metric_stat_t *m)
{
    if (fp == NULL || m == NULL) {
        return -1;
    }

    if (read_u64_le(fp, &m->count) != 0 ||
        read_f64_le(fp, &m->mean) != 0 ||
        read_f64_le(fp, &m->m2) != 0 ||
        read_f64_le(fp, &m->variance) != 0 ||
        read_f64_le(fp, &m->stddev) != 0) {
        return -1;
    }

    return 0;
}

static void welford_update(metric_stat_t *m, double value)
{
    double count_d;
    double delta;
    double delta2;

    if (m == NULL) {
        return;
    }

    m->count += 1U;
    count_d = (double)m->count;
    delta = value - m->mean;
    m->mean += delta / count_d;
    delta2 = value - m->mean;
    m->m2 += delta * delta2;

    if (m->count > 1U) {
        m->variance = m->m2 / (double)(m->count - 1U);
        m->stddev = sqrt(m->variance);
    } else {
        m->variance = 0.0;
        m->stddev = 0.0;
    }
}

static int build_tmp_path(const char *path, char *tmp_path, size_t tmp_path_len)
{
    int n;

    if (path == NULL || tmp_path == NULL || tmp_path_len == 0U) {
        return -1;
    }

    n = snprintf(tmp_path, tmp_path_len, "%s.tmp", path);
    if (n < 0 || (size_t)n >= tmp_path_len) {
        return -1;
    }

    return 0;
}

static int baseline_save_locked(void)
{
    FILE *fp = NULL;
    char tmp_path[PATH_MAX];
    int fd;
    int rc = -1;

    if (!g_state.initialized || g_state.db_path[0] == '\0') {
        fprintf(stderr, "baseline_save: baseline not initialized\n");
        return -1;
    }

    if (build_tmp_path(g_state.db_path, tmp_path, sizeof(tmp_path)) != 0) {
        fprintf(stderr, "baseline_save: tmp path too long\n");
        return -1;
    }

    fp = fopen(tmp_path, "wb");
    if (fp == NULL) {
        fprintf(stderr, "baseline_save: fopen(%s) failed: %s\n", tmp_path, strerror(errno));
        return -1;
    }

    if (fwrite(k_baseline_magic, sizeof(k_baseline_magic), 1U, fp) != 1U ||
        write_u32_le(fp, BASELINE_VERSION) != 0 ||
        write_u32_le(fp, k_endian_marker) != 0 ||
        write_metric(fp, &g_state.aes) != 0 ||
        write_metric(fp, &g_state.cycles) != 0 ||
        write_metric(fp, &g_state.cache_miss_rate) != 0 ||
        write_metric(fp, &g_state.files_modified) != 0 ||
        write_metric(fp, &g_state.files_renamed) != 0 ||
        write_metric(fp, &g_state.files_deleted) != 0 ||
        write_metric(fp, &g_state.disk_write) != 0) {
        fprintf(stderr, "baseline_save: write failed for %s\n", tmp_path);
        goto out;
    }

    if (fflush(fp) != 0) {
        fprintf(stderr, "baseline_save: fflush(%s) failed: %s\n", tmp_path, strerror(errno));
        goto out;
    }

    fd = fileno(fp);
    if (fd >= 0 && fsync(fd) != 0) {
        fprintf(stderr, "baseline_save: fsync(%s) failed: %s\n", tmp_path, strerror(errno));
        goto out;
    }

    if (fclose(fp) != 0) {
        fp = NULL;
        fprintf(stderr, "baseline_save: fclose(%s) failed: %s\n", tmp_path, strerror(errno));
        goto out;
    }
    fp = NULL;

    if (rename(tmp_path, g_state.db_path) != 0) {
        fprintf(stderr,
                "baseline_save: rename(%s -> %s) failed: %s\n",
                tmp_path,
                g_state.db_path,
                strerror(errno));
        (void)unlink(tmp_path);
        return -1;
    }

    rc = 0;

out:
    if (fp != NULL) {
        (void)fclose(fp);
        (void)unlink(tmp_path);
    }
    return rc;
}

static int baseline_load_locked(void)
{
    FILE *fp;
    unsigned char magic[sizeof(k_baseline_magic)];
    uint32_t version = 0U;
    uint32_t endian_marker = 0U;

    if (!g_state.initialized || g_state.db_path[0] == '\0') {
        fprintf(stderr, "baseline_load: baseline not initialized\n");
        return -1;
    }

    fp = fopen(g_state.db_path, "rb");
    if (fp == NULL) {
        if (errno == ENOENT) {
            return 0;
        }
        fprintf(stderr, "baseline_load: fopen(%s) failed: %s\n", g_state.db_path, strerror(errno));
        return -1;
    }

    if (fread(magic, sizeof(magic), 1U, fp) != 1U) {
        fprintf(stderr, "baseline_load: short read on magic\n");
        (void)fclose(fp);
        return -1;
    }

    if (memcmp(magic, k_baseline_magic, sizeof(k_baseline_magic)) != 0) {
        fprintf(stderr, "baseline_load: invalid magic in %s\n", g_state.db_path);
        (void)fclose(fp);
        return -1;
    }

    if (read_u32_le(fp, &version) != 0 || read_u32_le(fp, &endian_marker) != 0) {
        fprintf(stderr, "baseline_load: failed to read header in %s\n", g_state.db_path);
        (void)fclose(fp);
        return -1;
    }

    if (version != BASELINE_VERSION) {
        fprintf(stderr, "baseline_load: unsupported version %u\n", version);
        (void)fclose(fp);
        return -1;
    }

    if (endian_marker != k_endian_marker) {
        fprintf(stderr, "baseline_load: invalid endian marker in %s\n", g_state.db_path);
        (void)fclose(fp);
        return -1;
    }

    if (read_metric(fp, &g_state.aes) != 0 ||
        read_metric(fp, &g_state.cycles) != 0 ||
        read_metric(fp, &g_state.cache_miss_rate) != 0 ||
        read_metric(fp, &g_state.files_modified) != 0 ||
        read_metric(fp, &g_state.files_renamed) != 0 ||
        read_metric(fp, &g_state.files_deleted) != 0 ||
        read_metric(fp, &g_state.disk_write) != 0) {
        fprintf(stderr, "baseline_load: failed to read metric data from %s\n", g_state.db_path);
        (void)fclose(fp);
        return -1;
    }

    if (fclose(fp) != 0) {
        fprintf(stderr, "baseline_load: fclose(%s) failed: %s\n", g_state.db_path, strerror(errno));
        return -1;
    }

    return 0;
}

int baseline_init(const char *db_path)
{
    int rc;

    if (db_path == NULL || db_path[0] == '\0') {
        fprintf(stderr, "baseline_init: invalid db_path\n");
        return -1;
    }

    if (strlen(db_path) >= sizeof(g_state.db_path)) {
        fprintf(stderr, "baseline_init: db_path too long\n");
        return -1;
    }

    if (pthread_mutex_lock(&g_baseline_lock) != 0) {
        fprintf(stderr, "baseline_init: mutex lock failed\n");
        return -1;
    }

    memset(&g_state, 0, sizeof(g_state));
    (void)snprintf(g_state.db_path, sizeof(g_state.db_path), "%s", db_path);
    g_state.initialized = 1;
    clear_metrics_locked();

    rc = baseline_load_locked();
    if (rc != 0) {
        memset(&g_state, 0, sizeof(g_state));
    }

    if (pthread_mutex_unlock(&g_baseline_lock) != 0) {
        fprintf(stderr, "baseline_init: mutex unlock failed\n");
        return -1;
    }

    return rc;
}

int baseline_update(const telemetry_sample_t *sample)
{
    if (sample == NULL) {
        fprintf(stderr, "baseline_update: sample is NULL\n");
        return -1;
    }

    if (pthread_mutex_lock(&g_baseline_lock) != 0) {
        fprintf(stderr, "baseline_update: mutex lock failed\n");
        return -1;
    }

    if (!g_state.initialized) {
        fprintf(stderr, "baseline_update: baseline not initialized\n");
        (void)pthread_mutex_unlock(&g_baseline_lock);
        return -1;
    }

    if (sample->aes_instructions_per_sec != -1.0 && isfinite(sample->aes_instructions_per_sec)) {
        welford_update(&g_state.aes, sample->aes_instructions_per_sec);
    }
    if (isfinite(sample->cycles_per_sec)) {
        welford_update(&g_state.cycles, sample->cycles_per_sec);
    }
    if (isfinite(sample->cache_miss_rate)) {
        welford_update(&g_state.cache_miss_rate, sample->cache_miss_rate);
    }
    if (isfinite(sample->files_modified_per_sec)) {
        welford_update(&g_state.files_modified, sample->files_modified_per_sec);
    }
    if (isfinite(sample->files_renamed_per_sec)) {
        welford_update(&g_state.files_renamed, sample->files_renamed_per_sec);
    }
    if (isfinite(sample->files_deleted_per_sec)) {
        welford_update(&g_state.files_deleted, sample->files_deleted_per_sec);
    }
    if (isfinite(sample->disk_write_bytes_per_sec)) {
        welford_update(&g_state.disk_write, sample->disk_write_bytes_per_sec);
    }

    if (pthread_mutex_unlock(&g_baseline_lock) != 0) {
        fprintf(stderr, "baseline_update: mutex unlock failed\n");
        return -1;
    }

    return 0;
}

int baseline_ready(void)
{
    int ready = 0;

    if (pthread_mutex_lock(&g_baseline_lock) != 0) {
        fprintf(stderr, "baseline_ready: mutex lock failed\n");
        return 0;
    }

    if (g_state.initialized &&
        g_state.aes.count >= BASELINE_MIN_SAMPLES &&
        g_state.cycles.count >= BASELINE_MIN_SAMPLES &&
        g_state.cache_miss_rate.count >= BASELINE_MIN_SAMPLES &&
        g_state.files_modified.count >= BASELINE_MIN_SAMPLES &&
        g_state.files_renamed.count >= BASELINE_MIN_SAMPLES &&
        g_state.files_deleted.count >= BASELINE_MIN_SAMPLES &&
        g_state.disk_write.count >= BASELINE_MIN_SAMPLES) {
        ready = 1;
    }

    if (pthread_mutex_unlock(&g_baseline_lock) != 0) {
        fprintf(stderr, "baseline_ready: mutex unlock failed\n");
        return 0;
    }

    return ready;
}

int baseline_save(void)
{
    int rc;

    if (pthread_mutex_lock(&g_baseline_lock) != 0) {
        fprintf(stderr, "baseline_save: mutex lock failed\n");
        return -1;
    }

    rc = baseline_save_locked();

    if (pthread_mutex_unlock(&g_baseline_lock) != 0) {
        fprintf(stderr, "baseline_save: mutex unlock failed\n");
        return -1;
    }

    return rc;
}

int baseline_load(void)
{
    int rc;

    if (pthread_mutex_lock(&g_baseline_lock) != 0) {
        fprintf(stderr, "baseline_load: mutex lock failed\n");
        return -1;
    }

    clear_metrics_locked();
    rc = baseline_load_locked();

    if (pthread_mutex_unlock(&g_baseline_lock) != 0) {
        fprintf(stderr, "baseline_load: mutex unlock failed\n");
        return -1;
    }

    return rc;
}

void baseline_shutdown(void)
{
    if (pthread_mutex_lock(&g_baseline_lock) != 0) {
        fprintf(stderr, "baseline_shutdown: mutex lock failed\n");
        return;
    }

    if (g_state.initialized && baseline_save_locked() != 0) {
        fprintf(stderr, "baseline_shutdown: failed to save baseline\n");
    }

    memset(&g_state, 0, sizeof(g_state));

    if (pthread_mutex_unlock(&g_baseline_lock) != 0) {
        fprintf(stderr, "baseline_shutdown: mutex unlock failed\n");
    }
}
