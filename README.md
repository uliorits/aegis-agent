
# Aegis Agent

Aegis Agent is a **Linux endpoint telemetry and anomaly detection prototype** written in C.
It collects low-level system signals (CPU, filesystem, process, and I/O activity), builds a statistical baseline, detects anomalies using z-scores, and classifies suspicious behavior such as ransomware-like activity.
Telemetry and alerts are currently emitted as JSON to stdout (MVP transport).

This project is designed as a **learning / research EDR-style agent**, not a production security product.

---

## Features

* **Core agent loop**

  * Config loading
  * Graceful shutdown (SIGINT, SIGTERM)
  * Baseline and detect modes

* **Telemetry**

  * CPU performance counters (cycles, instructions, cache misses) via `perf_event_open`
  * Filesystem activity rates (modified/renamed/deleted)
  * Top active process
  * Disk I/O rates
  * Time-normalized metrics

* **Baseline**

  * Online mean and standard deviation using Welford’s algorithm
  * Persistent binary profile (`baseline/profile.db`)
  * Ready after a minimum number of samples (default: 300)

* **Anomaly Detection**

  * Z-score based deviation from learned behavior
  * Produces:

    * `anomaly_score` (0..1)
    * `z_score`
    * Flags: crypto spike, write storm, rename storm, delete storm
  * Includes hard fallback thresholds if baseline is not reliable

* **Classifier**

  * Combines anomaly score and flags into a ransomware likelihood score
  * Outputs verdict:

    * SAFE
    * SUSPICIOUS
    * RANSOMWARE

* **Comms (MVP)**

  * Emits JSON lines to stdout:

    * Telemetry events
    * Alert events when ransomware is detected

---

## Project Structure

```
aegis-agent/
├── core/        # Main loop, config, shared types
├── telemetry/   # CPU, FS, process, I/O collectors
├── baseline/    # Statistical baseline + persistence
├── anomaly/     # Z-score anomaly detection + models
├── classifier/  # Ransomware scoring + verdict logic
├── comms/       # JSON output (stdout transport)
└── Makefile
```

---

## Build Requirements

* Linux (tested on Ubuntu/Kali)
* gcc or clang
* make
* pthreads
* Linux perf events (for CPU telemetry)

Install basics:

```bash
sudo apt update
sudo apt install -y build-essential git
```

---

## Build

From the project root:

```bash
make clean
make
```

This produces:

```bash
./aegis-agent
```

---

## Configuration

Create a config file, for example `aegis-agent.conf`:

```ini
sampling_interval_ms = 1000
telemetry_root_path = /
cloud_endpoint_url = stdout
baseline_db_path = baseline/profile.db
mode = baseline
```

Fields:

* `sampling_interval_ms` – How often to collect telemetry
* `telemetry_root_path` – Root path for filesystem monitoring
* `cloud_endpoint_url` – Currently ignored (stdout JSON output)
* `baseline_db_path` – Where baseline profile is saved/loaded
* `mode` – `baseline` or `detect`

---

## Running

### Baseline Mode (learning normal behavior)

```bash
./aegis-agent aegis-agent.conf
```

Set in config:

```ini
mode = baseline
```

Let it run for a while (until at least ~300 samples are collected).
On shutdown, the baseline is saved to `baseline/profile.db`.

---

### Detect Mode (anomaly + classification)

Change config:

```ini
mode = detect
```

Then run:

```bash
./aegis-agent aegis-agent.conf
```

The agent will:

* Load the baseline
* Continue updating it if needed
* Emit telemetry JSON
* Emit alert JSON when ransomware-like behavior is detected

---

## Output Format (MVP)

Telemetry example (JSON line):

```json
{
  "type":"telemetry",
  "timestamp_ns":123456789,
  "cycles_per_sec":12345.6,
  "cache_miss_rate":0.0123,
  "files_modified_per_sec":42.0,
  "disk_write_bytes_per_sec":1048576.0,
  "top_pid":1234,
  "top_comm":"openssl",
  "anomaly_score":0.82,
  "z_score":3.4,
  "flags":5,
  "verdict":"SUSPICIOUS",
  "confidence":0.82,
  "ransomware_score":0.78
}
```

Alert example:

```json
{
  "type":"alert",
  "timestamp_ns":123456789,
  "ransomware_score":0.92,
  "flags":7,
  "confidence":0.92
}
```

---

## Testing Environment

* Recommended: Ubuntu or Kali Linux VM
* Run as normal user first
* Some CPU perf counters may require elevated permissions depending on kernel settings

---

## Limitations

* Not a real EDR, research/prototype only
* Filesystem and process monitoring are simplified
* Transport is stdout only (no real cloud backend yet)
* No active response (no process killing, isolation, etc.)


---

## Disclaimer

This project is for **educational and research purposes only**.
Do not deploy it as a security product in production environments.

