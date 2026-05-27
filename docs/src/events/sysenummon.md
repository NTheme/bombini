# SysEnumMon

## SysEnumMonEvent

SysEnumMonEvent represents detected system enumeration activity: at least `chain_size`
distinct observations from the watch list were correlated inside one process tree within
the `window_size_sec` window.

The event is a `chain` of observations. Each chain entry carries the `entry` that performed
it and a `timestamp`. The `entry` is tagged by `type`: `Exec` (from `bprm_check_security`,
with the observed `binary`) or `FileOpen` (from `file_open`, with the observed `path`); in
both cases `process` is the snapshot of the process that performed the observation (restored
from the ProcMon Process cache). Correlation is keyed on the parent PID, so all entries of one
chain share the same parent process tree (visible via each `process.ppid`).

```json
{
  "type": "SysEnumMonEvent",
  "chain": [
    {
      "entry": {
        "type": "Exec",
        "process": {
          "start_time": "2026-05-28T02:10:01.234Z",
          "pid": 191100, "tid": 191100, "ppid": 191096,
          "uid": 1000, "euid": 1000, "gid": 1000, "egid": 1000, "auid": 1000,
          "cap_inheritable": "", "cap_permitted": "", "cap_effective": "",
          "secureexec": "", "filename": "id", "binary_path": "/usr/bin/id",
          "args": "", "exec_id": "MTkxMTAw...", "parent_exec_id": "MTkxMDk2..."
        },
        "binary": "id"
      },
      "timestamp": "2026-05-28T02:10:01.234Z"
    },
    {
      "entry": {
        "type": "FileOpen",
        "process": {
          "start_time": "2026-05-28T02:10:01.780Z",
          "pid": 191102, "tid": 191102, "ppid": 191096,
          "uid": 1000, "euid": 1000, "gid": 1000, "egid": 1000, "auid": 1000,
          "cap_inheritable": "", "cap_permitted": "", "cap_effective": "",
          "secureexec": "", "filename": "cat", "binary_path": "/usr/bin/cat",
          "args": "/etc/shadow", "exec_id": "MTkxMTAy...", "parent_exec_id": "MTkxMDk2..."
        },
        "path": "/etc/shadow"
      },
      "timestamp": "2026-05-28T02:10:01.789Z"
    }
  ],
  "timestamp": "2026-05-28T02:10:01.789Z"
}
```
