# SysEnumMon

## SysEnumMonEvent

SysEnumMonEvent represents detected system enumeration activity: at least `chain_size`
distinct observations from the watch list were correlated inside one process tree within
the `window_size_sec` window.

Correlation is keyed on the parent PID, so the whole chain belongs to a single parent
process tree. That parent is reported once as the top-level `process` (restored from the
ProcMon Process cache); the new task being `execve`'d is not yet fully populated at
`bprm_check_security` time, which is why the parent key is used. The event then carries a
`chain` of observations, each with its `entry` and a `timestamp`. The `entry` is tagged by
`type`: `Exec` (from `bprm_check_security`, with the observed `binary`) or `FileOpen` (from
`file_open`, with the observed `path`).

```json
{
  "type": "SysEnumMonEvent",
  "process": {
    "start_time": "2026-05-28T02:10:01.200Z",
    "pid": 191096, "tid": 191096, "ppid": 191000,
    "uid": 1000, "euid": 1000, "gid": 1000, "egid": 1000, "auid": 1000,
    "cap_inheritable": "", "cap_permitted": "", "cap_effective": "",
    "secureexec": "", "filename": "linpeas.sh", "binary_path": "/usr/bin/bash",
    "args": "./linpeas.sh", "exec_id": "MTkxMDk2...", "parent_exec_id": "MTkxMDAw..."
  },
  "chain": [
    {
      "entry": { "type": "Exec", "binary": "id" },
      "timestamp": "2026-05-28T02:10:01.234Z"
    },
    {
      "entry": { "type": "Exec", "binary": "uname" },
      "timestamp": "2026-05-28T02:10:01.560Z"
    },
    {
      "entry": { "type": "FileOpen", "path": "/etc/shadow" },
      "timestamp": "2026-05-28T02:10:01.789Z"
    }
  ],
  "timestamp": "2026-05-28T02:10:01.789Z"
}
```
