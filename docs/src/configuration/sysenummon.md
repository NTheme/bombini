# SysEnumMon

Detector correlates system enumeration (reconnaissance) activity. Automated privilege
escalation scanners (PEASS-ng: LinPEAS, LinEnum, pspy and similar) perform many small
enumeration steps in a short time: they execute information gathering binaries (`id`,
`whoami`, `uname`, `netstat` and so on) and read sensitive files (`/etc/shadow`,
`/etc/ssh/*` and so on). A single step is legitimate on its own, so an alert is raised only
when several distinct observations from the watch list accumulate inside one process tree
within a sliding time window.
Supported LSM hooks:

* `bprm_check_security` hook observes executed binary names on `execve`.
* `file_open` hook observes opened file paths.

Both hooks are always loaded, there is no per-hook enable switch. SysEnumMon depends on
ProcMon: the parent process reported by the alert is restored from the shared
`PROCMON_PROC_MAP` and the user space Process cache. The same map is used to garbage-collect
correlation state — once the parent has exited or left the cache, its accumulated chain is
dropped.

## Required Linux Kernel Version

6.2 or greater

## Config Description

SysEnumMon does not provide rule-based filtering or sandbox mode. It is configured by a
watch list and two correlation parameters:

* `chain_size` - threshold `K`: number of distinct observations from the watch list that must occur within the window to raise an alert.
* `window_size_sec` - sliding window length `W` in seconds. The window starts with the first observation; if the next observation arrives later than `W` seconds after the first one, the correlation state of the process tree is reset.
* `bprm_check.name` - list of binary names matched on `execve`.
* `file_open.path` - list of exact file paths matched on `file_open`.
* `file_open.path_prefix` - list of path prefixes matched on `file_open` (longest prefix match).

Observations are de-duplicated, so repeating the same entry does not advance the counter:
a script that calls `id` in a loop does not raise an alert. The total number of unique watch
list entries (names + paths + prefixes) must not exceed 256.

**Example**

```yaml
chain_size: 3
window_size_sec: 10
bprm_check:
  name:
    - id
    - whoami
    - uname
    - netstat
    - ss
    - getcap
file_open:
  path:
    - /etc/shadow
  path_prefix:
    - /etc/ssh
```
