# Designing a File System Monitoring Solution using EBPF

The initial plan was to use tracepoints on functions such as `open`, `read` and
`write`. But most of these functions except open get only a file
descriptor. This means, to do anything useful with it, I'd have to add a
tracepoint to the open call/return, and find out the returned file descriptor
, resolve the path of the actual file(as paths to `open`  can be relative), 
and send all this information to the userspace program.

The userspace program would have to then maintain a file descriptor table for
every process that opens a file in the monitored path.

This approach wasn't ideal as maintaining a file descriptor table during a
situation a high number of of read/write events would be inefficient.

An alternative to the file descriptor table in userspace would be to use the
current task (fetched with bpf_get_current_task) , find the actual file
structure in the process's file descriptor table, fetch the dentry and then
resolve the path  untill it hits a root. I tested this approach out but the
ebpf verifier did not like me looping like that. It would have also had a
non-negligible performance const, traversing the dentry tree in an ebpf context
like that.

I also considered sending the file descriptors to the userspace program and then
procfs(`/proc/$PID/fd/`) to resolve file descriptors to paths but that didn't
sound like a solid idea since there is no guarantee that the file descriptor will exist
by the time the event arrives on the userland program.

Then, I found out about `bpf_d_path` which is exactly what I needed.
However, there's a catch. The function only works in certain situations.

The rules are:
-  Tracepoints are not allowed unless they're iterators. 
-  LSM hooks are allowed as long as they're sleepable. [Link to sleepable set](https://github.com/torvalds/linux/blob/595523945be0a5a2f12a1c04772383293fbc04a1/kernel/bpf/bpf_lsm.c#L283-L394)
-  Otherwise only fentry hooks related these functions were allowed.
```
security_file_permission
security_inode_getattr
security_file_open
security_path_truncate
vfs_truncate
vfs_fallocate
dentry_open
vfs_getattr
filp_close
```

So I decided to use a combination of `security_file_permission` and various LSM hooks to monitor the events.
Most of the lsm hooks have access to either a `*file` or a `*path` which can be used with `bpf_d_path`

Most of the other data required for the monitor events were attached to the
context argument so that was trivial to retrieve.

For timestamps, I used `bpf_ktime_get_boot_ns` which returns the number of
nanoseconds it has been since the system booted while including the suspsended
time.

## Filtering
Since the hooks I was using to monitor the events fire every time a relevant
event happens throughout the entire system, I made the decision to provide the
path that the agent is filtering to within a map to the ebpf program do the
filering within the ebpf program itself. This saves a lot of unncessary work.


## Database Choice

For the database, I chose PostgreSQL because of its scalability when it comes to
handling large datasets, its support for advanced indexing and query
optimization, and its ability to scale both vertically and horizontally through
features like partitioning and extensions like Citus for distributed workloads.
