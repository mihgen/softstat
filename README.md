## Report file descriptors usage information

#### Example usage
Make sure you run this utility under root (it needs access to /proc).

```bash
# Build binary
go build softstat.go

# Alternatively, download already compiled version
wget https://github.com/mihgen/softstat/releases/download/0.2/softstat
chmod +x softstat

# Show 10 mostly loaded processes
./softstat

# Show 1000 mostly loaded processes
./softstat -n 1000

# Show all
./softstat -n -1
```

#### How it works
This utility will go over all processes in /proc, get their cmd name from /proc/\<pid\>/status, and count number of open file descriptors from /proc/\<pid\>/fd/. prlimit64() system call is used to get limits set for the process, and SoftLimit value is used in calculations.

Use *prlimit* Linux utility if you need to get or change limits of running process. Alternatively, /proc/\<pid\>/limits can be used to get current limits.

There are a few ceilings process count can hit. Currently, only these two are used:
1. **/proc/sys/kernel/threads-max** is maximum task count (processes and threads) you may have in a system
2. **/proc/\<pid\>/limits**, Max processes, Soft Limit. (Hard limit is not in use by kernel and ignored). This value is checked when this given PID tries to create a new process (or thread). However, this limit is NOT how much threads or children given PID can have; this limit is total number of processes ran under real UID which PID rans under. For example, there are 10 processes running under user "buddy". One of process is apache2, and we set a limit for this process to 10 using *prlimit*. After that, no new forks could be created by apache2, as we are pressed by a limit for this process. At the same time, any other process running with the same UID can create new processes or threads.

In the output of *softstat*, only one set of processes count / limit / % is given, the one with higher usage.

#### Limitations
Note, that currently *softstat* only works on x86_64 Linux.
Limits related to processes count are not yet calculated:
* cgroups
* pid_max - to check if we don't exhaust PID namespace
