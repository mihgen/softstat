## Report file descriptors usage information

#### Example usage
Make sure you run this utility under root (it needs access to /proc).

```bash
# Build binary
go build softstat.go

# Alternatively, download already compiled version
wget https://github.com/mihgen/softstat/releases/download/0.1/softstat
chmod +x softstat

# Show 10 mostly loaded processes
./softstat

# Show 1000 mostly loaded processes
./softstat -n 1000
```

#### How it works
This utility will go over all processes in /proc, get their cmd name from /proc/\<pid\>/status, and count number of open file descriptors from /proc/\<pid\>/fd/. prlimit64() system call is used to get limits set for the process, and SoftLimit value is used in calculations.

Use *prlimit* Linux utility if you need to get or change limits of running process. Alternatively, /proc/\<pid\>/limits can be used to get current limits.

Note, that currently *softstat* only works on x86_64 Linux.
