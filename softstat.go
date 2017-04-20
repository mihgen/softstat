// Copyright 2017 Mike Scherbakov
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"unsafe"
)

type Limits struct {
	openFiles syscall.Rlimit
	stackSize syscall.Rlimit
}

type OutputEntry struct {
	pid          string
	cmd          string
	fds          uint64
	fdsLimit     uint64
	fdsPercent   float32
	stack        uint64
	stackLimit   uint64
	stackPercent float32
}

func Prlimit(pid int, resource int, new_rlim *syscall.Rlimit, old_rlim *syscall.Rlimit) (err error) {
	// 302 is SYS_PRLIMIT64 system call. It is not exposed in Go as part of syscall, that's why we do it here.
	// Note, that this code only works on Linux x86_64
	// See details at https://groups.google.com/forum/#!topic/golang-dev/UNEHXy06O7Y
	_, _, e1 := syscall.RawSyscall6(302, uintptr(pid), uintptr(resource), uintptr(unsafe.Pointer(new_rlim)), uintptr(unsafe.Pointer(old_rlim)), 0, 0)
	if e1 != 0 {
		err = e1
	}
	return
}

type ByFdsPercent []OutputEntry

func (p ByFdsPercent) Len() int           { return len(p) }
func (p ByFdsPercent) Less(i, j int) bool { return p[i].fdsPercent < p[j].fdsPercent }
func (p ByFdsPercent) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

func GetLimits(pid string) Limits {
	var mylimit Limits
	var rlim syscall.Rlimit
	pidNu, _ := strconv.Atoi(pid)

	err := Prlimit(pidNu, syscall.RLIMIT_NOFILE, nil, &rlim)
	if err != nil {
		panic(err)
	}

	mylimit.openFiles = rlim

	err = Prlimit(pidNu, syscall.RLIMIT_STACK, nil, &rlim)
	if err != nil {
		panic(err)
	}
	mylimit.stackSize = rlim
	return mylimit
}

func GetFdOpen(pid string) uint64 {
	dir, err := os.Open(filepath.Join("/proc", pid, "fd"))
	if err != nil {
		panic(err)
	}
	defer dir.Close()
	fds, err := dir.Readdirnames(-1)
	if err != nil {
		panic(err)
	}
	return uint64(len(fds))
}

func GetStackSize(pid string) uint64 {
	return 0
}

func CmdName(pid string) string {
	statusFile, err := os.Open(filepath.Join("/proc/", pid, "/status"))
	if err != nil {
		panic(err)
	}
	defer statusFile.Close()
	stScan := bufio.NewScanner(statusFile)
	stScan.Scan()
	parsed := strings.Fields(stScan.Text())
	if len(parsed) != 2 {
		panic("Can't parse cmdname for pid=" + pid)
	}

	return parsed[1]
}

func main() {
	nLines := flag.Int("n", 10, "Output n most loaded processes")
	flag.Parse()
	procs, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		panic(err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintln(w, "PID\tFD\tFD-max\tFD%\tCMD\t")

	entries := []OutputEntry{}

	for _, p := range procs {
		stat, err := os.Stat(p)
		if err != nil {
			panic(err)
		}
		pid := stat.Name()
		if stat.IsDir() {
			limits := GetLimits(pid)
			open := GetFdOpen(pid)
			stack := GetStackSize(pid)
			entries = append(entries, OutputEntry{
				pid:          pid,
				cmd:          CmdName(pid),
				fds:          open,
				fdsLimit:     limits.openFiles.Cur,
				fdsPercent:   float32(open) / float32(limits.openFiles.Cur),
				stack:        stack,
				stackLimit:   limits.stackSize.Cur,
				stackPercent: float32(stack) / float32(limits.stackSize.Cur),
			})
		}
	}
	sort.Sort(sort.Reverse(ByFdsPercent(entries)))

	for i := 0; i < *nLines && i < len(entries); i++ {
		e := entries[i]
		fmt.Fprintf(w, "%s\t%d\t%d\t%2.2f\t%s\t\n", e.pid, e.fds, e.fdsLimit, e.fdsPercent, e.cmd)
	}
	if err = w.Flush(); err != nil {
		panic(err)
	}

}
