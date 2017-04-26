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
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"unsafe"
)

var UserProcs map[string]uint64
var TotalThreads uint64

type Limits struct {
	openFiles syscall.Rlimit
	nProc     syscall.Rlimit
}

type OutputEntry struct {
	pid          string
	cmd          string
	fds          uint64
	fdsLimit     string
	fdsPercent   float32
	nProc        uint64
	nProcLimit   string
	nProcPercent float32
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

func max(p1, p2 float32) float32 {
	if p1 < p2 {
		return p2
	}
	return p1
}

func (p ByFdsPercent) Len() int { return len(p) }
func (p ByFdsPercent) Less(i, j int) bool {
	return max(p[i].fdsPercent, p[i].nProcPercent) < max(p[j].fdsPercent, p[j].nProcPercent)
}
func (p ByFdsPercent) Swap(i, j int) { p[i], p[j] = p[j], p[i] }

func GetLimits(pid string) Limits {
	var mylimit Limits
	var rlim syscall.Rlimit
	pidNu, _ := strconv.Atoi(pid)

	err := Prlimit(pidNu, syscall.RLIMIT_NOFILE, nil, &rlim)
	if err != nil {
		panic(err)
	}

	mylimit.openFiles = rlim

	// syscall.RLIMIT_NPROC is not defined, using number instead
	// See https://github.com/golang/go/issues/14854 for details
	err = Prlimit(pidNu, 6, nil, &rlim)
	if err != nil {
		panic(err)
	}
	mylimit.nProc = rlim
	return mylimit
}

func countFiles(dir string) uint64 {
	f, err := os.Open(dir)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	files, err := f.Readdirnames(-1)
	if err != nil {
		panic(err)
	}
	return uint64(len(files))
}

func GetFdOpen(pid string) uint64 {
	return countFiles(filepath.Join("/proc", pid, "fd"))
}

func GetNProcPerUid(pid string) uint64 {
	// we actually need number of processes ran by this PID's UID
	uid, _ := getStatus(pid)
	return uint64(UserProcs[uid])
}

func CmdName(pid string) string {
	data, err := ioutil.ReadFile(filepath.Join("/proc", pid, "comm"))
	if err != nil {
		panic(err)
	}
	return strings.TrimSuffix(string(data), "\n")
}

func getStatus(pid string) (uid string, threads uint64) {
	data, err := ioutil.ReadFile(filepath.Join("/proc", pid, "status"))
	if err != nil {
		panic(err)
	}
	str := string(data)

	reUid := regexp.MustCompile(`(?m:^Uid:[ \t]+([0-9]+)[ \t]+)`)
	matchedUid := reUid.FindStringSubmatch(str)
	uid = matchedUid[1]

	reThreads := regexp.MustCompile(`(?m:^Threads:[ \t]+([0-9]+))`)
	matchedThreads := reThreads.FindStringSubmatch(str)
	threads, err = strconv.ParseUint(matchedThreads[1], 10, 64)
	if err != nil {
		panic(err)
	}
	return uid, threads
}

func countProcesses(pids []string) {
	UserProcs = make(map[string]uint64)
	for _, pid := range pids {
		uid, threads := getStatus(pid)
		UserProcs[uid] += threads
		TotalThreads += threads
	}
}

func ProcTotalLimit() uint64 {
	data, err := ioutil.ReadFile("/proc/sys/kernel/threads-max")
	if err != nil {
		panic(err)
	}
	threadsMax, err := strconv.ParseUint(strings.TrimSuffix(string(data), "\n"), 10, 64)

	if err != nil {
		panic(err)
	}
	return threadsMax
}

func main() {
	nLines := flag.Int("n", 10, "Output N most loaded processes. Use -1 to list all.")
	flag.Parse()
	procs, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		panic(err)
	}
	var pids []string
	for _, p := range procs {
		pids = append(pids, strings.Split(p, "/")[2])
	}

	// count number of processes per user
	countProcesses(pids)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintln(w, "PID\tFD\tFD-max\tFD%\tProc\tProc-Max\tProc%\tCMD\t")

	entries := []OutputEntry{}

	// Limits for total number of processes.
	pp1 := float32(TotalThreads) / float32(ProcTotalLimit()) * 100.0

	for _, pid := range pids {
		limits := GetLimits(pid)
		open := GetFdOpen(pid)
		fdsLimit := strconv.FormatUint(limits.openFiles.Cur, 10)
		fdsPercent := float32(open) / float32(limits.openFiles.Cur) * 100.0
		if fdsPercent > 100 {
			fdsPercent = 100
		}
		if limits.openFiles.Cur == math.MaxUint64 {
			fdsLimit = "-1"
		}

		nProc := GetNProcPerUid(pid)
		pp2 := float32(nProc) / float32(limits.nProc.Cur) * 100.0

		var pp float32   // process percentage
		var p, pl uint64 // process count, process limit
		// TODO: we need to check not just for uid=0, but also for CAP_SYS_RESOURCE & CAP_SYS_ADMIN
		// http://lxr.free-electrons.com/source/kernel/fork.c#L1529
		if pp2 > pp1 && pid != "0" {
			pp = pp2
			p = nProc
			pl = limits.nProc.Cur
		} else {
			pp = pp1
			p = TotalThreads
			pl = ProcTotalLimit()
		}
		if pp > 100 {
			pp = 100
		}
		var plStr string
		if pl == math.MaxUint64 {
			plStr = "-1"
		} else {
			plStr = strconv.FormatUint(pl, 10)
		}

		entries = append(entries, OutputEntry{
			pid:          pid,
			cmd:          CmdName(pid),
			fds:          open,
			fdsLimit:     fdsLimit,
			fdsPercent:   fdsPercent,
			nProc:        p,
			nProcLimit:   plStr,
			nProcPercent: pp,
		})
	}
	sort.Sort(sort.Reverse(ByFdsPercent(entries)))

	if *nLines == -1 {
		*nLines = len(entries)
	}
	for i := 0; i < *nLines && i < len(entries); i++ {
		e := entries[i]
		fmt.Fprintf(w, "%s\t%d\t%s\t%2.1f\t%d\t%s\t%2.1f\t%s\t\n", e.pid, e.fds, e.fdsLimit, e.fdsPercent, e.nProc, e.nProcLimit, e.nProcPercent, e.cmd)
	}
	if err = w.Flush(); err != nil {
		panic(err)
	}

}
