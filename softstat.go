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

type Metric struct {
	name string
	f    interface{}
	res  Entry
}

type Limits struct {
	openFiles syscall.Rlimit
	nProc     syscall.Rlimit
}

type Entry struct {
	v   uint64
	max uint64
}

type Boundary struct {
	by  string
	v   uint64
	max uint64
	p   float64
}

type OutputEntry struct {
	pid   string
	data  []Metric
	bound Boundary
	cmd   string
}

type Task struct {
	pid    string
	UidMap map[string]uint64
	limits Limits
}

type Tasks struct {
	pids  []Task
	total uint64
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

func GetLimits(pid string) (Limits, error) {
	var mylimit Limits
	var rlim syscall.Rlimit
	pidNu, _ := strconv.Atoi(pid)

	err := Prlimit(pidNu, syscall.RLIMIT_NOFILE, nil, &rlim)
	mylimit.openFiles = rlim
	if err != nil {
		return mylimit, err
	}

	// syscall.RLIMIT_NPROC is not defined, using number instead
	// See https://github.com/golang/go/issues/14854 for details
	err = Prlimit(pidNu, 6, nil, &rlim)
	mylimit.nProc = rlim
	if err != nil {
		return mylimit, err
	}
	return mylimit, nil
}

func countFiles(dir string) (uint64, error) {
	f, err := os.Open(dir)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	files, err := f.Readdirnames(-1)
	if err != nil {
		return 0, err
	}
	return uint64(len(files)), nil
}

func (t Task) FdsRlim() (Entry, error) {
	v, err := countFiles(filepath.Join("/proc", t.pid, "fd"))
	if err != nil {
		return Entry{}, err // this process may no longer exist. So let's skip it.
	}
	return Entry{v, t.limits.openFiles.Cur}, nil
}

func (t Task) NprocRlim() (Entry, error) {
	uid, _, err := getStatus(t.pid)
	if err != nil {
		return Entry{}, err
	}
	return Entry{t.UidMap[uid], t.limits.nProc.Cur}, nil
}

func CalcBound(m []Metric) (b Boundary) {
	b.p = -1.0
	for i := 0; i < len(m); i++ {
		var p float64
		if m[i].res.max <= 0 {
			p = 100.0
		} else {
			p = 100.0 * float64(m[i].res.v) / float64(m[i].res.max)
		}
		if p > b.p {
			b.p = p
			b.by = m[i].name
			b.v = m[i].res.v
			b.max = m[i].res.max
		}
	}
	return
}

func getStatus(pid string) (uid string, threads uint64, err error) {
	str, err := ReadAndTrim(filepath.Join("/proc", pid, "status"))
	if err != nil {
		// we can't do anything for this pid. It may not exist anymore, or we don't have enough capabilities
		return
	}

	reUid := regexp.MustCompile(`(?m:^Uid:[ \t]+([0-9]+)[ \t]+)`)
	matchedUid := reUid.FindStringSubmatch(str)
	// TODO: what if we can't parse? Need to do error-handling
	uid = matchedUid[1]

	reThreads := regexp.MustCompile(`(?m:^Threads:[ \t]+([0-9]+))`)
	matchedThreads := reThreads.FindStringSubmatch(str)
	// TODO: what if we can't parse? Need to do error-handling
	threads, err = strconv.ParseUint(matchedThreads[1], 10, 64)
	return
}

func ProcTotalLimit() uint64 {
	str, err := ReadAndTrim("/proc/sys/kernel/threads-max")
	if err != nil {
		// we are in a big trouble if we can't get threads-max, so just panic right away
		panic(err)
	}
	threadsMax, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		panic(err)
	}
	return threadsMax
}

func TasksInit() *Tasks {
	t := new(Tasks)
	byUid := make(map[string]uint64)

	procs, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		panic(err)
	}
	for _, p := range procs {
		pid := strings.Split(p, "/")[2]

		uid, threads, err := getStatus(pid)
		if err != nil {
			// process may no longer exist, so we just skip pid with errors
			// TODO: need to have better error handling here.
			// One of issues could be that we simply can't open any file, as we reached FD limit ourselves.
			continue
		}
		// TODO: we need to check for uid=0, CAP_SYS_RESOURCE & CAP_SYS_ADMIN
		// http://lxr.free-electrons.com/source/kernel/fork.c#L1529
		// and error handling
		l, _ := GetLimits(pid)
		byUid[uid] += threads
		t.pids = append(t.pids, Task{pid: pid, limits: l, UidMap: byUid})
		t.total += threads
	}
	return t
}

func ReadAndTrim(file string) (string, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(string(data), "\n"), nil
}

func CmdName(pid string) (string, error) {
	return ReadAndTrim(filepath.Join("/proc", pid, "comm"))
}

func FileNr() (used, max uint64) {
	str, err := ReadAndTrim("/proc/sys/fs/file-nr")
	if err != nil {
		panic(err)
	}
	parsed := strings.Split(str, "\t")

	used, err = strconv.ParseUint(parsed[0], 10, 64)
	if err != nil {
		panic(err)
	}
	max, err = strconv.ParseUint(parsed[2], 10, 64)
	if err != nil {
		panic(err)
	}
	return
}

func FilePerProcMax() uint64 {
	str, err := ReadAndTrim("/proc/sys/fs/nr_open")
	if err != nil {
		panic(err)
	}
	x, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		panic(err)
	}
	return x
}

func main() {
	var nLines int
	if len(os.Args) == 2 && os.Args[1] == "-1" {
		nLines = -1
	} else {
		flag.IntVar(&nLines, "n", 10, "Output N most loaded processes. Use -1 to list all.")
		flag.Parse()
	}

	// ************** POPULATE CODE ********************
	tasks := TasksInit()
	procTotalLimit := ProcTotalLimit()
	fileTotal, fileMax := FileNr()
	filePerProcMax := FilePerProcMax()
	var out []OutputEntry
	for _, pid := range tasks.pids {
		m := []Metric{{name: "fds-rlim", f: pid.FdsRlim}, {name: "nproc-rlim", f: pid.NprocRlim}}
		for i := 0; i < len(m); i++ {
			//TODO: need error handling. What if we could not get FD limits, but got everything else?
			e, _ := m[i].f.(func() (Entry, error))()
			m[i].res = e
		}
		cmd, _ := CmdName(pid.pid)

		adds := []Metric{{name: "threads-max", res: Entry{tasks.total, procTotalLimit}},
			{name: "file-max", res: Entry{fileTotal, fileMax}},
			{name: "file-perproc-max", res: Entry{m[0].res.v, filePerProcMax}}}
		out = append(out, OutputEntry{pid.pid, m, CalcBound(append(m, adds...)), cmd})
	}

	// **************** PRINT CODE *********************
	fmt.Printf("Tasks %d, system max is %d\n", tasks.total, procTotalLimit)
	fmt.Printf("File descriptors open %d, system max total is %d, system max per process is %d\n", fileTotal, fileMax, filePerProcMax)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 0, ' ', tabwriter.AlignRight)
	fmt.Fprintln(w, "PID\t FD\t FD-RL\t TSK\t TSK-RL\t BOUND\t VAL\t MAX\t %USE\t CMD\t")

	sort.Slice(out, func(i, j int) bool { return out[i].bound.p > out[j].bound.p })
	if nLines == -1 {
		nLines = len(out)
	}
	for i := 0; i < nLines && i < len(out); i++ {
		fmt.Fprintf(w, "%s\t", out[i].pid)
		for j := 0; j < len(out[i].data); j++ {
			maxS := "-1"
			if out[i].data[j].res.max != math.MaxUint64 {
				maxS = strconv.FormatUint(out[i].data[j].res.max, 10)
			}
			fmt.Fprintf(w, "%d\t %s\t ", out[i].data[j].res.v, maxS)
		}
		fmt.Fprintf(w, "%s\t %d\t %d\t %2.1f\t ", out[i].bound.by, out[i].bound.v, out[i].bound.max, out[i].bound.p)
		fmt.Fprintf(w, "%s\t\n", out[i].cmd)
	}
	if err := w.Flush(); err != nil {
		panic(err)
	}
}
