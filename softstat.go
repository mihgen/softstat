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

package softstat

import (
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

type Limits struct {
	openFiles syscall.Rlimit
	nProc     syscall.Rlimit
}

type Task struct {
	Pid    string
	UidMap map[string]uint64
	limits Limits
}

type Tasks struct {
	Pids  []Task
	Total uint64
}

type Entry struct {
	V   uint64
	Max uint64
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
	v, err := countFiles(filepath.Join("/proc", t.Pid, "fd"))
	if err != nil {
		return Entry{}, err // this process may no longer exist. So let's skip it.
	}
	return Entry{v, t.limits.openFiles.Cur}, nil
}

func (t Task) NprocRlim() (Entry, error) {
	uid, _, err := getStatus(t.Pid)
	if err != nil {
		return Entry{}, err
	}
	return Entry{t.UidMap[uid], t.limits.nProc.Cur}, nil
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
		panic(err)
	}
	threadsMax, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		panic(err)
	}
	return threadsMax
}

func PidTotalLimit() uint64 {
	str, err := ReadAndTrim("/proc/sys/kernel/pid_max")
	if err != nil {
		panic(err)
	}
	v, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		panic(err)
	}
	return v
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
		// TODO: error handling
		l, _ := GetLimits(pid)
		// User with uid=0 has no RLIMIT enforcement on number of tasks. threads-max is still applied though.
		if uid == "0" {
			// TODO: we need to check for CAP_SYS_RESOURCE & CAP_SYS_ADMIN too
			// http://lxr.free-electrons.com/source/kernel/fork.c#L1529
			l.nProc.Cur = math.MaxUint64
		}
		byUid[uid] += threads
		t.Pids = append(t.Pids, Task{Pid: pid, limits: l, UidMap: byUid})
		t.Total += threads
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
