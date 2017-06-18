package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"text/tabwriter"

	"github.com/mihgen/softstat"
)

type Metric struct {
	name string
	f    interface{}
	res  softstat.Entry
}

type OutputEntry struct {
	pid   string
	data  []Metric
	bound Boundary
	cmd   string
}

type Boundary struct {
	by  string
	v   uint64
	max uint64
	p   float64
}

func CalcBound(m []Metric) (b Boundary) {
	b.p = -1.0
	for i := 0; i < len(m); i++ {
		var p float64
		if m[i].res.Max <= 0 {
			p = 100.0
		} else {
			p = 100.0 * float64(m[i].res.V) / float64(m[i].res.Max)
		}
		if p > b.p {
			b.p = p
			b.by = m[i].name
			b.v = m[i].res.V
			b.max = m[i].res.Max
		}
	}
	return
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
	tasks := softstat.TasksInit()
	procTotalLimit := softstat.ProcTotalLimit()
	fileTotal, fileMax := softstat.FileNr()
	filePerProcMax := softstat.FilePerProcMax()
	var out []OutputEntry
	for _, pid := range tasks.Pids {
		m := []Metric{{name: "fds-rlim", f: pid.FdsRlim}, {name: "nproc-rlim", f: pid.NprocRlim}}
		for i := 0; i < len(m); i++ {
			//TODO: need error handling. What if we could not get FD limits, but got everything else?
			e, _ := m[i].f.(func() (softstat.Entry, error))()
			m[i].res = e
		}
		cmd, _ := softstat.CmdName(pid.Pid)

		adds := []Metric{{name: "threads-max", res: softstat.Entry{tasks.Total, procTotalLimit}},
			{name: "pid_max", res: softstat.Entry{tasks.Total, softstat.PidTotalLimit()}},
			{name: "file-max", res: softstat.Entry{fileTotal, fileMax}},
			{name: "file-perproc-max", res: softstat.Entry{m[0].res.V, filePerProcMax}}}
		out = append(out, OutputEntry{pid.Pid, m, CalcBound(append(m, adds...)), cmd})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].bound.p > out[j].bound.p })

	// **************** PRINT CODE *********************
	fmt.Printf("Tasks %d, system max is %d\n", tasks.Total, procTotalLimit)
	fmt.Printf("File descriptors open %d, system max total is %d, system max per process is %d\n", fileTotal, fileMax, filePerProcMax)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 0, ' ', tabwriter.AlignRight)
	fmt.Fprintln(w, "PID\t FD\t FD-RL\t TSK\t TSK-RL\t BOUND\t VAL\t MAX\t %USE\t CMD\t")

	if nLines == -1 {
		nLines = len(out)
	}
	for i := 0; i < nLines && i < len(out); i++ {
		fmt.Fprintf(w, "%s\t", out[i].pid)
		for j := 0; j < len(out[i].data); j++ {
			maxS := "-1"
			if out[i].data[j].res.Max != math.MaxUint64 {
				maxS = strconv.FormatUint(out[i].data[j].res.Max, 10)
			}
			fmt.Fprintf(w, "%d\t %s\t ", out[i].data[j].res.V, maxS)
		}
		fmt.Fprintf(w, "%s\t %d\t %d\t %2.1f\t ", out[i].bound.by, out[i].bound.v, out[i].bound.max, out[i].bound.p)
		fmt.Fprintf(w, "%s\t\n", out[i].cmd)
	}
	if err := w.Flush(); err != nil {
		panic(err)
	}
}
