package softstat

import (
	"syscall"
	"unsafe"
)

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
