// SPDX-FileCopyrightText: 2026 Actinis OÜ
// SPDX-License-Identifier: EUPL-1.2

#ifndef BERBERIS_KERNEL_API_ARM64_PROC_SELF_SYSCALL_EMULATION_H_
#define BERBERIS_KERNEL_API_ARM64_PROC_SELF_SYSCALL_EMULATION_H_

#include <sys/stat.h>

#include <cstddef>
#include <cstdint>

namespace berberis {

// The guest view of a thread's own /proc/<pid>/task/<tid>/syscall file.
//
// The kernel renders that file from the thread's in-flight syscall: the
// syscall number, its six arguments, the stack pointer and the program
// counter. Under translation the thread is inside a HOST x86_64 syscall, so
// the real file shows the host number (x86_64 read is 0, arm64 read is 63),
// a host stack and a PC in the translated-code cache, none of which the guest
// can map to its own code. Native protection libraries read the file to check
// that a syscall came from the guest libc's text (#1030), and fail on a PC
// outside every guest module. A guest open of the calling thread's own
// syscall file therefore gets a memfd whose content is re-rendered from the
// guest registers whenever the guest reads it from offset 0.
//
// Every hook is a no-op unless such a file is open, so other syscalls pay
// one relaxed atomic load.

// The arm64 (asm-generic) numbers of the hooked syscalls.
inline constexpr long kGuestNrProcSyscallFstatfs = 44;
inline constexpr long kGuestNrProcSyscallOpenat = 56;
inline constexpr long kGuestNrProcSyscallClose = 57;
inline constexpr long kGuestNrProcSyscallRead = 63;
inline constexpr long kGuestNrProcSyscallReadv = 65;
inline constexpr long kGuestNrProcSyscallPread64 = 67;
inline constexpr long kGuestNrProcSyscallPreadv = 69;
inline constexpr long kGuestNrProcSyscallFstat = 80;
inline constexpr long kGuestNrProcSyscallOpenat2 = 437;

// Formats one kernel-style syscall line ("%d 0x%lx ... 0x%lx\n": the number,
// six arguments, SP and PC) into `out`. Returns the length, or 0 when `size`
// is too small.
size_t FormatGuestProcSyscallLine(long nr,
                                  const uint64_t (&args)[6],
                                  uint64_t sp,
                                  uint64_t pc,
                                  char* out,
                                  size_t size);

// After a successful guest openat/openat2 that returned `host_fd` for
// `guest_path`: if the fd is the calling thread's own syscall file, opened
// read-only, returns a memfd standing in for it (and closes `host_fd`).
// Otherwise returns `host_fd` unchanged.
long MaybeEmulateProcSelfSyscallOpen(const char* guest_path, long host_fd);

// Before a guest read of `fd`: if it is an emulated syscall file and the read
// starts at offset 0, renders the current guest syscall into it. The calling
// thread's own file shows `nr`, `args`, `sp` and `pc`; a read from another
// thread shows "running", as the kernel does for a running thread.
// `offset` is the explicit pread offset, or -1 for the fd's own position.
void RefreshEmulatedProcSelfSyscall(long fd,
                                    long offset,
                                    long nr,
                                    const uint64_t (&args)[6],
                                    uint64_t sp,
                                    uint64_t pc);

// The real file's stat for an emulated fd. Returns false for any other fd.
bool GetEmulatedProcSelfSyscallStat(long fd, struct stat* st);

// Drops the bookkeeping for `fd` before the guest closes it.
void ForgetEmulatedProcSelfSyscall(long fd);

// True while at least one emulated syscall file is registered.
bool HasEmulatedProcSelfSyscallFds();

}  // namespace berberis

#endif  // BERBERIS_KERNEL_API_ARM64_PROC_SELF_SYSCALL_EMULATION_H_
