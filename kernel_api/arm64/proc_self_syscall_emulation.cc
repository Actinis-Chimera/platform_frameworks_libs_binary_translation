// SPDX-FileCopyrightText: 2026 Actinis OÜ
// SPDX-License-Identifier: EUPL-1.2

#include "proc_self_syscall_emulation.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <mutex>

#include "berberis/base/fd.h"
#include "berberis/base/raw_syscall.h"
#include "berberis/base/tracing.h"

namespace berberis {

namespace {

// A process rarely holds more than one of these open; past this many, further
// opens keep the host file rather than grow a table on the syscall path.
constexpr size_t kMaxEmulatedFds = 16;

struct EmulatedSyscallFile {
  bool used = false;
  int fd = -1;
  // The memfd's identity, so a guest fd number reused for another file (after
  // dup2 over it or close_range) is never mistaken for the emulated one.
  dev_t mem_dev = 0;
  ino_t mem_ino = 0;
  // The thread whose syscall the file describes.
  pid_t owner_tid = 0;
  struct stat real_stat = {};
};

std::mutex g_mutex;
EmulatedSyscallFile g_files[kMaxEmulatedFds];
std::atomic<size_t> g_count{0};

// Raw syscalls, so the ids compared at open and at read come from the same
// source whatever the libc in between does with them.
pid_t CurrentTid() {
  return static_cast<pid_t>(RawSyscall(__NR_gettid));
}

pid_t CurrentTgid() {
  return static_cast<pid_t>(RawSyscall(__NR_getpid));
}

bool IsSameFile(const struct stat& st, const char* path) {
  struct stat other;
  return stat(path, &other) == 0 && st.st_dev == other.st_dev && st.st_ino == other.st_ino;
}

bool NamesSyscallFile(const char* path) {
  if (path == nullptr) {
    return false;
  }
  constexpr char kName[] = "syscall";
  constexpr size_t kNameLen = sizeof(kName) - 1;
  size_t len = strlen(path);
  if (len < kNameLen || strcmp(path + len - kNameLen, kName) != 0) {
    return false;
  }
  return len == kNameLen || path[len - kNameLen - 1] == '/';
}

// The live entry for `fd`, or nullptr. Drops an entry whose fd number now
// names another file. Requires g_mutex.
EmulatedSyscallFile* FindLocked(long fd) {
  for (auto& file : g_files) {
    if (!file.used || file.fd != fd) {
      continue;
    }
    struct stat st;
    if (fstat(static_cast<int>(fd), &st) == 0 && st.st_dev == file.mem_dev &&
        st.st_ino == file.mem_ino) {
      return &file;
    }
    file = EmulatedSyscallFile{};
    g_count.fetch_sub(1, std::memory_order_relaxed);
    return nullptr;
  }
  return nullptr;
}

void WriteContent(int fd, const char* data, size_t size) {
  if (ftruncate64(fd, 0) != 0) {
    return;
  }
  size_t done = 0;
  while (done < size) {
    ssize_t written = pwrite64(fd, data + done, size - done, static_cast<off64_t>(done));
    if (written <= 0) {
      return;
    }
    done += static_cast<size_t>(written);
  }
}

}  // namespace

size_t FormatGuestProcSyscallLine(long nr,
                                  const uint64_t (&args)[6],
                                  uint64_t sp,
                                  uint64_t pc,
                                  char* out,
                                  size_t size) {
  // The kernel's proc_pid_syscall format for a thread inside a syscall.
  int len = snprintf(out,
                     size,
                     "%d 0x%" PRIx64 " 0x%" PRIx64 " 0x%" PRIx64 " 0x%" PRIx64 " 0x%" PRIx64
                     " 0x%" PRIx64 " 0x%" PRIx64 " 0x%" PRIx64 "\n",
                     static_cast<int>(nr),
                     args[0],
                     args[1],
                     args[2],
                     args[3],
                     args[4],
                     args[5],
                     sp,
                     pc);
  if (len < 0 || static_cast<size_t>(len) >= size) {
    return 0;
  }
  return static_cast<size_t>(len);
}

long MaybeEmulateProcSelfSyscallOpen(const char* guest_path, long host_fd) {
  if (host_fd < 0 || !NamesSyscallFile(guest_path)) {
    return host_fd;
  }
  int fd = static_cast<int>(host_fd);
  int status_flags = fcntl(fd, F_GETFL);
  if (status_flags == -1 || (status_flags & O_PATH) != 0 ||
      (status_flags & O_ACCMODE) != O_RDONLY) {
    return host_fd;
  }
  struct stat real_stat;
  if (fstat(fd, &real_stat) != 0) {
    return host_fd;
  }
  pid_t owner_tid;
  if (IsSameFile(real_stat, "/proc/thread-self/syscall")) {
    owner_tid = CurrentTid();
  } else if (IsSameFile(real_stat, "/proc/self/syscall")) {
    // The process-level file describes the thread-group leader.
    owner_tid = CurrentTgid();
  } else {
    return host_fd;
  }
  int fd_flags = fcntl(fd, F_GETFD);

  std::lock_guard lock(g_mutex);
  EmulatedSyscallFile* slot = nullptr;
  for (auto& file : g_files) {
    if (!file.used) {
      slot = &file;
      break;
    }
  }
  if (slot == nullptr) {
    TRACE("too many emulated syscall files open; keeping the host view");
    return host_fd;
  }
  int mem_fd = CreateMemfdOrDie("[guest /proc/self/syscall]");
  if (fd_flags != -1 && (fd_flags & FD_CLOEXEC) == 0) {
    fcntl(mem_fd, F_SETFD, fd_flags);
  }
  struct stat mem_stat;
  if (fstat(mem_fd, &mem_stat) != 0) {
    CloseUnsafe(mem_fd);
    return host_fd;
  }
  CloseUnsafe(fd);
  *slot = EmulatedSyscallFile{
      .used = true,
      .fd = mem_fd,
      .mem_dev = mem_stat.st_dev,
      .mem_ino = mem_stat.st_ino,
      .owner_tid = owner_tid,
      .real_stat = real_stat,
  };
  g_count.fetch_add(1, std::memory_order_relaxed);
  TRACE("emulating the guest view of the syscall file of tid %d as fd %d", owner_tid, mem_fd);
  return mem_fd;
}

void RefreshEmulatedProcSelfSyscall(long fd,
                                    long offset,
                                    long nr,
                                    const uint64_t (&args)[6],
                                    uint64_t sp,
                                    uint64_t pc) {
  if (!HasEmulatedProcSelfSyscallFds()) {
    return;
  }
  std::lock_guard lock(g_mutex);
  EmulatedSyscallFile* file = FindLocked(fd);
  if (file == nullptr) {
    return;
  }
  if (offset < 0) {
    offset = lseek64(file->fd, 0, SEEK_CUR);
  }
  if (offset != 0) {
    // A continued read sees the content rendered when the read began, like the
    // kernel's seq_file.
    return;
  }
  char line[256];
  size_t len;
  if (CurrentTid() == file->owner_tid) {
    len = FormatGuestProcSyscallLine(nr, args, sp, pc, line, sizeof(line));
  } else {
    constexpr char kRunning[] = "running\n";
    memcpy(line, kRunning, sizeof(kRunning));
    len = sizeof(kRunning) - 1;
  }
  WriteContent(file->fd, line, len);
}

bool GetEmulatedProcSelfSyscallStat(long fd, struct stat* st) {
  if (!HasEmulatedProcSelfSyscallFds()) {
    return false;
  }
  std::lock_guard lock(g_mutex);
  EmulatedSyscallFile* file = FindLocked(fd);
  if (file == nullptr) {
    return false;
  }
  *st = file->real_stat;
  return true;
}

void ForgetEmulatedProcSelfSyscall(long fd) {
  if (!HasEmulatedProcSelfSyscallFds()) {
    return;
  }
  std::lock_guard lock(g_mutex);
  EmulatedSyscallFile* file = FindLocked(fd);
  if (file != nullptr) {
    *file = EmulatedSyscallFile{};
    g_count.fetch_sub(1, std::memory_order_relaxed);
  }
}

bool HasEmulatedProcSelfSyscallFds() {
  return g_count.load(std::memory_order_relaxed) != 0;
}

}  // namespace berberis
