// SPDX-FileCopyrightText: 2026 Actinis OÜ
// SPDX-License-Identifier: EUPL-1.2

#include "gtest/gtest.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include "berberis/guest_os_primitives/guest_thread.h"
#include "berberis/guest_state/guest_state.h"
#include "berberis/kernel_api/run_guest_syscall.h"

#include "proc_self_syscall_emulation.h"

namespace berberis {

namespace {

// arm64 (asm-generic) syscall numbers.
constexpr long kNrOpenat = 56;
constexpr long kNrClose = 57;
constexpr long kNrRead = 63;
constexpr long kNrPread64 = 67;
constexpr long kNrFstat = 80;
constexpr long kAtFdcwd = -100;

constexpr uint64_t kGuestSp = 0x7000'1000;
constexpr uint64_t kGuestSvcPc = 0x4000'0000;

class GuestSyscalls {
 public:
  GuestSyscalls() : thread_(GuestThread::CreateForTest(&state_)) { state_.thread = thread_; }
  ~GuestSyscalls() { GuestThread::Destroy(thread_); }

  bool ok() const { return thread_ != nullptr; }

  long Call(long nr, uint64_t a0, uint64_t a1 = 0, uint64_t a2 = 0, uint64_t a3 = 0,
            uint64_t a4 = 0, uint64_t a5 = 0) {
    state_.cpu.x[0] = a0;
    state_.cpu.x[1] = a1;
    state_.cpu.x[2] = a2;
    state_.cpu.x[3] = a3;
    state_.cpu.x[4] = a4;
    state_.cpu.x[5] = a5;
    state_.cpu.x[8] = nr;
    state_.cpu.sp = kGuestSp;
    state_.cpu.insn_addr = kGuestSvcPc;
    RunGuestSyscall(&state_);
    return static_cast<long>(state_.cpu.x[0]);
  }

  long Open(const char* path) {
    return Call(kNrOpenat, static_cast<uint64_t>(kAtFdcwd), reinterpret_cast<uint64_t>(path),
                O_RDONLY);
  }

 private:
  ThreadState state_{};
  GuestThread* thread_;
};

std::string Expected(long nr, uint64_t fd, const void* buf, uint64_t count, uint64_t a3,
                     uint64_t a4, uint64_t a5) {
  char line[256];
  snprintf(line, sizeof(line),
           "%ld 0x%" PRIx64 " 0x%" PRIx64 " 0x%" PRIx64 " 0x%" PRIx64 " 0x%" PRIx64 " 0x%" PRIx64
           " 0x%" PRIx64 " 0x%" PRIx64 "\n",
           nr, fd, reinterpret_cast<uint64_t>(buf), count, a3, a4, a5, kGuestSp, kGuestSvcPc + 4);
  return line;
}

// #1030: a protection library read its own task/<tid>/syscall and found the
// host view (x86_64 read is 0, a host SP, a PC in the code cache), then
// dereferenced NULL. The guest must see its own syscall: the arm64 number,
// its registers, its SP and the PC after its svc.
TEST(ProcSelfSyscallEmulationTest, OwnThreadFileShowsTheGuestSyscall) {
  struct Result {
    bool ran = false;
    long fd = -1;
    std::string first;
    std::string expected;
    long eof = -1;
    std::string pread;
    std::string pread_expected;
    long close = -1;
  } r;
  std::thread worker([&r] {
    GuestSyscalls guest;
    if (!guest.ok()) {
      return;
    }
    r.fd = guest.Open("/proc/thread-self/syscall");
    if (r.fd < 0) {
      return;
    }
    char buf[256] = {};
    long n = guest.Call(kNrRead, r.fd, reinterpret_cast<uint64_t>(buf), 255, 0x11, 0x22, 0x33);
    r.first.assign(buf, n > 0 ? n : 0);
    r.expected = Expected(kNrRead, r.fd, buf, 255, 0x11, 0x22, 0x33);
    char rest[16];
    r.eof = guest.Call(kNrRead, r.fd, reinterpret_cast<uint64_t>(rest), sizeof(rest));
    char again[256] = {};
    n = guest.Call(kNrPread64, r.fd, reinterpret_cast<uint64_t>(again), 200, 0, 0x44, 0x55);
    r.pread.assign(again, n > 0 ? n : 0);
    r.pread_expected = Expected(kNrPread64, r.fd, again, 200, 0, 0x44, 0x55);
    r.close = guest.Call(kNrClose, r.fd);
    r.ran = true;
  });
  worker.join();
  ASSERT_TRUE(r.ran) << "fd=" << r.fd;
  EXPECT_EQ(r.first, r.expected);
  EXPECT_EQ(r.eof, 0);
  EXPECT_EQ(r.pread, r.pread_expected);
  EXPECT_EQ(r.close, 0);
  EXPECT_FALSE(HasEmulatedProcSelfSyscallFds());
}

// A relative open under the thread's own task directory is the same file.
TEST(ProcSelfSyscallEmulationTest, RelativeOpenUnderTaskDirectoryIsEmulated) {
  std::string line;
  std::string expected;
  std::thread worker([&] {
    GuestSyscalls guest;
    int dir = open("/proc/thread-self", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (!guest.ok() || dir < 0) {
      return;
    }
    long fd = guest.Call(kNrOpenat, dir, reinterpret_cast<uint64_t>("syscall"), O_RDONLY);
    close(dir);
    if (fd < 0) {
      return;
    }
    char buf[256] = {};
    long n = guest.Call(kNrRead, fd, reinterpret_cast<uint64_t>(buf), 255);
    line.assign(buf, n > 0 ? n : 0);
    expected = Expected(kNrRead, fd, buf, 255, 0, 0, 0);
    guest.Call(kNrClose, fd);
  });
  worker.join();
  EXPECT_FALSE(expected.empty());
  EXPECT_EQ(line, expected);
}

// fstat describes the procfs file, not the memfd behind it.
TEST(ProcSelfSyscallEmulationTest, FstatReportsTheProcFile) {
  uint32_t mode = 0;
  int64_t size = -1;
  std::thread worker([&] {
    GuestSyscalls guest;
    if (!guest.ok()) {
      return;
    }
    long fd = guest.Open("/proc/thread-self/syscall");
    if (fd < 0) {
      return;
    }
    // arm64 struct stat: st_mode at offset 16, st_size at offset 48.
    alignas(8) unsigned char guest_stat[128] = {};
    if (guest.Call(kNrFstat, fd, reinterpret_cast<uint64_t>(guest_stat)) == 0) {
      memcpy(&mode, guest_stat + 16, sizeof(mode));
      memcpy(&size, guest_stat + 48, sizeof(size));
    }
    guest.Call(kNrClose, fd);
  });
  worker.join();
  EXPECT_TRUE(S_ISREG(mode));
  EXPECT_EQ(mode & 0777, 0400u);
  EXPECT_EQ(size, 0);
}

// Another thread reading the file sees the owner as running, as the kernel
// shows a thread that is not in a syscall it can describe.
TEST(ProcSelfSyscallEmulationTest, AnotherThreadSeesTheOwnerRunning) {
  long fd = -1;
  std::thread opener([&] {
    GuestSyscalls guest;
    if (guest.ok()) {
      fd = guest.Open("/proc/thread-self/syscall");
    }
  });
  opener.join();
  ASSERT_GE(fd, 0);
  std::string line;
  std::thread reader([&] {
    GuestSyscalls guest;
    char buf[64] = {};
    long n = guest.Call(kNrRead, fd, reinterpret_cast<uint64_t>(buf), sizeof(buf) - 1);
    line.assign(buf, n > 0 ? n : 0);
    guest.Call(kNrClose, fd);
  });
  reader.join();
  EXPECT_EQ(line, "running\n");
  EXPECT_FALSE(HasEmulatedProcSelfSyscallFds());
}

// Other files, and the syscall file opened for writing, keep the host fd.
TEST(ProcSelfSyscallEmulationTest, OtherFilesKeepTheHostFd) {
  int stat_fd = open("/proc/thread-self/stat", O_RDONLY | O_CLOEXEC);
  ASSERT_GE(stat_fd, 0);
  EXPECT_EQ(MaybeEmulateProcSelfSyscallOpen("/proc/thread-self/stat", stat_fd), stat_fd);
  close(stat_fd);

  int syscall_fd = open("/proc/thread-self/syscall", O_RDONLY | O_CLOEXEC);
  ASSERT_GE(syscall_fd, 0);
  // A path that does not name a syscall file is never stat-checked.
  EXPECT_EQ(MaybeEmulateProcSelfSyscallOpen("/proc/thread-self/syscalls", syscall_fd), syscall_fd);
  EXPECT_EQ(MaybeEmulateProcSelfSyscallOpen(nullptr, syscall_fd), syscall_fd);
  close(syscall_fd);

  int path_fd = open("/proc/thread-self/syscall", O_PATH | O_CLOEXEC);
  ASSERT_GE(path_fd, 0);
  EXPECT_EQ(MaybeEmulateProcSelfSyscallOpen("/proc/thread-self/syscall", path_fd), path_fd);
  close(path_fd);

  EXPECT_EQ(MaybeEmulateProcSelfSyscallOpen("/proc/thread-self/syscall", -1), -1);
  EXPECT_FALSE(HasEmulatedProcSelfSyscallFds());
}

// A guest fd number reused for another file (dup2 over it) is not written to.
TEST(ProcSelfSyscallEmulationTest, ReusedFdNumberIsNotTreatedAsEmulated) {
  int host_fd = open("/proc/thread-self/syscall", O_RDONLY | O_CLOEXEC);
  ASSERT_GE(host_fd, 0);
  long fd = MaybeEmulateProcSelfSyscallOpen("/proc/thread-self/syscall", host_fd);
  ASSERT_NE(fd, host_fd);
  ASSERT_TRUE(HasEmulatedProcSelfSyscallFds());

  char path[] = "/tmp/berberis-proc-syscall-XXXXXX";
  int other = mkstemp(path);
  ASSERT_GE(other, 0);
  unlink(path);
  ASSERT_EQ(write(other, "keep", 4), 4);
  ASSERT_EQ(dup2(other, static_cast<int>(fd)), fd);

  const uint64_t args[6] = {};
  RefreshEmulatedProcSelfSyscall(fd, 0, kNrRead, args, kGuestSp, kGuestSvcPc + 4);
  char buf[8] = {};
  EXPECT_EQ(pread(other, buf, sizeof(buf), 0), 4);
  EXPECT_STREQ(buf, "keep");
  struct stat st;
  EXPECT_FALSE(GetEmulatedProcSelfSyscallStat(fd, &st));
  EXPECT_FALSE(HasEmulatedProcSelfSyscallFds());
  ForgetEmulatedProcSelfSyscall(fd);
  close(static_cast<int>(fd));
  close(other);
}

// Unregistered fds and continued reads leave the content alone.
TEST(ProcSelfSyscallEmulationTest, ContinuedReadKeepsTheRenderedLine) {
  int host_fd = open("/proc/thread-self/syscall", O_RDONLY | O_CLOEXEC);
  ASSERT_GE(host_fd, 0);
  long fd = MaybeEmulateProcSelfSyscallOpen("/proc/thread-self/syscall", host_fd);
  ASSERT_NE(fd, host_fd);
  const uint64_t first[6] = {1, 2, 3, 4, 5, 6};
  RefreshEmulatedProcSelfSyscall(fd, -1, kNrRead, first, kGuestSp, kGuestSvcPc + 4);
  char head[4] = {};
  ASSERT_EQ(read(static_cast<int>(fd), head, 3), 3);
  const uint64_t second[6] = {9, 9, 9, 9, 9, 9};
  RefreshEmulatedProcSelfSyscall(fd, -1, 99, second, 0, 0);
  RefreshEmulatedProcSelfSyscall(fd + 1000, 0, 99, second, 0, 0);
  char line[256] = {};
  ASSERT_GT(pread(static_cast<int>(fd), line, sizeof(line) - 1, 0), 0);
  char expected[256];
  ASSERT_GT(FormatGuestProcSyscallLine(kNrRead, first, kGuestSp, kGuestSvcPc + 4, expected,
                                       sizeof(expected)),
            0u);
  EXPECT_STREQ(line, expected);
  ForgetEmulatedProcSelfSyscall(fd);
  ForgetEmulatedProcSelfSyscall(fd);
  EXPECT_FALSE(HasEmulatedProcSelfSyscallFds());
  close(static_cast<int>(fd));
}

TEST(ProcSelfSyscallEmulationTest, FormatRejectsAShortBuffer) {
  const uint64_t args[6] = {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX};
  char small[16];
  EXPECT_EQ(FormatGuestProcSyscallLine(63, args, UINT64_MAX, UINT64_MAX, small, sizeof(small)), 0u);
  char line[256];
  size_t len = FormatGuestProcSyscallLine(-1, args, 1, 2, line, sizeof(line));
  ASSERT_GT(len, 0u);
  EXPECT_EQ(std::string(line, 3), "-1 ");
  EXPECT_EQ(line[len - 1], '\n');
}

}  // namespace

}  // namespace berberis
