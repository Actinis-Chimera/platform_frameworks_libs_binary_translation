// SPDX-FileCopyrightText: 2026 Actinis OÜ
// SPDX-License-Identifier: EUPL-1.2

// A guest can name its own /proc/self/maps and /proc/cpuinfo in more ways than
// the absolute path. openat(procfd, "self") followed by openat(selffd, "./maps"),
// openat(procfd, "self/maps"), openat(procfd, "<pid>/maps") and openat2 with any
// of those all reach the same file. The translator serves the absolute path
// from an emulated view (guest-executable regions print "x", host-only
// libraries are hidden, the CPU is an arm64 one). Every other way of opening
// the file must return the same view, or a guest that compares two reads sees
// the host process instead of the Android-shaped one.

#include "gtest/gtest.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "berberis/base/config_globals.h"
#include "berberis/guest_os_primitives/guest_map_shadow.h"
#include "berberis/guest_os_primitives/guest_thread.h"
#include "berberis/guest_state/guest_addr.h"
#include "berberis/guest_state/guest_state.h"
#include "berberis/kernel_api/main_executable_real_path_emulation.h"
#include "berberis/kernel_api/open_emulation.h"
#include "berberis/kernel_api/run_guest_syscall.h"
#include "berberis/kernel_api/unistd_emulation.h"

namespace berberis {

namespace {

// struct open_how has the same layout for the arm64 guest and the x86_64 host.
struct OpenHow {
  uint64_t flags;
  uint64_t mode;
  uint64_t resolve;
};

constexpr size_t kOpenHowSizeVer0 = sizeof(OpenHow);

std::string ReadAll(int fd) {
  std::string content;
  char buf[4096];
  ssize_t n;
  while ((n = read(fd, buf, sizeof(buf))) > 0) {
    content.append(buf, static_cast<size_t>(n));
  }
  return content;
}

// Calls `open_fn`, which must fail, and returns the errno it left.
template <typename OpenFn>
int FailureErrno(OpenFn open_fn) {
  errno = 0;
  const int result = open_fn();
  const int saved_errno = errno;
  EXPECT_EQ(-1, result);
  return saved_errno;
}

// Emulated descriptors are remembered by number, so an emulated fd must be
// forgotten when it is closed or a later host open that reuses the number would
// look emulated.
void CloseGuestFd(int fd) {
  if (fd < 0) {
    return;
  }
  CloseEmulatedProcSelfMapsFileDescriptor(fd);
  close(fd);
}

// Returns the permissions field of the line of a maps dump that covers `addr`,
// or an empty string when no line does.
std::string PermsCovering(const std::string& maps, uintptr_t addr) {
  size_t pos = 0;
  while (pos < maps.size()) {
    size_t eol = maps.find('\n', pos);
    if (eol == std::string::npos) {
      eol = maps.size();
    }
    const std::string line = maps.substr(pos, eol - pos);
    pos = eol + 1;
    uintptr_t start = 0;
    uintptr_t end = 0;
    char perms[8] = {};
    if (sscanf(line.c_str(), "%" SCNxPTR "-%" SCNxPTR " %7s", &start, &end, perms) == 3 &&
        start <= addr && addr < end) {
      return perms;
    }
  }
  return "";
}

class OpenProcSelfRelativeTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ::testing::Test::SetUp();
    page_size_ = static_cast<size_t>(getpagesize());
    // A read-only host mapping that the translator treats as guest code: the
    // host kernel prints "r--p" for it, the guest view must print "r-xp".
    region_ = mmap(nullptr, page_size_, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(MAP_FAILED, region_);
    GuestMapShadow::GetInstance()->SetExecutable(ToGuestAddr(region_), page_size_);
    proc_dir_ = open("/proc", O_RDONLY | O_DIRECTORY);
    ASSERT_GE(proc_dir_, 0);
    self_dir_ = open("/proc/self", O_RDONLY | O_DIRECTORY);
    ASSERT_GE(self_dir_, 0);
  }

  void TearDown() override {
    close(self_dir_);
    close(proc_dir_);
    GuestMapShadow::GetInstance()->ClearExecutable(ToGuestAddr(region_), page_size_);
    munmap(region_, page_size_);
    ::testing::Test::TearDown();
  }

  // Opens `path` for the guest and checks that the result is the emulated
  // /proc/self/maps whose content shows the guest-executable region as such.
  void ExpectGuestMaps(int fd, const char* how_opened) {
    ASSERT_GE(fd, 0) << how_opened << ": " << strerror(errno);
    EXPECT_TRUE(IsFileDescriptorEmulatedProcSelfMaps(fd))
        << how_opened << " returned a descriptor that is not the emulated maps view";
    const std::string content = ReadAll(fd);
    EXPECT_EQ("r-xp", PermsCovering(content, reinterpret_cast<uintptr_t>(region_)))
        << how_opened << " did not return the guest view of the memory map";
    CloseGuestFd(fd);
  }

  // The absolute-path guest cpuinfo is the reference for every other way of
  // naming the file.
  static std::string AbsolutePathCpuinfo() {
    int fd = OpenatForGuest(AT_FDCWD, "/proc/cpuinfo", O_RDONLY, 0);
    EXPECT_GE(fd, 0);
    std::string content = ReadAll(fd);
    CloseGuestFd(fd);
    return content;
  }

  void ExpectGuestCpuinfo(int fd, const char* how_opened) {
    ASSERT_GE(fd, 0) << how_opened << ": " << strerror(errno);
    const std::string content = ReadAll(fd);
    CloseGuestFd(fd);
    EXPECT_NE(std::string::npos, content.find("CPU implementer"))
        << how_opened << " did not return the arm64 cpuinfo";
    EXPECT_EQ(std::string::npos, content.find("vendor_id"))
        << how_opened << " returned the host cpuinfo";
    EXPECT_EQ(AbsolutePathCpuinfo(), content) << how_opened;
  }

  size_t page_size_ = 0;
  void* region_ = nullptr;
  int proc_dir_ = -1;
  int self_dir_ = -1;
};

// The reference: the absolute path was always served.
TEST_F(OpenProcSelfRelativeTest, OpenatAbsolutePathServesGuestMaps) {
  ExpectGuestMaps(OpenatForGuest(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0), "absolute path");
  // An absolute path ignores the directory descriptor.
  ExpectGuestMaps(OpenatForGuest(self_dir_, "/proc/self/maps", O_RDONLY, 0),
                  "absolute path with a directory descriptor");
}

TEST_F(OpenProcSelfRelativeTest, OpenatRelativeToProcSelfDirectoryServesGuestMaps) {
  ExpectGuestMaps(OpenatForGuest(self_dir_, "maps", O_RDONLY, 0), "openat(selffd, \"maps\")");
}

TEST_F(OpenProcSelfRelativeTest, OpenatDotSlashRelativeToProcSelfDirectoryServesGuestMaps) {
  ExpectGuestMaps(OpenatForGuest(self_dir_, "./maps", O_RDONLY, 0), "openat(selffd, \"./maps\")");
}

TEST_F(OpenProcSelfRelativeTest, OpenatSelfRelativeToProcDirectoryServesGuestMaps) {
  ExpectGuestMaps(OpenatForGuest(proc_dir_, "self/maps", O_RDONLY, 0),
                  "openat(procfd, \"self/maps\")");
}

TEST_F(OpenProcSelfRelativeTest, OpenatNumericPidRelativeToProcDirectoryServesGuestMaps) {
  char path[64];
  snprintf(path, sizeof(path), "%d/maps", static_cast<int>(getpid()));
  ExpectGuestMaps(OpenatForGuest(proc_dir_, path, O_RDONLY, 0), "openat(procfd, \"<pid>/maps\")");
}

TEST_F(OpenProcSelfRelativeTest, OpenatTwoStepSelfThenMapsServesGuestMaps) {
  // The two opens an integrity check makes: the directory first, then the file
  // relative to it. The guest passes its own (arm64) open flag values.
  const int guest_dir_flags = ToGuestOpenFlags(O_RDONLY | O_DIRECTORY);
  int self_fd = OpenatForGuest(proc_dir_, "self", guest_dir_flags, 0);
  ASSERT_GE(self_fd, 0) << strerror(errno);
  ExpectGuestMaps(OpenatForGuest(self_fd, "./maps", O_RDONLY, 0),
                  "openat(openat(procfd, \"self\"), \"./maps\")");
  close(self_fd);
}

TEST_F(OpenProcSelfRelativeTest, OpenatRelativeCpuinfoServesGuestCpuinfo) {
  ExpectGuestCpuinfo(OpenatForGuest(AT_FDCWD, "/proc/cpuinfo", O_RDONLY, 0), "absolute path");
  ExpectGuestCpuinfo(OpenatForGuest(proc_dir_, "cpuinfo", O_RDONLY, 0),
                     "openat(procfd, \"cpuinfo\")");
  ExpectGuestCpuinfo(OpenatForGuest(proc_dir_, "./cpuinfo", O_RDONLY, 0),
                     "openat(procfd, \"./cpuinfo\")");
}

TEST_F(OpenProcSelfRelativeTest, OpenatOtherProcSelfFileStaysHostOpen) {
  int fd = OpenatForGuest(self_dir_, "status", O_RDONLY, 0);
  ASSERT_GE(fd, 0) << strerror(errno);
  EXPECT_FALSE(IsFileDescriptorEmulatedProcSelfMaps(fd));
  EXPECT_EQ(0u, ReadAll(fd).find("Name:"));
  CloseGuestFd(fd);
}

TEST_F(OpenProcSelfRelativeTest, OpenatRegularFileNamedMapsStaysHostOpen) {
  char dir_template[] = "/tmp/berberis_open_rel_XXXXXX";
  ASSERT_NE(nullptr, mkdtemp(dir_template));
  const std::string dir = dir_template;
  const std::string file = dir + "/maps";
  int file_fd = open(file.c_str(), O_WRONLY | O_CREAT, 0600);
  ASSERT_GE(file_fd, 0);
  ASSERT_EQ(5, write(file_fd, "plain", 5));
  close(file_fd);
  int dir_fd = open(dir.c_str(), O_RDONLY | O_DIRECTORY);
  ASSERT_GE(dir_fd, 0);

  int fd = OpenatForGuest(dir_fd, "maps", O_RDONLY, 0);
  ASSERT_GE(fd, 0) << strerror(errno);
  EXPECT_FALSE(IsFileDescriptorEmulatedProcSelfMaps(fd));
  EXPECT_EQ("plain", ReadAll(fd));
  CloseGuestFd(fd);

  close(dir_fd);
  unlink(file.c_str());
  rmdir(dir.c_str());
}

TEST_F(OpenProcSelfRelativeTest, OpenatMissingRelativeFileFailsLikeTheHost) {
  EXPECT_EQ(ENOENT,
            FailureErrno([&] { return OpenatForGuest(self_dir_, "no-such-file", O_RDONLY, 0); }));
}

// The main executable link is faked for readlink so a guest finds files next
// to its program. The dirfd-relative spellings must be faked as well.
class MainExecutableLinkTest : public OpenProcSelfRelativeTest {
 protected:
  void SetUp() override {
    OpenProcSelfRelativeTest::SetUp();
    saved_path_ = GetMainExecutableRealPath();
    SetMainExecutableRealPath(kGuestMain);
  }

  void TearDown() override {
    *GetMainExecutableRealPathPointer() = saved_path_;
    OpenProcSelfRelativeTest::TearDown();
  }

  static constexpr const char* kGuestMain = "/data/app/guest/main_program";
  const char* saved_path_ = nullptr;
};

TEST_F(MainExecutableLinkTest, ReadLinkOfProcSelfExeIsTheGuestProgram) {
  char buf[256];
  ssize_t n = ReadLinkAtForGuest(AT_FDCWD, "/proc/self/exe", buf, sizeof(buf));
  ASSERT_EQ(static_cast<ssize_t>(strlen(kGuestMain)), n);
  EXPECT_EQ(kGuestMain, std::string(buf, static_cast<size_t>(n)));
}

TEST_F(MainExecutableLinkTest, ReadLinkRelativeToProcSelfDirectoryIsTheGuestProgram) {
  char buf[256];
  ssize_t n = ReadLinkAtForGuest(self_dir_, "exe", buf, sizeof(buf));
  ASSERT_EQ(static_cast<ssize_t>(strlen(kGuestMain)), n) << strerror(errno);
  EXPECT_EQ(kGuestMain, std::string(buf, static_cast<size_t>(n)));

  n = ReadLinkAtForGuest(proc_dir_, "self/exe", buf, sizeof(buf));
  ASSERT_EQ(static_cast<ssize_t>(strlen(kGuestMain)), n) << strerror(errno);
  EXPECT_EQ(kGuestMain, std::string(buf, static_cast<size_t>(n)));
}

TEST_F(MainExecutableLinkTest, OtherRelativeLinkIsNotFaked) {
  char buf[256];
  // /proc/self/cwd is a link too, but not the main executable.
  ssize_t n = ReadLinkAtForGuest(self_dir_, "cwd", buf, sizeof(buf));
  ASSERT_GT(n, 0) << strerror(errno);
  EXPECT_NE(kGuestMain, std::string(buf, static_cast<size_t>(n)));
}

TEST_F(MainExecutableLinkTest, RealPathLookupUsesTheDirectoryDescriptor) {
  EXPECT_STREQ(kGuestMain, TryReadLinkToMainExecutableRealPath(AT_FDCWD, "/proc/self/exe"));
  EXPECT_STREQ(kGuestMain, TryReadLinkToMainExecutableRealPath(self_dir_, "exe"));
  EXPECT_STREQ(kGuestMain, TryReadLinkToMainExecutableRealPath(proc_dir_, "self/exe"));
  EXPECT_EQ(nullptr, TryReadLinkToMainExecutableRealPath(self_dir_, "cwd"));
  // "exe" in the current directory is not /proc/self/exe.
  EXPECT_EQ(nullptr, TryReadLinkToMainExecutableRealPath(AT_FDCWD, "exe"));
}

// openat2 reaches the same files as openat and must not bypass the emulation.
class Openat2ProcSelfTest : public OpenProcSelfRelativeTest {
 protected:
  static int Openat2(int dirfd, const char* path, uint64_t flags, uint64_t resolve = 0) {
    OpenHow how = {flags, 0, resolve};
    return Openat2ForGuest(dirfd, path, &how, sizeof(how));
  }
};

TEST_F(Openat2ProcSelfTest, AbsolutePathServesGuestMaps) {
  ExpectGuestMaps(Openat2(AT_FDCWD, "/proc/self/maps", O_RDONLY), "openat2 absolute path");
}

TEST_F(Openat2ProcSelfTest, RelativePathsServeGuestMaps) {
  ExpectGuestMaps(Openat2(self_dir_, "maps", O_RDONLY), "openat2(selffd, \"maps\")");
  ExpectGuestMaps(Openat2(self_dir_, "./maps", O_RDONLY), "openat2(selffd, \"./maps\")");
  ExpectGuestMaps(Openat2(proc_dir_, "self/maps", O_RDONLY), "openat2(procfd, \"self/maps\")");
}

TEST_F(Openat2ProcSelfTest, CpuinfoServesGuestCpuinfo) {
  ExpectGuestCpuinfo(Openat2(AT_FDCWD, "/proc/cpuinfo", O_RDONLY), "openat2 absolute path");
  ExpectGuestCpuinfo(Openat2(proc_dir_, "cpuinfo", O_RDONLY), "openat2(procfd, \"cpuinfo\")");
}

TEST_F(Openat2ProcSelfTest, EmulatedMapsIsCloseOnExec) {
  int fd = Openat2(self_dir_, "maps", O_RDONLY | O_CLOEXEC);
  ASSERT_GE(fd, 0) << strerror(errno);
  EXPECT_NE(0, fcntl(fd, F_GETFD) & FD_CLOEXEC);
  CloseGuestFd(fd);
}

TEST_F(Openat2ProcSelfTest, OtherFileStaysHostOpen) {
  int fd = Openat2(self_dir_, "status", O_RDONLY);
  ASSERT_GE(fd, 0) << strerror(errno);
  EXPECT_FALSE(IsFileDescriptorEmulatedProcSelfMaps(fd));
  EXPECT_EQ(0u, ReadAll(fd).find("Name:"));
  CloseGuestFd(fd);
}

TEST_F(Openat2ProcSelfTest, GuestOpenFlagsAreTranslatedForTheHost) {
  // Guest (arm64) O_DIRECTORY is the host's O_DIRECT bit. Passed on unchanged,
  // the host rejects the open of a directory.
  const uint64_t guest_dir_flags = static_cast<uint64_t>(ToGuestOpenFlags(O_RDONLY | O_DIRECTORY));
  int fd = Openat2(AT_FDCWD, "/proc/self", guest_dir_flags);
  ASSERT_GE(fd, 0) << strerror(errno);
  struct stat st;
  ASSERT_EQ(0, fstat(fd, &st));
  EXPECT_TRUE(S_ISDIR(st.st_mode));
  close(fd);

  // And a plain file is refused as a non-directory when the guest asks for one.
  EXPECT_EQ(ENOTDIR,
            FailureErrno([&] { return Openat2(AT_FDCWD, "/proc/self/status", guest_dir_flags); }));
}

TEST_F(Openat2ProcSelfTest, HostResolveRulesStillApplyToOtherFiles) {
  // /proc/self is a symlink: RESOLVE_NO_SYMLINKS must refuse to walk it.
  constexpr uint64_t kResolveNoSymlinks = 0x04;
  EXPECT_EQ(ELOOP, FailureErrno([&] {
              return Openat2(proc_dir_, "self/status", O_RDONLY, kResolveNoSymlinks);
            }));
}

// The resolve restrictions of openat2 decide what a path names (or whether it names anything), so
// the emulated views may be served only to a path the host kernel would resolve to the real file
// under the same restrictions. Each case compares with a host openat2 given the same arguments, so
// the tests do not hardcode what the kernel answers.
class Openat2ResolveTest : public Openat2ProcSelfTest {
 protected:
  static constexpr uint64_t kResolveNoXdev = 0x01;
  static constexpr uint64_t kResolveNoSymlinks = 0x04;
  static constexpr uint64_t kResolveBeneath = 0x08;
  static constexpr uint64_t kResolveInRoot = 0x10;
  static constexpr long kSysOpenat2 = 437;

  void SetUp() override {
    Openat2ProcSelfTest::SetUp();
    char dir_template[] = "/tmp/openat2_resolve_XXXXXX";
    ASSERT_NE(nullptr, mkdtemp(dir_template)) << strerror(errno);
    empty_dir_path_ = dir_template;
    empty_dir_ = open(dir_template, O_RDONLY | O_DIRECTORY);
    ASSERT_GE(empty_dir_, 0) << strerror(errno);
  }

  void TearDown() override {
    if (empty_dir_ >= 0) {
      close(empty_dir_);
    }
    // A test may have created a file in the directory.
    unlink((empty_dir_path_ + "/created").c_str());
    rmdir(empty_dir_path_.c_str());
    Openat2ProcSelfTest::TearDown();
  }

  // What the host kernel makes of the same openat2: a descriptor, or -1 with errno set.
  static int HostOpenat2(int dirfd, const char* path, uint64_t flags, uint64_t resolve) {
    OpenHow how = {flags, 0, resolve};
    return static_cast<int>(syscall(kSysOpenat2, dirfd, path, &how, sizeof(how)));
  }

  static bool HostHasOpenat2() {
    errno = 0;
    const int fd = HostOpenat2(AT_FDCWD, "/proc/self", O_RDONLY, 0);
    if (fd >= 0) {
      close(fd);
      return true;
    }
    return errno != ENOSYS;
  }

  // Expects the guest's openat2 of `path` to fail with `expected_errno`, the very error that a host
  // openat2 with the same arguments gives, and not to hand out any descriptor.
  void ExpectFailsLikeTheHost(int dirfd, const char* path, uint64_t resolve, int expected_errno) {
    if (!HostHasOpenat2()) {
      GTEST_SKIP() << "the host kernel has no openat2";
    }
    errno = 0;
    const int host_fd = HostOpenat2(dirfd, path, O_RDONLY, resolve);
    const int host_errno = errno;
    if (host_fd >= 0) {
      close(host_fd);
    }
    ASSERT_EQ(-1, host_fd) << "the host kernel opens " << path << " with resolve " << resolve;
    ASSERT_EQ(expected_errno, host_errno) << "the host kernel's answer is not what this test assumes";

    errno = 0;
    const int fd = Openat2(dirfd, path, O_RDONLY, resolve);
    const int guest_errno = errno;
    if (fd >= 0) {
      const bool emulated = IsFileDescriptorEmulatedProcSelfMaps(fd);
      CloseGuestFd(fd);
      FAIL() << "openat2(" << path << ", resolve " << resolve << ") returned a descriptor"
             << (emulated ? " for the emulated maps view" : "") << " where the host fails with "
             << strerror(host_errno);
    }
    EXPECT_EQ(host_errno, guest_errno);
  }

  std::string empty_dir_path_;
  int empty_dir_ = -1;
};

TEST_F(Openat2ResolveTest, MapsThroughASymlinkFailsWithNoSymlinks) {
  // /proc/self is a symlink.
  ExpectFailsLikeTheHost(AT_FDCWD, "/proc/self/maps", kResolveNoSymlinks, ELOOP);
}

TEST_F(Openat2ResolveTest, MapsByAbsolutePathFailsWithBeneath) {
  ExpectFailsLikeTheHost(AT_FDCWD, "/proc/self/maps", kResolveBeneath, EXDEV);
}

TEST_F(Openat2ResolveTest, MapsInRootOfAnEmptyDirectoryIsNotFound) {
  // Under RESOLVE_IN_ROOT an absolute path starts at dirfd, not at the real root.
  ExpectFailsLikeTheHost(empty_dir_, "/proc/self/maps", kResolveInRoot, ENOENT);
}

TEST_F(Openat2ResolveTest, MapsRelativeToProcSelfServedWithBeneathAndNoXdev) {
  ExpectGuestMaps(Openat2(self_dir_, "maps", O_RDONLY, kResolveBeneath | kResolveNoXdev),
                  "openat2(selffd, \"maps\", BENEATH | NO_XDEV)");
  ExpectGuestMaps(Openat2(self_dir_, "maps", O_RDONLY, 0), "openat2(selffd, \"maps\")");
}

TEST_F(Openat2ResolveTest, CpuinfoThroughASymlinkFailsWithNoSymlinks) {
  // "self" is a symlink, and ".." of the process directory is /proc again.
  ExpectFailsLikeTheHost(AT_FDCWD, "/proc/self/../cpuinfo", kResolveNoSymlinks, ELOOP);
}

TEST_F(Openat2ResolveTest, CpuinfoByAbsolutePathFailsWithBeneath) {
  ExpectFailsLikeTheHost(AT_FDCWD, "/proc/cpuinfo", kResolveBeneath, EXDEV);
}

TEST_F(Openat2ResolveTest, CpuinfoInRootOfAnEmptyDirectoryIsNotFound) {
  ExpectFailsLikeTheHost(empty_dir_, "/proc/cpuinfo", kResolveInRoot, ENOENT);
}

TEST_F(Openat2ResolveTest, CpuinfoRelativeToProcServedWithBeneathAndNoXdev) {
  ExpectGuestCpuinfo(Openat2(proc_dir_, "cpuinfo", O_RDONLY, kResolveBeneath | kResolveNoXdev),
                     "openat2(procfd, \"cpuinfo\", BENEATH | NO_XDEV)");
}

TEST_F(Openat2ResolveTest, OtherFileStaysHostOpenUnderResolveRestrictions) {
  int fd = Openat2(self_dir_, "status", O_RDONLY, kResolveBeneath | kResolveNoXdev);
  ASSERT_GE(fd, 0) << strerror(errno);
  EXPECT_FALSE(IsFileDescriptorEmulatedProcSelfMaps(fd));
  EXPECT_EQ(0u, ReadAll(fd).find("Name:"));
  CloseGuestFd(fd);
}

TEST_F(Openat2ResolveTest, CreatingAFileUnderResolveRestrictionsStillWorks) {
  // The file does not exist yet, so nothing can be looked up first to decide on emulation.
  OpenHow how = {O_WRONLY | O_CREAT | O_EXCL, 0600, kResolveBeneath};
  const int fd = Openat2ForGuest(empty_dir_, "created", &how, sizeof(how));
  ASSERT_GE(fd, 0) << strerror(errno);
  EXPECT_FALSE(IsFileDescriptorEmulatedProcSelfMaps(fd));
  close(fd);
  struct stat st;
  EXPECT_EQ(0, fstatat(empty_dir_, "created", &st, 0));
}

TEST_F(Openat2ProcSelfTest, RejectsMalformedHowLikeTheKernel) {
  constexpr const char* kPath = "/proc/self/maps";
  OpenHow how = {O_RDONLY, 0, 0};
  EXPECT_EQ(EINVAL, FailureErrno([&] {
              return Openat2ForGuest(AT_FDCWD, kPath, &how, kOpenHowSizeVer0 - 1);
            }));
  EXPECT_EQ(EFAULT, FailureErrno([&] {
              return Openat2ForGuest(AT_FDCWD, kPath, nullptr, kOpenHowSizeVer0);
            }));

  // A larger struct is accepted only if its extra bytes are zero.
  std::vector<unsigned char> bigger(kOpenHowSizeVer0 + 8, 0);
  memcpy(bigger.data(), &how, sizeof(how));
  bigger.back() = 1;
  EXPECT_EQ(E2BIG, FailureErrno([&] {
              return Openat2ForGuest(AT_FDCWD, kPath, bigger.data(), bigger.size());
            }));

  // Flags above the 32 bits of an open flag word are invalid.
  OpenHow wide = {uint64_t{1} << 32, 0, 0};
  EXPECT_EQ(EINVAL,
            FailureErrno([&] { return Openat2ForGuest(AT_FDCWD, kPath, &wide, sizeof(wide)); }));

  // Unknown resolve bits are invalid.
  OpenHow bad_resolve = {O_RDONLY, 0, uint64_t{1} << 20};
  EXPECT_EQ(EINVAL, FailureErrno([&] {
              return Openat2ForGuest(AT_FDCWD, kPath, &bad_resolve, sizeof(bad_resolve));
            }));

  // A mode is only valid together with O_CREAT.
  OpenHow bad_mode = {O_RDONLY, 0600, 0};
  EXPECT_EQ(EINVAL, FailureErrno([&] {
              return Openat2ForGuest(AT_FDCWD, kPath, &bad_mode, sizeof(bad_mode));
            }));
}

TEST_F(Openat2ProcSelfTest, AcceptsZeroExtendedHow) {
  OpenHow how = {O_RDONLY, 0, 0};
  std::vector<unsigned char> bigger(kOpenHowSizeVer0 + 8, 0);
  memcpy(bigger.data(), &how, sizeof(how));
  ExpectGuestMaps(Openat2ForGuest(AT_FDCWD, "/proc/self/maps", bigger.data(), bigger.size()),
                  "openat2 with a zero-extended struct");
}

// Translated code reaches the open emulation through the syscall table, not by calling
// OpenatForGuest or Openat2ForGuest, so check the table routes both syscalls to it.
class GuestSyscallDispatchTest : public OpenProcSelfRelativeTest {
 protected:
  static constexpr uint64_t kGuestNrOpenat = 56;   // asm-generic __NR_openat
  static constexpr uint64_t kGuestNrOpenat2 = 437;

  // Runs the guest syscall `nr` on a guest thread of its own and returns what the guest sees in
  // x0: the descriptor, or the negated errno.
  static long RunSyscall(uint64_t nr, uint64_t arg_0, uint64_t arg_1, uint64_t arg_2,
                         uint64_t arg_3) {
    long result = -ENOSYS;
    std::thread worker([&] {
      ThreadState state{};
      GuestThread* guest_thread = GuestThread::CreateForTest(&state);
      if (guest_thread == nullptr) {
        return;
      }
      state.thread = guest_thread;
      state.cpu.x[0] = arg_0;
      state.cpu.x[1] = arg_1;
      state.cpu.x[2] = arg_2;
      state.cpu.x[3] = arg_3;
      state.cpu.x[8] = nr;
      RunGuestSyscall(&state);
      result = static_cast<long>(state.cpu.x[0]);
      GuestThread::Destroy(guest_thread);
    });
    worker.join();
    return result;
  }
};

TEST_F(GuestSyscallDispatchTest, OpenatServesGuestMapsRelativeToADirectory) {
  const long fd = RunSyscall(kGuestNrOpenat,
                             static_cast<uint64_t>(self_dir_),
                             reinterpret_cast<uint64_t>("./maps"),
                             static_cast<uint64_t>(ToGuestOpenFlags(O_RDONLY)),
                             0);
  ExpectGuestMaps(static_cast<int>(fd), "guest openat(selffd, \"./maps\")");
}

TEST_F(GuestSyscallDispatchTest, Openat2ServesGuestMapsRelativeToADirectory) {
  OpenHow how = {static_cast<uint64_t>(ToGuestOpenFlags(O_RDONLY)), 0, 0};
  const long fd = RunSyscall(kGuestNrOpenat2,
                             static_cast<uint64_t>(self_dir_),
                             reinterpret_cast<uint64_t>("./maps"),
                             reinterpret_cast<uint64_t>(&how),
                             sizeof(how));
  ExpectGuestMaps(static_cast<int>(fd), "guest openat2(selffd, \"./maps\")");
}

TEST_F(GuestSyscallDispatchTest, Openat2ServesGuestCpuinfoRelativeToProc) {
  OpenHow how = {static_cast<uint64_t>(ToGuestOpenFlags(O_RDONLY)), 0, 0};
  const long fd = RunSyscall(kGuestNrOpenat2,
                             static_cast<uint64_t>(proc_dir_),
                             reinterpret_cast<uint64_t>("cpuinfo"),
                             reinterpret_cast<uint64_t>(&how),
                             sizeof(how));
  ExpectGuestCpuinfo(static_cast<int>(fd), "guest openat2(procfd, \"cpuinfo\")");
}

TEST_F(GuestSyscallDispatchTest, Openat2ReportsTheKernelsErrorForAMalformedStruct) {
  OpenHow how = {O_RDONLY, 0, 0};
  EXPECT_EQ(-EINVAL,
            RunSyscall(kGuestNrOpenat2,
                       static_cast<uint64_t>(AT_FDCWD),
                       reinterpret_cast<uint64_t>("/proc/self/maps"),
                       reinterpret_cast<uint64_t>(&how),
                       kOpenHowSizeVer0 - 1));
}

}  // namespace

}  // namespace berberis
