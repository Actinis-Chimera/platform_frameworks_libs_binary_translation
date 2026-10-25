// SPDX-FileCopyrightText: 2026 Actinis OÜ
// SPDX-License-Identifier: EUPL-1.2

// The guest's /proc/self/maps hides host images. A file the host has mapped
// with host-executable code is an x86_64 library or executable that the arm64
// guest cannot run and that an arm64 device would not have. Its in-memory
// headers are the host loader's: glibc relocates the d_ptr entries of a
// library's .dynamic in place, bionic does not. A guest integrity check that
// walks the maps, finds a host library under an Android name and parses its
// dynamic section adds the load bias a second time and faults on a
// non-canonical address. The view therefore drops every line of such a file,
// its read-only header and data lines included. A file that also holds guest
// code, and every file mapped without host code, stays.

#include "gtest/gtest.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include "berberis/base/fd.h"
#include "berberis/guest_os_primitives/guest_map_shadow.h"
#include "berberis/guest_state/guest_addr.h"
#include "berberis/kernel_api/open_emulation.h"

namespace berberis {

namespace {

struct MapsLine {
  uintptr_t start;
  uintptr_t end;
  std::string perms;
  unsigned dev_major;
  unsigned dev_minor;
  uint64_t inode;
};

std::vector<MapsLine> ParseMaps(const std::string& maps) {
  std::vector<MapsLine> lines;
  size_t pos = 0;
  while (pos < maps.size()) {
    size_t eol = maps.find('\n', pos);
    if (eol == std::string::npos) {
      eol = maps.size();
    }
    const auto text = maps.substr(pos, eol - pos);
    pos = eol + 1;
    MapsLine line{};
    char perms[8] = {};
    uint64_t offset = 0;
    if (sscanf(text.c_str(),
               "%" SCNxPTR "-%" SCNxPTR " %7s %" SCNx64 " %x:%x %" SCNu64,
               &line.start,
               &line.end,
               perms,
               &offset,
               &line.dev_major,
               &line.dev_minor,
               &line.inode) == 7) {
      line.perms = perms;
      lines.push_back(line);
    }
  }
  return lines;
}

std::string ReadAll(int fd) {
  std::string content;
  char buf[4096];
  ssize_t n;
  while ((n = read(fd, buf, sizeof(buf))) > 0) {
    content.append(buf, static_cast<size_t>(n));
  }
  return content;
}

std::vector<MapsLine> HostMaps() {
  const auto fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
  EXPECT_GE(fd, 0);
  const auto content = ReadAll(fd);
  close(fd);
  return ParseMaps(content);
}

std::vector<MapsLine> GuestMaps() {
  const auto fd = OpenatForGuest(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
  EXPECT_GE(fd, 0);
  const auto content = ReadAll(fd);
  CloseEmulatedProcSelfMapsFileDescriptor(fd);
  close(fd);
  return ParseMaps(content);
}

// The file a maps line maps, as the maps print it: its device and inode.
struct MappedFile {
  unsigned dev_major;
  unsigned dev_minor;
  uint64_t inode;
};

MappedFile FileOf(const MapsLine& line) {
  return {line.dev_major, line.dev_minor, line.inode};
}

// The identity /proc/self/maps prints for an open file. The maps print the
// superblock's device, which is what fstat reports for a memfd; for a file on
// btrfs or overlayfs fstat reports another device, so a test about such a file
// takes its identity from a maps line instead (FileOf).
MappedFile FileOf(int fd) {
  struct stat st{};
  EXPECT_EQ(0, fstat(fd, &st));
  return {major(st.st_dev), minor(st.st_dev), st.st_ino};
}

std::vector<MapsLine> LinesOf(const std::vector<MapsLine>& maps, const MappedFile& file) {
  std::vector<MapsLine> lines;
  for (const auto& line : maps) {
    if (line.inode == file.inode && line.dev_major == file.dev_major &&
        line.dev_minor == file.dev_minor) {
      lines.push_back(line);
    }
  }
  return lines;
}

// The line of `maps` that covers `addr`, or nullptr when none does.
const MapsLine* LineCovering(const std::vector<MapsLine>& maps, uintptr_t addr) {
  for (const auto& line : maps) {
    if (line.start <= addr && addr < line.end) {
      return &line;
    }
  }
  return nullptr;
}

bool HasHostExecutableLine(const std::vector<MapsLine>& lines) {
  for (const auto& line : lines) {
    if (line.perms.size() > 2 && line.perms[2] == 'x') {
      return true;
    }
  }
  return false;
}

// A host function: its address lies in the test binary's host code.
__attribute__((noinline)) int HostCodeMarker() {
  return 0;
}

class ProcSelfMapsHostImageTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ::testing::Test::SetUp();
    page_size_ = static_cast<size_t>(getpagesize());
  }

  void TearDown() override {
    for (auto& [addr, size] : mappings_) {
      GuestMapShadow::GetInstance()->ClearExecutable(ToGuestAddr(addr), size);
      munmap(addr, size);
    }
    for (int fd : fds_) {
      close(fd);
    }
    ::testing::Test::TearDown();
  }

  // A file of `pages` pages that lives as long as the test.
  int NewFile(const char* name, size_t pages) {
    const auto fd = CreateMemfdOrDie(name);
    FtruncateOrDie(fd, static_cast<off64_t>(pages * page_size_));
    fds_.push_back(fd);
    return fd;
  }

  void* Map(int fd, size_t page, int prot) {
    void* addr = mmap(
        nullptr, page_size_, prot, MAP_PRIVATE, fd, static_cast<off_t>(page * page_size_));
    EXPECT_NE(MAP_FAILED, addr);
    mappings_.emplace_back(addr, page_size_);
    return addr;
  }

  size_t page_size_ = 0;
  std::vector<std::pair<void*, size_t>> mappings_;
  std::vector<int> fds_;
};

// The x86_64 image holding this test's code: the shape of every host library.
TEST_F(ProcSelfMapsHostImageTest, OwnHostImageIsHidden) {
  const auto host_maps = HostMaps();
  const auto marker = reinterpret_cast<uintptr_t>(&HostCodeMarker);
  const auto* marker_line = LineCovering(host_maps, marker);
  ASSERT_NE(nullptr, marker_line);
  ASSERT_NE(0u, marker_line->inode);
  const auto image = FileOf(*marker_line);
  const auto host_lines = LinesOf(host_maps, image);
  ASSERT_TRUE(HasHostExecutableLine(host_lines));

  const auto guest_maps = GuestMaps();
  EXPECT_TRUE(LinesOf(guest_maps, image).empty())
      << "the guest view lists " << LinesOf(guest_maps, image).size()
      << " lines of the host image";
  EXPECT_EQ(nullptr, LineCovering(guest_maps, marker));
  // The image's first line holds the ELF header a parser starts from.
  EXPECT_EQ(nullptr, LineCovering(guest_maps, host_lines.front().start));
}

TEST_F(ProcSelfMapsHostImageTest, HostCodeFileIsHiddenWithItsDataLines) {
  const auto fd = NewFile("host-image", 2);
  void* header = Map(fd, 0, PROT_READ);
  void* code = Map(fd, 1, PROT_READ | PROT_EXEC);

  const auto guest_maps = GuestMaps();
  EXPECT_EQ(nullptr, LineCovering(guest_maps, reinterpret_cast<uintptr_t>(code)));
  EXPECT_EQ(nullptr, LineCovering(guest_maps, reinterpret_cast<uintptr_t>(header)));
  EXPECT_TRUE(LinesOf(guest_maps, FileOf(fd)).empty());
}

TEST_F(ProcSelfMapsHostImageTest, FileWithoutHostCodeStaysVisible) {
  const auto fd = NewFile("guest-data", 1);
  void* data = Map(fd, 0, PROT_READ);

  const auto guest_maps = GuestMaps();
  const auto* line = LineCovering(guest_maps, reinterpret_cast<uintptr_t>(data));
  ASSERT_NE(nullptr, line);
  EXPECT_EQ("r--p", line->perms);
  EXPECT_EQ(1u, LinesOf(guest_maps, FileOf(fd)).size());
}

// A guest JIT may map one file twice, writable and as guest code. If the host
// has also mapped part of it as code, the file is still the guest's.
TEST_F(ProcSelfMapsHostImageTest, FileWithGuestCodeStaysVisible) {
  const auto fd = NewFile("shared-code", 2);
  void* guest_code = Map(fd, 0, PROT_READ);
  GuestMapShadow::GetInstance()->SetExecutable(ToGuestAddr(guest_code), page_size_);
  void* host_code = Map(fd, 1, PROT_READ | PROT_EXEC);

  const auto guest_maps = GuestMaps();
  const auto* guest_line = LineCovering(guest_maps, reinterpret_cast<uintptr_t>(guest_code));
  ASSERT_NE(nullptr, guest_line);
  EXPECT_EQ("r-xp", guest_line->perms);
  const auto* host_line = LineCovering(guest_maps, reinterpret_cast<uintptr_t>(host_code));
  ASSERT_NE(nullptr, host_line);
  EXPECT_EQ("r--p", host_line->perms);
}

// Anonymous host code (the translator's code cache, the vdso) is not a file a
// guest can parse as an image, and its lines were always shown non-executable.
TEST_F(ProcSelfMapsHostImageTest, AnonymousHostCodeStaysVisible) {
  void* code = mmap(
      nullptr, page_size_, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(MAP_FAILED, code);
  mappings_.emplace_back(code, page_size_);

  const auto* line = LineCovering(GuestMaps(), reinterpret_cast<uintptr_t>(code));
  ASSERT_NE(nullptr, line);
  EXPECT_EQ("r--p", line->perms);
}

}  // namespace

}  // namespace berberis
