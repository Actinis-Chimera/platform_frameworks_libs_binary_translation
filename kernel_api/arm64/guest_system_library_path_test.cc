// SPDX-FileCopyrightText: 2026 Actinis OÜ
// SPDX-License-Identifier: EUPL-1.2

// A guest that opens an Android system library by its canonical path gets the
// guest's arm64 copy of it. On the x86_64 host image /system/lib64 and the
// runtime APEX's bionic directory hold the host's x86_64 libraries, and the
// arm64 ones live in /system/lib64/arm64. A guest that loads a library itself,
// reading its ELF header and segments instead of calling dlopen, otherwise
// reads a library of the wrong machine and gives up on it.

#include "gtest/gtest.h"

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "berberis/kernel_api/open_emulation.h"

namespace berberis {

namespace {

class GuestSystemLibraryPathTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ::testing::Test::SetUp();
    char dir_template[] = "/tmp/berberis-guest-lib-XXXXXX";
    ASSERT_NE(nullptr, mkdtemp(dir_template));
    guest_dir_ = dir_template;
  }

  void TearDown() override {
    for (const auto& path : created_) {
      unlink(path.c_str());
    }
    rmdir(guest_dir_.c_str());
    ::testing::Test::TearDown();
  }

  // A library named `name` in the guest library directory.
  std::string AddGuestLibrary(const char* name) {
    const auto path = guest_dir_ + "/" + name;
    const auto fd = open(path.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
    EXPECT_GE(fd, 0);
    close(fd);
    created_.push_back(path);
    return path;
  }

  std::string For(const char* path) const {
    return GuestSystemLibraryPathFor(path, guest_dir_.c_str());
  }

  std::string guest_dir_;
  std::vector<std::string> created_;
};

TEST_F(GuestSystemLibraryPathTest, SystemLibraryOpensTheGuestCopy) {
  const auto guest_libz = AddGuestLibrary("libz.so");
  EXPECT_EQ(guest_libz, For("/system/lib64/libz.so"));
}

TEST_F(GuestSystemLibraryPathTest, RuntimeApexBionicLibraryOpensTheGuestCopy) {
  const auto guest_libc = AddGuestLibrary("libc.so");
  const auto guest_libz = AddGuestLibrary("libz.so");
  EXPECT_EQ(guest_libc, For("/apex/com.android.runtime/lib64/bionic/libc.so"));
  // The host image links more than libc, libdl and libm here; the guest copy
  // of each one is found the same way.
  EXPECT_EQ(guest_libz, For("/apex/com.android.runtime/lib64/bionic/libz.so"));
}

// A host library without an arm64 copy keeps its path, and the guest opens
// what the host image has, as before.
TEST_F(GuestSystemLibraryPathTest, LibraryWithoutGuestCopyKeepsItsPath) {
  AddGuestLibrary("libz.so");
  EXPECT_EQ("", For("/system/lib64/libdrion_host_only.so"));
}

// Only a library directly in one of the two directories is the host's: the
// guest directory itself, hw/ and other subdirectories, the 32-bit directory,
// other partitions and relative paths are left alone.
TEST_F(GuestSystemLibraryPathTest, OtherPathsKeepTheirPath) {
  AddGuestLibrary("libz.so");
  EXPECT_EQ("", For("/system/lib64/arm64/libz.so"));
  EXPECT_EQ("", For("/system/lib64/hw/libz.so"));
  EXPECT_EQ("", For("/system/lib64/../lib64/libz.so"));
  EXPECT_EQ("", For("/system/lib/libz.so"));
  EXPECT_EQ("", For("/vendor/lib64/libz.so"));
  EXPECT_EQ("", For("/system/lib64libz.so"));
  EXPECT_EQ("", For("system/lib64/libz.so"));
  EXPECT_EQ("", For("/apex/com.android.runtime/lib64/libz.so"));
  EXPECT_EQ("", For("/apex/com.android.art/lib64/bionic/libz.so"));
}

TEST_F(GuestSystemLibraryPathTest, DirectoryAndEmptyNamesKeepTheirPath) {
  AddGuestLibrary("libz.so");
  EXPECT_EQ("", For("/system/lib64/"));
  EXPECT_EQ("", For("/system/lib64/."));
  EXPECT_EQ("", For("/system/lib64/.."));
  EXPECT_EQ("", For(nullptr));
}

// A guest directory entry that is not a regular file is not a library.
TEST_F(GuestSystemLibraryPathTest, GuestDirectoryEntryMustBeAFile) {
  const auto subdir = guest_dir_ + "/libdir.so";
  ASSERT_EQ(0, mkdir(subdir.c_str(), 0755));
  EXPECT_EQ("", For("/system/lib64/libdir.so"));
  rmdir(subdir.c_str());
}

}  // namespace

}  // namespace berberis
