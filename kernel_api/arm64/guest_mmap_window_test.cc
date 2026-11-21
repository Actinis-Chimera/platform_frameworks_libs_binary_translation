// SPDX-FileCopyrightText: 2026 Actinis OÜ
// SPDX-License-Identifier: EUPL-1.2

// A guest mmap that leaves the address to the kernel must get an address an
// arm64 Android device could return: below 2^39. Guest allocators that check
// their blocks against that range otherwise fail every allocation.

#include "gtest/gtest.h"

#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "berberis/kernel_api/sys_mman_emulation.h"

#include "guest_mmap_window.h"

namespace berberis {

namespace {

constexpr uintptr_t kTestPage = 0x1000;

size_t PageSize() {
  return static_cast<size_t>(getpagesize());
}

uintptr_t AsAddr(void* ptr) {
  return reinterpret_cast<uintptr_t>(ptr);
}

bool InWindow(void* ptr, size_t length) {
  uintptr_t addr = AsAddr(ptr);
  return addr >= kGuestMmapWindowBegin && addr + length <= kGuestMmapWindowEnd;
}

void* MapAnon(void* addr, size_t length, int flags = 0) {
  return MmapForGuest(
      addr, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | flags, -1, 0);
}

TEST(GuestMmapWindowGap, EmptyWindowTakesTheTop) {
  EXPECT_EQ(0x9000u, FindHighestGuestMmapGap(nullptr, 0, 0x1000, 0xa000, kTestPage));
}

TEST(GuestMmapWindowGap, SkipsRangesAboveTheLimitAndFindsTheGapBelowATakenOne) {
  GuestMmapRange ranges[] = {{0x6000, 0x8000}, {0xb000, 0xc000}};
  EXPECT_EQ(0x5000u, FindHighestGuestMmapGap(ranges, 2, 0x1000, 0x8000, kTestPage));
  EXPECT_EQ(0x9000u, FindHighestGuestMmapGap(ranges, 2, 0x1000, 0xa000, kTestPage));
}

TEST(GuestMmapWindowGap, RangeStraddlingTheLimitMovesTheGapBelowIt) {
  GuestMmapRange ranges[] = {{0x7000, 0xc000}};
  EXPECT_EQ(0x5000u, FindHighestGuestMmapGap(ranges, 1, 0x1000, 0xa000, 2 * kTestPage));
}

TEST(GuestMmapWindowGap, TooSmallGapsAreSkipped) {
  GuestMmapRange ranges[] = {{0x2000, 0x4000}, {0x5000, 0x9000}};
  EXPECT_EQ(0u, FindHighestGuestMmapGap(ranges, 2, 0x1000, 0x9000, 2 * kTestPage));
  EXPECT_EQ(0x4000u, FindHighestGuestMmapGap(ranges, 2, 0x1000, 0x9000, kTestPage));
}

TEST(GuestMmapWindowGap, GapClippedByTheWindowBegin) {
  GuestMmapRange ranges[] = {{0x0, 0x2000}, {0x3000, 0x9000}};
  EXPECT_EQ(0u, FindHighestGuestMmapGap(ranges, 2, 0x2800, 0x9000, kTestPage));
  EXPECT_EQ(0x2000u, FindHighestGuestMmapGap(ranges, 2, 0x2000, 0x9000, kTestPage));
}

TEST(GuestMmapWindowGap, RequestsLargerThanTheWindowFail) {
  EXPECT_EQ(0u, FindHighestGuestMmapGap(nullptr, 0, 0x1000, 0x3000, 3 * kTestPage));
  EXPECT_EQ(0u, FindHighestGuestMmapGap(nullptr, 0, 0x3000, 0x1000, kTestPage));
  EXPECT_EQ(0u, FindHighestGuestMmapGap(nullptr, 0, 0x1000, 0x3000, 0));
}

TEST(GuestMmapWindowPolicy, OnlyKernelPlacedRequestsMove) {
  EXPECT_TRUE(ShouldPlaceInGuestMmapWindow(nullptr, MAP_PRIVATE));
  EXPECT_TRUE(ShouldPlaceInGuestMmapWindow(reinterpret_cast<void*>(kGuestMmapWindowEnd), 0));
  EXPECT_FALSE(ShouldPlaceInGuestMmapWindow(reinterpret_cast<void*>(kGuestMmapWindowBegin), 0));
  EXPECT_FALSE(ShouldPlaceInGuestMmapWindow(nullptr, MAP_FIXED));
  EXPECT_FALSE(ShouldPlaceInGuestMmapWindow(
      reinterpret_cast<void*>(kGuestMmapWindowEnd + PageSize()), MAP_FIXED_NOREPLACE));
}

TEST(GuestMmapWindow, AnonymousMappingLandsBelowTheDeviceCeiling) {
  size_t length = 16 * PageSize();
  void* ptr = MapAnon(nullptr, length);
  ASSERT_NE(MAP_FAILED, ptr);
  EXPECT_TRUE(InWindow(ptr, length)) << ptr;
  memset(ptr, 0x5a, length);
  EXPECT_EQ(0x5a, static_cast<uint8_t*>(ptr)[length - 1]);
  ASSERT_EQ(0, MunmapForGuest(ptr, length));
}

TEST(GuestMmapWindow, UnalignedLengthIsMappedWhole) {
  size_t length = PageSize() + 1;
  void* ptr = MapAnon(nullptr, length);
  ASSERT_NE(MAP_FAILED, ptr);
  EXPECT_TRUE(InWindow(ptr, 2 * PageSize())) << ptr;
  static_cast<uint8_t*>(ptr)[2 * PageSize() - 1] = 1;
  ASSERT_EQ(0, MunmapForGuest(ptr, length));
}

TEST(GuestMmapWindow, HintAboveTheCeilingIsMovedBelowIt) {
  void* hint = reinterpret_cast<void*>(uintptr_t{0x7000'0000'0000});
  void* ptr = MapAnon(hint, PageSize());
  ASSERT_NE(MAP_FAILED, ptr);
  EXPECT_TRUE(InWindow(ptr, PageSize())) << ptr;
  ASSERT_EQ(0, MunmapForGuest(ptr, PageSize()));
}

TEST(GuestMmapWindow, FixedMappingKeepsItsAddress) {
  // A fixed mapping outside the window must stay where the guest put it.
  void* high = mmap(nullptr, PageSize(), PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(MAP_FAILED, high);
  ASSERT_GE(AsAddr(high), kGuestMmapWindowEnd);
  void* ptr = MapAnon(high, PageSize(), MAP_FIXED);
  EXPECT_EQ(high, ptr);
  ASSERT_EQ(0, MunmapForGuest(high, PageSize()));
}

TEST(GuestMmapWindow, TakenRangeBelowTheLastPlacementIsSkipped) {
  size_t length = 4 * PageSize();
  void* first = MapAnon(nullptr, length);
  ASSERT_NE(MAP_FAILED, first);
  ASSERT_TRUE(InWindow(first, length)) << first;
  // Something outside MmapForGuest takes the range the next placement would
  // use; the placement must neither replace it nor leave the window.
  void* below = reinterpret_cast<void*>(AsAddr(first) - length);
  void* blocker = mmap(below, length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                       -1, 0);
  ASSERT_EQ(below, blocker);
  void* second = MapAnon(nullptr, length);
  ASSERT_NE(MAP_FAILED, second);
  EXPECT_TRUE(InWindow(second, length)) << second;
  EXPECT_TRUE(AsAddr(second) + length <= AsAddr(blocker) || AsAddr(second) >= AsAddr(first) + length)
      << second;
  ASSERT_EQ(0, MunmapForGuest(second, length));
  ASSERT_EQ(0, munmap(blocker, length));
  ASSERT_EQ(0, MunmapForGuest(first, length));
}

TEST(GuestMmapWindow, FileMappingLandsBelowTheCeilingWithItsContents) {
  int fd = static_cast<int>(syscall(SYS_memfd_create, "guest-mmap-window", 0));
  ASSERT_GE(fd, 0);
  ASSERT_EQ(0, ftruncate(fd, static_cast<off_t>(PageSize())));
  ASSERT_EQ(4, pwrite(fd, "abcd", 4, 0));
  void* ptr = MmapForGuest(nullptr, PageSize(), PROT_READ, MAP_SHARED, fd, 0);
  ASSERT_NE(MAP_FAILED, ptr);
  EXPECT_TRUE(InWindow(ptr, PageSize())) << ptr;
  EXPECT_EQ(0, memcmp(ptr, "abcd", 4));
  ASSERT_EQ(0, MunmapForGuest(ptr, PageSize()));
  close(fd);
}

TEST(GuestMmapWindow, GrowingRemapThatMustMoveStaysBelowTheCeiling) {
  size_t page = PageSize();
  void* ptr = MapAnon(nullptr, page);
  ASSERT_NE(MAP_FAILED, ptr);
  ASSERT_TRUE(InWindow(ptr, page)) << ptr;
  static_cast<uint8_t*>(ptr)[0] = 0x42;
  // Block growth in place, so the kernel would move the mapping.
  void* next = reinterpret_cast<void*>(AsAddr(ptr) + page);
  void* blocker =
      mmap(next, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  bool own_blocker = blocker == next;
  if (!own_blocker) {
    // The page above is already taken, which blocks growth just as well.
    ASSERT_EQ(MAP_FAILED, blocker);
  }
  void* moved = MremapForGuest(ptr, page, 8 * page, MREMAP_MAYMOVE, nullptr);
  ASSERT_NE(MAP_FAILED, moved);
  EXPECT_NE(ptr, moved);
  EXPECT_TRUE(InWindow(moved, 8 * page)) << moved;
  EXPECT_EQ(0x42, static_cast<uint8_t*>(moved)[0]);
  static_cast<uint8_t*>(moved)[8 * page - 1] = 1;
  ASSERT_EQ(0, MunmapForGuest(moved, 8 * page));
  if (own_blocker) {
    ASSERT_EQ(0, munmap(blocker, page));
  }
}

TEST(GuestMmapWindow, GrowingRemapInPlaceKeepsTheAddress) {
  size_t page = PageSize();
  // Reserve three pages, then release the top two so growth has room.
  void* ptr = MapAnon(nullptr, 3 * page);
  ASSERT_NE(MAP_FAILED, ptr);
  ASSERT_EQ(0, MunmapForGuest(static_cast<uint8_t*>(ptr) + page, 2 * page));
  void* grown = MremapForGuest(ptr, page, 3 * page, MREMAP_MAYMOVE, nullptr);
  EXPECT_EQ(ptr, grown);
  ASSERT_EQ(0, MunmapForGuest(grown, 3 * page));
}

}  // namespace

}  // namespace berberis
