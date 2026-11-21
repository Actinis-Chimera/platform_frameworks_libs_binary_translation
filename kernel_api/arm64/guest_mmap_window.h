// SPDX-FileCopyrightText: 2026 Actinis OÜ
// SPDX-License-Identifier: EUPL-1.2

// Keeps the addresses an arm64 guest gets from mmap inside the user address
// space of an arm64 Android device.
//
// Android arm64 kernels (GKI) run with a 39-bit user address space, so every
// pointer an app sees on a device is below 2^39. An x86_64 host has 47 bits
// and its kernel places mappings top-down from just below 2^47. Guest code
// that validates pointers against the device range then rejects every block
// the host hands it: one engine allocator treats any free block above 2^41 as
// heap corruption and fails the allocation.
//
// Placement requests that leave the address to the kernel therefore go to
// [kGuestMmapWindowBegin, kGuestMmapWindowEnd), top-down from the last
// placement as the kernel does, through MAP_FIXED_NOREPLACE so a mapping that
// already exists is never replaced. Requests with MAP_FIXED or
// MAP_FIXED_NOREPLACE, and hints inside the window, keep their meaning. When
// the window has no gap for a request it falls back to the host placement.
//
// The window starts at 64 GiB, clear of the low ranges the host side of the
// runtime uses: guest code and the translated-code exec regions below 2 GiB,
// and the low-heap reservations of the host allocator below 24 GiB.

#ifndef BERBERIS_KERNEL_API_ARM64_GUEST_MMAP_WINDOW_H_
#define BERBERIS_KERNEL_API_ARM64_GUEST_MMAP_WINDOW_H_

#include <sys/mman.h>
#include <sys/types.h>

#include <cstddef>
#include <cstdint>

// The host glibc sysroot predates these flags; their kernel ABI values are fixed.
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

namespace berberis {

inline constexpr uintptr_t kGuestMmapWindowBegin = uintptr_t{1} << 36;
inline constexpr uintptr_t kGuestMmapWindowEnd = uintptr_t{1} << 39;

struct GuestMmapRange {
  uintptr_t begin;
  uintptr_t end;
};

// Returns the highest start address s such that [s, s + length) lies inside
// [window_begin, limit) and intersects none of `ranges`, or 0 when no gap
// fits. `ranges` must be sorted by begin and must not overlap, as the lines of
// /proc/self/maps are. `length`, `window_begin` and `limit` must be multiples
// of the page size.
uintptr_t FindHighestGuestMmapGap(const GuestMmapRange* ranges,
                                  size_t count,
                                  uintptr_t window_begin,
                                  uintptr_t limit,
                                  size_t length);

// True when a guest mmap with these arguments leaves the placement to the
// kernel and its result must be kept inside the window.
bool ShouldPlaceInGuestMmapWindow(void* addr, int flags);

// Maps [s, s + length) at a free address s inside the window. Returns
// MAP_FAILED, with errno set, when the window has no gap for the request or
// the mapping fails; the caller then maps it as the host would.
void* MmapInGuestMmapWindow(size_t length, int prot, int flags, int fd, off64_t offset);

// Moves a growing mapping that the kernel would move out of the window to a
// free address inside it. Returns MAP_FAILED, with errno set, when the move
// must be left to the host mremap.
void* MremapIntoGuestMmapWindow(void* old_addr, size_t old_size, size_t new_size);

}  // namespace berberis

#endif  // BERBERIS_KERNEL_API_ARM64_GUEST_MMAP_WINDOW_H_
