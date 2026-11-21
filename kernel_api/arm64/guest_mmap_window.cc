// SPDX-FileCopyrightText: 2026 Actinis OÜ
// SPDX-License-Identifier: EUPL-1.2

#include "guest_mmap_window.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <mutex>
#include <vector>

#include "berberis/base/tracing.h"

namespace berberis {

namespace {

std::mutex g_window_mutex;
// The next placement goes below this address, as the kernel's top-down
// placement goes below its previous one.
uintptr_t g_window_cursor = kGuestMmapWindowEnd;

size_t PageSize() {
  return static_cast<size_t>(getpagesize());
}

size_t AlignToPage(size_t length) {
  size_t page_size = PageSize();
  return (length + page_size - 1) & ~(page_size - 1);
}

bool IsHex(char c, uintptr_t* digit) {
  if (c >= '0' && c <= '9') {
    *digit = c - '0';
  } else if (c >= 'a' && c <= 'f') {
    *digit = c - 'a' + 10;
  } else {
    return false;
  }
  return true;
}

// Reads the mappings that intersect the window from the host's
// /proc/self/maps. Raw syscalls keep the guest views of procfs out of it.
bool ReadWindowMappings(std::vector<GuestMmapRange>* ranges) {
  int fd = static_cast<int>(
      syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC));
  if (fd < 0) {
    return false;
  }
  char buffer[4096];
  // Each line starts with "begin-end "; parse those two fields only.
  enum class Field { kBegin, kEnd, kSkip } field = Field::kBegin;
  uintptr_t begin = 0;
  uintptr_t end = 0;
  bool ok = true;
  for (;;) {
    ssize_t count = syscall(SYS_read, fd, buffer, sizeof(buffer));
    if (count < 0) {
      if (errno == EINTR) {
        continue;
      }
      ok = false;
      break;
    }
    if (count == 0) {
      break;
    }
    for (ssize_t i = 0; i < count; i++) {
      char c = buffer[i];
      uintptr_t digit;
      if (c == '\n') {
        field = Field::kBegin;
        begin = 0;
        end = 0;
        continue;
      }
      if (field == Field::kBegin) {
        if (IsHex(c, &digit)) {
          begin = (begin << 4) | digit;
        } else {
          field = c == '-' ? Field::kEnd : Field::kSkip;
        }
      } else if (field == Field::kEnd) {
        if (IsHex(c, &digit)) {
          end = (end << 4) | digit;
        } else {
          field = Field::kSkip;
          if (end > kGuestMmapWindowBegin && begin < kGuestMmapWindowEnd) {
            ranges->push_back({begin, end});
          }
        }
      }
    }
  }
  syscall(SYS_close, fd);
  return ok;
}

uintptr_t FindWindowGap(uintptr_t limit, size_t length) {
  std::vector<GuestMmapRange> ranges;
  if (!ReadWindowMappings(&ranges)) {
    return 0;
  }
  uintptr_t start =
      FindHighestGuestMmapGap(ranges.data(), ranges.size(), kGuestMmapWindowBegin, limit, length);
  if (start == 0 && limit != kGuestMmapWindowEnd) {
    // Nothing below the cursor: reuse a gap that unmapped ranges left above it.
    start = FindHighestGuestMmapGap(
        ranges.data(), ranges.size(), kGuestMmapWindowBegin, kGuestMmapWindowEnd, length);
  }
  return start;
}

// Maps at exactly `start` without replacing anything. Returns false, with
// errno set, when the range is taken or the mapping fails.
bool MapAt(uintptr_t start, size_t length, int prot, int flags, int fd, off64_t offset) {
  void* want = reinterpret_cast<void*>(start);
  void* result = mmap64(want, length, prot, flags | MAP_FIXED_NOREPLACE, fd, offset);
  if (result == want) {
    return true;
  }
  if (result != MAP_FAILED) {
    // A kernel without MAP_FIXED_NOREPLACE treats it as a hint.
    munmap(result, length);
    errno = EEXIST;
  }
  return false;
}

}  // namespace

uintptr_t FindHighestGuestMmapGap(const GuestMmapRange* ranges,
                                  size_t count,
                                  uintptr_t window_begin,
                                  uintptr_t limit,
                                  size_t length) {
  if (length == 0 || limit < window_begin || limit - window_begin < length) {
    return 0;
  }
  uintptr_t gap_end = limit;
  for (size_t i = count; i > 0; i--) {
    const GuestMmapRange& range = ranges[i - 1];
    if (range.begin >= gap_end) {
      continue;
    }
    uintptr_t gap_begin = range.end > window_begin ? range.end : window_begin;
    if (gap_end > gap_begin && gap_end - gap_begin >= length) {
      return gap_end - length;
    }
    gap_end = range.begin;
    if (gap_end <= window_begin) {
      return 0;
    }
  }
  return gap_end - window_begin >= length ? gap_end - length : 0;
}

bool ShouldPlaceInGuestMmapWindow(void* addr, int flags) {
  if (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) {
    return false;
  }
  return addr == nullptr || reinterpret_cast<uintptr_t>(addr) >= kGuestMmapWindowEnd;
}

void* MmapInGuestMmapWindow(size_t length, int prot, int flags, int fd, off64_t offset) {
  size_t aligned = AlignToPage(length);
  if (aligned == 0 || aligned < length || aligned > kGuestMmapWindowEnd - kGuestMmapWindowBegin) {
    errno = ENOMEM;
    return MAP_FAILED;
  }
  std::lock_guard<std::mutex> lock(g_window_mutex);
  // The fast path: the range right below the previous placement.
  if (g_window_cursor - kGuestMmapWindowBegin >= aligned) {
    uintptr_t start = g_window_cursor - aligned;
    if (MapAt(start, length, prot, flags, fd, offset)) {
      g_window_cursor = start;
      return reinterpret_cast<void*>(start);
    }
    if (errno != EEXIST) {
      return MAP_FAILED;
    }
  }
  // Something else took that range: find a gap in the current mappings.
  uintptr_t start = FindWindowGap(g_window_cursor, aligned);
  if (start == 0) {
    TRACE("No room for a %zu-byte guest mapping below 0x%zx", aligned, kGuestMmapWindowEnd);
    errno = ENOMEM;
    return MAP_FAILED;
  }
  if (!MapAt(start, length, prot, flags, fd, offset)) {
    return MAP_FAILED;
  }
  g_window_cursor = start;
  return reinterpret_cast<void*>(start);
}

void* MremapIntoGuestMmapWindow(void* old_addr, size_t old_size, size_t new_size) {
  // Growing in place keeps the address, as the kernel prefers to.
  void* result = mremap(old_addr, old_size, new_size, 0);
  if (result != MAP_FAILED) {
    return result;
  }
  // Reserve the destination, then move the mapping over the reservation.
  void* target =
      MmapInGuestMmapWindow(new_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (target == MAP_FAILED) {
    return MAP_FAILED;
  }
  result = mremap(old_addr, old_size, new_size, MREMAP_MAYMOVE | MREMAP_FIXED, target);
  if (result == MAP_FAILED) {
    int saved_errno = errno;
    munmap(target, new_size);
    errno = saved_errno;
  }
  return result;
}

}  // namespace berberis
