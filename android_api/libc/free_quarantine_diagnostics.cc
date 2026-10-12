// SPDX-FileCopyrightText: 2026 Actinis OÜ
// SPDX-License-Identifier: EUPL-1.2

#if defined(BERBERIS_ENABLE_GUEST_FREE_DIAGNOSTICS) && defined(NATIVE_BRIDGE_GUEST_ARCH_ARM64)
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <dlfcn.h>
#include <unistd.h>

#include "berberis/guest_os_primitives/guest_thread_manager.h"
#include "berberis/guest_state/guest_state.h"

bool TraceGuestQuarantineInput(void* ptr) {
  static const auto enabled = [] {
    const auto* value = getenv("DRION_TRACE_GUEST_CALL");
    return value && (value[0] == '1' || value[0] == '2');
  }();
  if (!enabled) return false;
  static const auto selected_size = [] {
    const auto* value = getenv("DRION_TRACE_ALLOC_OBJECT_SIZE");
    return value ? strtoull(value, nullptr, 10) : 0;
  }();
  if (!selected_size) return false;
  const auto saved_errno = errno;
  // This bounded probe observes allocation ownership; it does not use the
  // returned size to access storage or extend a compiler-known object bound.
  using UsableSize = size_t (*)(void*);
  static const auto usable_size =
      reinterpret_cast<UsableSize>(dlsym(RTLD_DEFAULT, "malloc_usable_size"));
  const auto allocation_size = usable_size ? usable_size(ptr) : 0;
  auto matches = allocation_size == selected_size;
  if (selected_size == std::numeric_limits<unsigned long long>::max()) {
    // Diagnostic shape selector for a length-prefixed sequential index array.
    // Read only the allocator-reported live object, capped at 64 KiB.
    matches = allocation_size >= 16 && allocation_size <= 65536 &&
              allocation_size % 4 == 0;
    if (matches) {
      const auto* words = static_cast<const uint32_t*>(ptr);
      const auto count = allocation_size / 4 - 1;
      matches = words[0] == count;
      for (size_t index = 0; matches && index < count; ++index) {
        matches = words[index + 1] == index;
      }
    }
  }
  if (!matches) {
    errno = saved_errno;
    return false;
  }
  static const auto retain = [] {
    const auto* value = getenv("DRION_TRACE_GUEST_CALL");
    return value && value[0] == '2';
  }();
  static std::atomic<unsigned> samples{0};
  const auto sample = samples.fetch_add(1, std::memory_order_relaxed);
  // A bounded diagnostic control, never a production allocator policy.
  static std::atomic<size_t> retained_bytes{0};
  constexpr size_t kRetentionBudget = 16 * 1024 * 1024;
  auto used = retained_bytes.load(std::memory_order_relaxed);
  auto hold = retain && sample < 4096 && allocation_size <= kRetentionBudget;
  while (hold) {
    if (used > kRetentionBudget - allocation_size) {
      hold = false;
      break;
    }
    if (retained_bytes.compare_exchange_weak(used, used + allocation_size,
                                             std::memory_order_relaxed)) break;
  }
  if (sample >= 64) {
    errno = saved_errno;
    return hold;
  }
  auto* thread = berberis::GetCurrentGuestThread();
  if (thread) {
    const auto& cpu = thread->state()->cpu;
    char line[384];
    auto length = snprintf(line, sizeof(line),
        "berberis[quarantine-input]: ptr=%p size=%zu pc=%lx lr=%lx x19=%lx x20=%lx\n",
        ptr, allocation_size, cpu.insn_addr, cpu.x[30], cpu.x[19], cpu.x[20]);
    if (length > 0 && static_cast<size_t>(length) < sizeof(line)) {
      const auto written = write(STDERR_FILENO, line, length);
      (void)written;
    }
    berberis::GuestAddr stack_base;
    size_t stack_size = 0;
    size_t guard_size = 0;
    thread->GetAttr(&stack_base, &stack_size, &guard_size);
    auto fp = cpu.x[29];
    for (unsigned index = 0; index < 8; ++index) {
      if (stack_size < 16 || fp < stack_base ||
          fp - stack_base > stack_size - 16 || fp % 16) break;
      uint64_t frame[2];
      memcpy(frame, reinterpret_cast<const void*>(fp), sizeof(frame));
      length = snprintf(line, sizeof(line),
          "berberis[quarantine-frame]: ptr=%p index=%u fp=%lx lr=%lx\n",
          ptr, index, fp, frame[1]);
      if (length > 0 && static_cast<size_t>(length) < sizeof(line)) {
        const auto written = write(STDERR_FILENO, line, length);
        (void)written;
      }
      if (frame[0] <= fp) break;
      fp = frame[0];
    }
  }
  errno = saved_errno;
  return hold;
}
#elif defined(BERBERIS_ENABLE_GUEST_FREE_DIAGNOSTICS)
bool TraceGuestQuarantineInput(void*) { return false; }
#endif
