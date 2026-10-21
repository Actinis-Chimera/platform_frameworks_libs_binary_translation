// SPDX-FileCopyrightText: 2026 Actinis OÜ
// SPDX-License-Identifier: EUPL-1.2

// A guest munmap over a mapping that the translator protects from the guest
// (the host-mapped guest libc text, see ProtectMappingsFromGuest) must leave
// that mapping usable for every other thread. Clearing its executable bits
// first, even if they are restored right after, opens a window in which a
// thread translating a PC there caches a NoExec handler and faults with
// SEGV_ACCERR on valid libc code.

#include "gtest/gtest.h"

#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "berberis/guest_os_primitives/guest_map_shadow.h"
#include "berberis/guest_state/guest_addr.h"
#include "berberis/kernel_api/sys_mman_emulation.h"
#include "berberis/runtime_primitives/host_code.h"
#include "berberis/runtime_primitives/translation_cache.h"

namespace berberis {

namespace {

constexpr size_t kRegionPages = 4;
constexpr uint8_t kSentinel = 0xAB;

const HostCodeAddr kTranslatedCode = AsHostCodeAddr(AsHostCode(0xdead'beef));

size_t PageSize() {
  return static_cast<size_t>(getpagesize());
}

bool IsMapped(void* addr, size_t length) {
  return msync(addr, length, MS_ASYNC) == 0;
}

class MunmapProtectedMappingTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ::testing::Test::SetUp();
    region_size_ = kRegionPages * PageSize();
    region_ = static_cast<uint8_t*>(
        mmap(nullptr, region_size_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    ASSERT_NE(MAP_FAILED, region_);
    memset(region_, kSentinel, region_size_);
    shadow_ = GuestMapShadow::GetInstance();
    cache_ = TranslationCache::GetInstance();
    shadow_->SetExecutable(Guest(0), region_size_);
  }

  void TearDown() override {
    cache_->InvalidateGuestRange(Guest(0), Guest(region_size_));
    shadow_->ClearExecutable(Guest(0), region_size_);
    ::testing::Test::TearDown();
  }

  GuestAddr Guest(size_t offset) const { return ToGuestAddr(region_ + offset); }

  void CacheTranslated(GuestAddr pc) {
    GuestCodeEntry* entry = cache_->AddAndLockForTranslation(pc, 0);
    ASSERT_TRUE(entry);
    cache_->SetTranslatedAndUnlock(
        pc, entry, 4, GuestCodeEntry::Kind::kLiteTranslated, {kTranslatedCode, 1});
    ASSERT_EQ(kTranslatedCode, cache_->GetHostCodePtr(pc)->load());
  }

  HostCodeAddr CachedCode(GuestAddr pc) { return cache_->GetHostCodePtr(pc)->load(); }

  uint8_t* region_ = nullptr;
  size_t region_size_ = 0;
  GuestMapShadow* shadow_ = nullptr;
  TranslationCache* cache_ = nullptr;
};

TEST_F(MunmapProtectedMappingTest, GuestMunmapLeavesProtectedMappingExecutableAndMapped) {
  // Protected mappings are registered for the life of the process and cannot
  // be removed, so this region is never unmapped: a later test must not get
  // the same address back and inherit its protection.
  shadow_->AddProtectedMapping(region_, region_ + region_size_);
  const GuestAddr pc = Guest(PageSize() + 0x394);
  CacheTranslated(pc);

  // The guest unmaps one page in the middle of the protected range.
  EXPECT_EQ(0, MunmapForGuest(region_ + PageSize(), PageSize()));

  EXPECT_TRUE(shadow_->IsExecutable(Guest(0), region_size_))
      << "a protected range must never be non-executable for other threads";
  EXPECT_EQ(kTranslatedCode, CachedCode(pc))
      << "translations of a protected range must survive a suppressed munmap";
  ASSERT_TRUE(IsMapped(region_, region_size_));
  EXPECT_EQ(kSentinel, region_[PageSize() + 0x394]);
}

TEST_F(MunmapProtectedMappingTest, GuestMunmapOfUnprotectedMappingUnmapsIt) {
  const GuestAddr pc = Guest(0x10);
  CacheTranslated(pc);

  EXPECT_EQ(0, MunmapForGuest(region_, region_size_));

  EXPECT_FALSE(shadow_->IsExecutable(Guest(0), region_size_));
  EXPECT_NE(kTranslatedCode, CachedCode(pc));
  const int msync_result = msync(region_, region_size_, MS_ASYNC);
  const int msync_errno = errno;
  EXPECT_EQ(-1, msync_result);
  EXPECT_EQ(ENOMEM, msync_errno) << "the range must be unmapped";
}

}  // namespace

}  // namespace berberis
