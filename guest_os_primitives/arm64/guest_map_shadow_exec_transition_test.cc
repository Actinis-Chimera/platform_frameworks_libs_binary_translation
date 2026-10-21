// SPDX-FileCopyrightText: 2026 Actinis OÜ
// SPDX-License-Identifier: EUPL-1.2

// A guest that briefly makes its own code non-executable, for example
// mprotect(PROT_READ | PROT_WRITE) over a libc text range to patch it and then
// mprotect(PROT_READ | PROT_EXEC) to restore it, must not leave the range
// faulting afterwards. While the range is not executable, another thread that
// reaches a PC in it gets a NoExec handler cached for that PC. Making the
// range executable again has to drop that handler, as the kernel lets the
// code run again on hardware.

#include "gtest/gtest.h"

#include "berberis/base/config.h"  // kGuestPageSize
#include "berberis/base/large_mmap.h"
#include "berberis/guest_os_primitives/guest_map_shadow.h"
#include "berberis/guest_state/guest_addr.h"
#include "berberis/runtime_primitives/host_code.h"
#include "berberis/runtime_primitives/runtime_library.h"  // kEntry*
#include "berberis/runtime_primitives/translation_cache.h"

namespace berberis {

namespace {

constexpr GuestAddr kRegionStart{0x7f02'0000};
constexpr size_t kRegionSize{0x0004'0000};

const HostCodeAddr kTranslatedCode = AsHostCodeAddr(AsHostCode(0xdead'beef));

class GuestMapShadowExecTransitionTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ::testing::Test::SetUp();
    InitLargeMmap();
    cache_ = TranslationCache::GetInstance();
    cache_->InvalidateGuestRange(kRegionStart, kRegionStart + kRegionSize);
  }

  void TearDown() override {
    cache_->InvalidateGuestRange(kRegionStart, kRegionStart + kRegionSize);
    ::testing::Test::TearDown();
  }

  // What TranslateRegion stores for a PC that is not executable.
  void CacheNoExec(GuestAddr pc) {
    GuestCodeEntry* entry = cache_->AddAndLockForTranslation(pc, 0);
    ASSERT_TRUE(entry);
    cache_->SetTranslatedAndUnlock(
        pc, entry, 4, GuestCodeEntry::Kind::kSpecialHandler, {kEntryNoExec, 0});
    ASSERT_EQ(kEntryNoExec, cache_->GetHostCodePtr(pc)->load());
  }

  void CacheTranslated(GuestAddr pc) {
    GuestCodeEntry* entry = cache_->AddAndLockForTranslation(pc, 0);
    ASSERT_TRUE(entry);
    cache_->SetTranslatedAndUnlock(
        pc, entry, 4, GuestCodeEntry::Kind::kLiteTranslated, {kTranslatedCode, 1});
    ASSERT_EQ(kTranslatedCode, cache_->GetHostCodePtr(pc)->load());
  }

  HostCodeAddr CachedCode(GuestAddr pc) { return cache_->GetHostCodePtr(pc)->load(); }

  GuestMapShadow shadow_;
  TranslationCache* cache_ = nullptr;
};

TEST_F(GuestMapShadowExecTransitionTest, ReprotectExecutableDropsNoExecCachedMeanwhile) {
  constexpr GuestAddr kPc = kRegionStart + 0x1'4394;
  shadow_.SetExecutable(kRegionStart, kRegionSize);

  // mprotect(PROT_READ | PROT_WRITE): another thread reaches kPc meanwhile.
  shadow_.ClearExecutable(kRegionStart, kRegionSize);
  CacheNoExec(kPc);

  // mprotect(PROT_READ | PROT_EXEC): kPc is code again.
  shadow_.SetExecutable(kRegionStart, kRegionSize);

  EXPECT_TRUE(shadow_.IsExecutable(kPc, 4));
  EXPECT_EQ(kEntryNotTranslated, CachedCode(kPc))
      << "a NoExec handler cached while the range was not executable must not "
         "outlive mprotect(PROT_EXEC)";
}

TEST_F(GuestMapShadowExecTransitionTest, MapExecutableDropsNoExecCachedBeforeMapping) {
  constexpr GuestAddr kPc = kRegionStart + 0x2'0000;
  CacheNoExec(kPc);

  shadow_.SetExecutable(kRegionStart, kRegionSize);

  EXPECT_EQ(kEntryNotTranslated, CachedCode(kPc));
}

TEST_F(GuestMapShadowExecTransitionTest, ReprotectAlreadyExecutableKeepsTranslations) {
  constexpr GuestAddr kPc = kRegionStart + 0x8000;
  shadow_.SetExecutable(kRegionStart, kRegionSize);
  CacheTranslated(kPc);

  // mprotect(PROT_READ | PROT_EXEC) over code that is already executable.
  shadow_.SetExecutable(kRegionStart, kRegionSize);

  EXPECT_EQ(kTranslatedCode, CachedCode(kPc));
}

TEST_F(GuestMapShadowExecTransitionTest, ReprotectKeepsTranslationsOutsideTheFlippedPages) {
  constexpr GuestAddr kPatchedPage = kRegionStart + 0x1'0000;
  constexpr GuestAddr kNoExecPc = kPatchedPage + 0x10;
  constexpr GuestAddr kTranslatedPc = kRegionStart + 0x3'0000;
  shadow_.SetExecutable(kRegionStart, kRegionSize);
  CacheTranslated(kTranslatedPc);

  // Only one page goes through the writable window.
  shadow_.ClearExecutable(kPatchedPage, config::kGuestPageSize);
  CacheNoExec(kNoExecPc);

  // The guest restores execute permission over the whole range.
  shadow_.SetExecutable(kRegionStart, kRegionSize);

  EXPECT_EQ(kEntryNotTranslated, CachedCode(kNoExecPc));
  EXPECT_EQ(kTranslatedCode, CachedCode(kTranslatedPc))
      << "pages that stayed executable keep their translations";
}

}  // namespace

}  // namespace berberis
