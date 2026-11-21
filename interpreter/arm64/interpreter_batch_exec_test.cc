// SPDX-FileCopyrightText: 2026 Actinis OÜ
// SPDX-License-Identifier: EUPL-1.2

// InterpretBatch keeps decoding at each next PC to save the dispatcher round
// trip per instruction. On hardware an instruction fetch from a page without
// PROT_EXEC faults (SIGSEGV, SEGV_ACCERR) before the instruction runs, and a
// guest SIGSEGV handler may rely on that to make the page executable and
// resume.
// The dispatcher raises that fault through TranslateRegion's executability
// check (kEntryNoExec), so the batch must hand a PC on a non-executable page
// back to the dispatcher instead of decoding its bytes (#1723).

#include "gtest/gtest.h"

#include <sys/mman.h>

#include <cstdint>
#include <cstring>

#include "berberis/base/config.h"  // kGuestPageSize
#include "berberis/guest_os_primitives/guest_map_shadow.h"
#include "berberis/guest_state/guest_addr.h"
#include "berberis/guest_state/guest_state.h"
#include "berberis/interpreter/arm64/interpreter.h"
#include "berberis/runtime_primitives/host_code.h"
#include "berberis/runtime_primitives/runtime_library.h"  // kEntry*
#include "berberis/runtime_primitives/translation_cache.h"

namespace berberis {

namespace {

constexpr uint32_t kAddX0One = 0x91000400;  // add x0, x0, #1
const size_t kPage = config::kGuestPageSize;
const size_t kInsnsPerPage = kPage / sizeof(uint32_t);
constexpr int kMaxInsns = 10;

// b <offset>, offset in bytes from the branch.
uint32_t EncB(int64_t offset) {
  return 0x14000000u | (static_cast<uint32_t>(offset / 4) & 0x03ff'ffffu);
}

class InterpreterBatchExecTest : public ::testing::Test {
 protected:
  void SetUp() override {
    void* mem = mmap(nullptr, 3 * kPage, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(MAP_FAILED, mem);
    code_ = static_cast<uint32_t*>(mem);
    for (size_t i = 0; i < 3 * kInsnsPerPage; i++) {
      code_[i] = kAddX0One;
    }
    start_ = ToGuestAddr(code_);
    shadow_ = GuestMapShadow::GetInstance();
    cache_ = TranslationCache::GetInstance();
    cache_->InvalidateGuestRange(start_, start_ + 3 * kPage);
  }

  void TearDown() override {
    shadow_->ClearExecutable(start_, 3 * kPage);
    cache_->InvalidateGuestRange(start_, start_ + 3 * kPage);
    munmap(code_, 3 * kPage);
  }

  GuestAddr Page(int index) const { return start_ + index * kPage; }

  void Run(GuestAddr pc) {
    state_.cpu.insn_addr = pc;
    state_.cpu.x[0] = 0;
    InterpretBatch(&state_, kMaxInsns, cache_);
  }

  ThreadState state_{};
  uint32_t* code_ = nullptr;
  GuestAddr start_ = 0;
  GuestMapShadow* shadow_ = nullptr;
  TranslationCache* cache_ = nullptr;
};

TEST_F(InterpreterBatchExecTest, StopsBeforeFallingThroughIntoNonExecutablePage) {
  shadow_->SetExecutable(Page(0), kPage);

  Run(Page(1) - 2 * sizeof(uint32_t));

  EXPECT_EQ(2u, state_.cpu.x[0]) << "instructions on the non-executable page ran";
  EXPECT_EQ(Page(1), state_.cpu.insn_addr);
}

TEST_F(InterpreterBatchExecTest, StopsAtBranchTargetOnNonExecutablePage) {
  shadow_->SetExecutable(Page(0), kPage);
  shadow_->SetExecutable(Page(2), kPage);
  // A branch from page 0 into page 1, which is not executable.
  code_[1] = EncB(static_cast<int64_t>(kPage + 0x40 - sizeof(uint32_t)));

  Run(Page(0));

  EXPECT_EQ(1u, state_.cpu.x[0]) << "instructions on the non-executable page ran";
  EXPECT_EQ(Page(1) + 0x40, state_.cpu.insn_addr);
}

TEST_F(InterpreterBatchExecTest, ContinuesIntoNextExecutablePage) {
  shadow_->SetExecutable(Page(0), 2 * kPage);

  Run(Page(1) - 2 * sizeof(uint32_t));

  EXPECT_EQ(static_cast<uint64_t>(kMaxInsns), state_.cpu.x[0]);
  EXPECT_EQ(Page(1) + (kMaxInsns - 2) * sizeof(uint32_t), state_.cpu.insn_addr);
}

// The dispatcher sent the batch to a PC whose page is no longer executable,
// through an interpret entry cached while it was. Returning without progress
// must not leave that entry in place, or the dispatcher would call the batch
// again forever instead of reaching TranslateRegion's NoExec fault.
TEST_F(InterpreterBatchExecTest, DropsStaleInterpretEntryOnNonExecutablePage) {
  const GuestAddr pc = Page(1);
  GuestCodeEntry* entry = cache_->AddAndLockForTranslation(pc, 0);
  ASSERT_TRUE(entry);
  cache_->SetTranslatedAndUnlock(
      pc, entry, 4, GuestCodeEntry::Kind::kInterpreted, {kEntryInterpret, 0});

  Run(pc);

  EXPECT_EQ(0u, state_.cpu.x[0]) << "instructions on the non-executable page ran";
  EXPECT_EQ(pc, state_.cpu.insn_addr);
  EXPECT_EQ(kEntryNotTranslated, cache_->GetHostCodePtr(pc)->load());
}

}  // namespace

}  // namespace berberis
