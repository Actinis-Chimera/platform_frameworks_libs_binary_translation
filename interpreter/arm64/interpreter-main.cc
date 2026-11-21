/*
 * Copyright (C) 2026 utzcoz
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "berberis/interpreter/arm64/interpreter.h"

#include "berberis/base/bit_util.h"
#include "berberis/base/config.h"
#include "berberis/decoder/arm64/decoder.h"
#include "berberis/decoder/arm64/semantics_player.h"
#include "berberis/guest_os_primitives/guest_map_shadow.h"
#include "berberis/guest_state/guest_addr.h"
#include "berberis/guest_state/guest_state.h"
#include "berberis/guest_state/guest_state_opaque.h"
#include "berberis/runtime_primitives/runtime_library.h"
#include "berberis/runtime_primitives/translation_cache.h"

#include "../faulty_memory_accesses.h"

#include "interpreter.h"

namespace berberis {

void InitInterpreter() {
  AddFaultyMemoryAccessRecoveryCode();
}

void InterpretInsn(ThreadState* state) {
  GuestAddr pc = state->cpu.insn_addr;
  Interpreter interpreter(state);
  SemanticsPlayer sem_player(&interpreter);
  Decoder decoder(&sem_player);
  uint8_t insn_len = decoder.Decode(ToHostAddr<const uint16_t>(pc));
  interpreter.FinalizeInsn(insn_len);
}

void InterpretBatch(ThreadState* state, int max_insns, TranslationCache* cache) {
  // Create interpreter/decoder ONCE and reuse across instructions.
  // This eliminates per-instruction construction overhead (~60% of cost).
  Interpreter interpreter(state);
  SemanticsPlayer sem_player(&interpreter);
  Decoder decoder(&sem_player);

  // region digitalis
  // A fetch from a page without PROT_EXEC must fault before the instruction
  // runs, as it does on hardware, so that a guest SIGSEGV handler can make
  // the page executable and resume. Only the
  // dispatcher raises that fault (TranslateRegion installs kEntryNoExec), so
  // hand a PC on a non-executable page back to it instead of decoding the
  // page's bytes. Check once per page: the shadow lookup is a bitmap read.
  // The page tracking assumes the 4-byte A64 instruction never straddles a
  // page, which alignment guarantees.
  const GuestMapShadow* shadow = GuestMapShadow::GetInstance();
  GuestAddr checked_page = 0;
  // endregion
  for (int i = 0; i < max_insns; i++) {
    GuestAddr pc = state->cpu.insn_addr;
    if (pc == 0 || ArePendingSignalsPresent(*state)) break;

    // region digitalis
    GuestAddr page = AlignDown(pc, config::kGuestPageSize);
    if (page != checked_page) {
      if (!shadow->IsExecutable(pc, 4)) {
        // At the batch's first PC the dispatcher got here through an
        // interpret entry cached while the page was executable. Drop it, so
        // the next dispatch reaches TranslateRegion and its NoExec fault
        // instead of returning here without progress.
        if (i == 0) cache->InvalidateGuestRange(pc, pc + 4);
        break;
      }
      checked_page = page;
    }
    // endregion

    interpreter.Reset();
    uint8_t insn_len = decoder.Decode(ToHostAddr<const uint16_t>(pc));
    interpreter.FinalizeInsn(insn_len);

    // If a memory fault occurred, HandleHostSignal queued it as pending.
    // Break so ExecuteGuest can deliver the signal to the guest handler.
    if (interpreter.HasException()) {
      break;
    }

    // always check cache after each instruction
    // Previously only checked on non-sequential PCs (branches). This caused
    // the interpreter to run over JIT'd code at consecutive PCs, executing
    // up to 500 instructions at interpreter speed when JIT'd code was available.
    GuestAddr new_pc = state->cpu.insn_addr;
    if (new_pc == 0) break;
    auto code = cache->GetHostCodePtr(new_pc)->load();
    if (code != kEntryInterpret && code != kEntryNotTranslated &&
        code != kEntryTranslating) {
      break;
    }
  }
}

}  // namespace berberis
