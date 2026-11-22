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

// Digitalis-side override of libEGL's eglGetProcAddress that adds guest-callable
// wrapping for the ANGLE/CHROMIUM extension entry points the upstream proxy's
// wrap table does not know.
//
// Why this exists: ANGLE's host eglGetProcAddress returns a non-NULL dispatch
// stub for every proc it knows, and the upstream proxy trampoline
// (native_bridge_support .../egl_trampolines.cc) NULLs the guest return when its
// generated kOpenGLTrampolines table can't marshal that proc. That is fine for
// procs whose extension the driver does not advertise — but for advertised
// extensions it is a landmine: Chromium's GL bindings gate calls on the
// GL_EXTENSIONS string, not on the probed pointer being non-NULL. With ANGLE as
// the host GLES driver, GL_ANGLE_robust_client_memory IS advertised, Chromium
// enables the robust paths, and the very first state query calls the NULL that
// our proxy returned for glGetIntegervRobustANGLE — the guest jumps to address
// 0, berberis_HandleNoExec raises SIGSEGV(SEGV_ACCERR, addr=0), and the
// Chromium GPU process dies in a loop until the browser aborts with "Timed out
// waiting for GPU channel" (observed as the Helium crash on any heavy page).
//
// The override chains to the upstream trampoline first (keeping its several
// hundred core-GL wrappers), and only when upstream returned NULL for a
// host-present proc does it consult the wrap table in
// digitalis_extra_libegl_angle_procs.cc. The table is demand-driven: it covers
// the procs a Chromium 149 GPU process probes and that ANGLE-on-Android can
// advertise (GL_ANGLE_robust_client_memory, GL_ANGLE_get_tex_level_parameter,
// GL_ANGLE_multi_draw, GL_ANGLE_polygon_mode, GL_ANGLE_request_extension,
// GL_ANGLE_shader_pixel_local_storage, GL_CHROMIUM_copy_texture,
// GL_CHROMIUM_bind_uniform_location, GL_ANGLE_memory_object_flags,
// GL_ANGLE_vulkan_image, GL_ANGLE_blob_cache, EGL_KHR_debug,
// EGL_CHROMIUM_sync_control, and friends), plus those of
// GL_ANGLE_base_vertex_base_instance: Skia's GrGLInterface::validate() rejects
// the whole interface when that advertised extension's procs are NULL, and an
// app that builds a GrDirectContext from it then dereferences the NULL context.
// Probed procs of extensions ANGLE never advertises on Android (D3D stream
// textures, Metal shared events, macOS GPU-power switching, external contexts)
// are deliberately NOT covered: the upstream NULL stays correct and unreachable
// for them.

#if defined(__x86_64__)

#include "berberis/base/tracing.h"
#include "berberis/guest_abi/guest_params.h"
#include "berberis/proxy_loader/proxy_library_builder.h"
#include "berberis/runtime_primitives/host_code.h"

#include "digitalis_extra_libegl_angle_procs.h"
#include "register_extra_trampolines.h"

namespace berberis {
namespace {

using EglGenericFn = void (*)();
using PFN_eglGetProcAddress = EglGenericFn (*)(const char*);

// Chained override of the upstream eglGetProcAddress custom trampoline. The
// callee is a ChainedTrampoline holding the primary's {marshal_and_call, thunk};
// the thunk is the host eglGetProcAddress itself (the primary table binds it).
void DoDigitalisEglGetProcAddress(HostCode callee, ThreadState* state) {
  const auto* chain = static_cast<const ChainedTrampoline*>(callee);

  // Capture the proc name BEFORE running the primary: x0 doubles as the return
  // register, so the primary trampoline overwrites it with the result.
  auto [proc_name_param] = GuestParamsValues<PFN_eglGetProcAddress>(state);
  const char* proc_name = static_cast<const char*>(proc_name_param);

  // Full upstream behavior first: host lookup + kOpenGLTrampolines wrapping.
  chain->marshal_and_call(chain->thunk, state);

  auto&& [ret] = GuestReturnReference<PFN_eglGetProcAddress>(state);
  if (ToGuestAddr(ret) != 0 || proc_name == nullptr) {
    return;  // Upstream wrapped it (or nothing to retry).
  }

  const AngleProc* proc = FindAngleProc(proc_name);
  if (proc == nullptr) {
    return;  // Not covered here either; keep the upstream NULL.
  }

  PFN_eglGetProcAddress host_get_proc_address = AsFuncPtr(chain->thunk);
  EglGenericFn host_fn = host_get_proc_address(proc_name);
  if (host_fn == nullptr) {
    return;  // Host driver does not have it; NULL is the correct answer.
  }

  proc->wrap(reinterpret_cast<HostCode>(host_fn), proc->name);
  TRACE("digitalis eglGetProcAddress: wrapped \"%s\"", proc->name);
  ret = host_fn;
}

const KnownTrampoline kDigitalisLibEGLOverrides[] = {
    {"eglGetProcAddress", DoDigitalisEglGetProcAddress, nullptr},
};

REGISTER_DIGITALIS_EXTRA_TRAMPOLINE_OVERRIDES("libEGL.so", kDigitalisLibEGLOverrides)

}  // namespace
}  // namespace berberis

#endif  // defined(__x86_64__)