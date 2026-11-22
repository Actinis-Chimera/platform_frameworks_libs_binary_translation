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

// The ANGLE/CHROMIUM extension entry points the digitalis eglGetProcAddress
// override (digitalis_extra_libegl_trampolines.cc) wraps for guest callers when
// the upstream proxy's kOpenGLTrampolines table does not know them. See that
// file for why advertised-but-unwrapped extensions crash guests.
//
// Pointer parameters marshal as void* — valid under LP64 since guest and host
// share the address space and the pointee layout is identical; only the
// register class matters to the trampoline generator. Integer widths and float
// parameters follow the ANGLE prototypes exactly.

#if defined(__x86_64__)

#include "digitalis_extra_libegl_angle_procs.h"

#include <cstdint>
#include <cstring>

#include "berberis/guest_abi/function_wrappers.h"
#include "berberis/guest_abi/guest_function_wrapper.h"
#include "berberis/guest_abi/guest_params.h"

namespace berberis {
namespace {

// Self-contained GL/EGL scalar typedefs (no EGL/GLES headers needed).
using GLboolean_t = uint8_t;
using GLenum_t = uint32_t;
using GLuint_t = uint32_t;
using GLint_t = int32_t;
using GLsizei_t = int32_t;
using GLfloat_t = float;
using GLuint64_t = uint64_t;
using GLbitfield_t = uint32_t;
using GLsizeiptr_t = intptr_t;
using EGLBoolean_t = uint32_t;
using EGLint_t = int32_t;


// Registers `fn` as guest-callable with the auto-generated marshaller for the
// exact host signature FuncPtr.
template <typename FuncPtr>
void WrapAs(HostCode fn, const char* name) {
  WrapHostFunctionImpl(fn, GetTrampolineFunc<FuncPtr>(), name);
}

// --- Custom marshallers for the two procs that take guest callbacks. ---

// EGLint eglDebugMessageControlKHR(EGLDEBUGPROCKHR callback,
//                                  const EGLAttrib* attrib_list);
// EGLDEBUGPROCKHR: void (*)(EGLenum error, const char* command,
//                           EGLint messageType, EGLLabelKHR threadLabel,
//                           EGLLabelKHR objectLabel, const char* message)
void DoTrampoline_eglDebugMessageControlKHR(HostCode callee, ThreadState* state) {
  using DebugProc =
      void (*)(GLenum_t, const char*, EGLint_t, void*, void*, const char*);
  using PFN_callee = EGLint_t (*)(DebugProc, const void*);
  PFN_callee callee_function = AsFuncPtr(callee);

  auto [guest_callback, attrib_list] = GuestParamsValues<PFN_callee>(state);
  DebugProc host_callback =
      ToGuestAddr(guest_callback) == 0
          ? nullptr
          : WrapGuestFunction(guest_callback, "EGLDEBUGPROCKHR");

  auto&& [ret] = GuestReturnReference<PFN_callee>(state);
  ret = callee_function(host_callback, attrib_list);
}

// void glBlobCacheCallbacksANGLE(GLSETBLOBPROCANGLE set, GLGETBLOBPROCANGLE get,
//                                const void* userParam);
// set: void (*)(const void* key, GLsizeiptr keySize,
//               const void* value, GLsizeiptr valueSize, const void* userParam)
// get: GLsizeiptr (*)(const void* key, GLsizeiptr keySize,
//                     void* value, GLsizeiptr valueSize, const void* userParam)
void DoTrampoline_glBlobCacheCallbacksANGLE(HostCode callee, ThreadState* state) {
  using SetProc =
      void (*)(const void*, GLsizeiptr_t, const void*, GLsizeiptr_t, const void*);
  using GetProc =
      GLsizeiptr_t (*)(const void*, GLsizeiptr_t, void*, GLsizeiptr_t, const void*);
  using PFN_callee = void (*)(SetProc, GetProc, const void*);
  PFN_callee callee_function = AsFuncPtr(callee);

  auto [guest_set, guest_get, user_param] = GuestParamsValues<PFN_callee>(state);
  SetProc host_set = ToGuestAddr(guest_set) == 0
                         ? nullptr
                         : WrapGuestFunction(guest_set, "GLSETBLOBPROCANGLE");
  GetProc host_get = ToGuestAddr(guest_get) == 0
                         ? nullptr
                         : WrapGuestFunction(guest_get, "GLGETBLOBPROCANGLE");

  callee_function(host_set, host_get, user_param);
}

template <TrampolineFunc kFunc>
void WrapAsCustom(HostCode fn, const char* name) {
  WrapHostFunctionImpl(fn, kFunc, name);
}

// --- Demand-driven wrap table (names Chromium probes; ANGLE prototypes). ---

constexpr AngleProc kAngleProcs[] = {
    // GL_ANGLE_robust_client_memory — Chromium routes ALL state queries through
    // these when the extension is advertised; glGetIntegervRobustANGLE is the
    // proven Helium GPU-process crasher.
    {"glGetBooleanvRobustANGLE", WrapAs<void (*)(GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetBufferParameteri64vRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetBufferParameterivRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetBufferPointervRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetFloatvRobustANGLE", WrapAs<void (*)(GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetFramebufferAttachmentParameterivRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLenum_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetInteger64i_vRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLuint_t, GLsizei_t, void*, void*)>},
    {"glGetInteger64vRobustANGLE", WrapAs<void (*)(GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetIntegeri_vRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLuint_t, GLsizei_t, void*, void*)>},
    {"glGetIntegervRobustANGLE", WrapAs<void (*)(GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetInternalformativRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLenum_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetMultisamplefvRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLuint_t, GLsizei_t, void*, void*)>},
    {"glGetProgramivRobustANGLE",
     WrapAs<void (*)(GLuint_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetQueryObjecti64vRobustANGLE",
     WrapAs<void (*)(GLuint_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetQueryObjectivRobustANGLE",
     WrapAs<void (*)(GLuint_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetQueryObjectui64vRobustANGLE",
     WrapAs<void (*)(GLuint_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetQueryObjectuivRobustANGLE",
     WrapAs<void (*)(GLuint_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetQueryivRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetRenderbufferParameterivRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetSamplerParameterfvRobustANGLE",
     WrapAs<void (*)(GLuint_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetSamplerParameterivRobustANGLE",
     WrapAs<void (*)(GLuint_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetShaderivRobustANGLE",
     WrapAs<void (*)(GLuint_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetTexParameterfvRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetTexParameterivRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetUniformfvRobustANGLE",
     WrapAs<void (*)(GLuint_t, GLint_t, GLsizei_t, void*, void*)>},
    {"glGetUniformivRobustANGLE",
     WrapAs<void (*)(GLuint_t, GLint_t, GLsizei_t, void*, void*)>},
    {"glGetUniformuivRobustANGLE",
     WrapAs<void (*)(GLuint_t, GLint_t, GLsizei_t, void*, void*)>},
    {"glGetVertexAttribIivRobustANGLE",
     WrapAs<void (*)(GLuint_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetVertexAttribIuivRobustANGLE",
     WrapAs<void (*)(GLuint_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetVertexAttribPointervRobustANGLE",
     WrapAs<void (*)(GLuint_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetVertexAttribfvRobustANGLE",
     WrapAs<void (*)(GLuint_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetVertexAttribivRobustANGLE",
     WrapAs<void (*)(GLuint_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetActiveUniformBlockivRobustANGLE",
     WrapAs<void (*)(GLuint_t, GLuint_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glReadPixelsRobustANGLE",
     WrapAs<void (*)(GLint_t, GLint_t, GLsizei_t, GLsizei_t, GLenum_t, GLenum_t,
                     GLsizei_t, void*, void*, void*, void*)>},
    {"glSamplerParameterfvRobustANGLE",
     WrapAs<void (*)(GLuint_t, GLenum_t, GLsizei_t, const void*)>},
    {"glSamplerParameterivRobustANGLE",
     WrapAs<void (*)(GLuint_t, GLenum_t, GLsizei_t, const void*)>},
    {"glTexImage2DRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLint_t, GLint_t, GLsizei_t, GLsizei_t, GLint_t,
                     GLenum_t, GLenum_t, GLsizei_t, const void*)>},
    {"glTexImage3DRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLint_t, GLint_t, GLsizei_t, GLsizei_t, GLsizei_t,
                     GLint_t, GLenum_t, GLenum_t, GLsizei_t, const void*)>},
    {"glTexParameterfvRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLenum_t, GLsizei_t, const void*)>},
    {"glTexParameterivRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLenum_t, GLsizei_t, const void*)>},
    {"glTexSubImage2DRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLint_t, GLint_t, GLint_t, GLsizei_t, GLsizei_t,
                     GLenum_t, GLenum_t, GLsizei_t, const void*)>},
    {"glTexSubImage3DRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLint_t, GLint_t, GLint_t, GLint_t, GLsizei_t,
                     GLsizei_t, GLsizei_t, GLenum_t, GLenum_t, GLsizei_t,
                     const void*)>},

    // GL_ANGLE_get_tex_level_parameter
    {"glGetTexLevelParameterfvANGLE",
     WrapAs<void (*)(GLenum_t, GLint_t, GLenum_t, void*)>},
    {"glGetTexLevelParameterfvRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLint_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetTexLevelParameterivANGLE",
     WrapAs<void (*)(GLenum_t, GLint_t, GLenum_t, void*)>},
    {"glGetTexLevelParameterivRobustANGLE",
     WrapAs<void (*)(GLenum_t, GLint_t, GLenum_t, GLsizei_t, void*, void*)>},

    // GL_ANGLE_base_vertex_base_instance — Skia's GrGLInterface::validate()
    // requires all four once the extension is advertised.
    {"glDrawArraysInstancedBaseInstanceANGLE",
     WrapAs<void (*)(GLenum_t, GLint_t, GLsizei_t, GLsizei_t, GLuint_t)>},
    {"glDrawElementsInstancedBaseVertexBaseInstanceANGLE",
     WrapAs<void (*)(GLenum_t, GLsizei_t, GLenum_t, const void*, GLsizei_t,
                     GLint_t, GLuint_t)>},
    {"glMultiDrawArraysInstancedBaseInstanceANGLE",
     WrapAs<void (*)(GLenum_t, const void*, const void*, const void*,
                     const void*, GLsizei_t)>},
    {"glMultiDrawElementsInstancedBaseVertexBaseInstanceANGLE",
     WrapAs<void (*)(GLenum_t, const void*, GLenum_t, const void*, const void*,
                     const void*, const void*, GLsizei_t)>},

    // GL_ANGLE_multi_draw
    {"glMultiDrawArraysANGLE",
     WrapAs<void (*)(GLenum_t, const void*, const void*, GLsizei_t)>},
    {"glMultiDrawArraysInstancedANGLE",
     WrapAs<void (*)(GLenum_t, const void*, const void*, const void*, GLsizei_t)>},
    {"glMultiDrawElementsANGLE",
     WrapAs<void (*)(GLenum_t, const void*, GLenum_t, const void*, GLsizei_t)>},
    {"glMultiDrawElementsInstancedANGLE",
     WrapAs<void (*)(GLenum_t, const void*, GLenum_t, const void*, const void*,
                     GLsizei_t)>},

    // GL_ANGLE_polygon_mode / GL_ANGLE_request_extension
    {"glPolygonModeANGLE", WrapAs<void (*)(GLenum_t, GLenum_t)>},
    {"glRequestExtensionANGLE", WrapAs<void (*)(const char*)>},

    // GL_ANGLE_shader_pixel_local_storage
    {"glBeginPixelLocalStorageANGLE", WrapAs<void (*)(GLsizei_t, const void*)>},
    {"glEndPixelLocalStorageANGLE", WrapAs<void (*)(GLsizei_t, const void*)>},
    {"glFramebufferMemorylessPixelLocalStorageANGLE",
     WrapAs<void (*)(GLint_t, GLenum_t)>},
    {"glFramebufferPixelLocalClearValuefvANGLE",
     WrapAs<void (*)(GLint_t, const void*)>},
    {"glFramebufferPixelLocalClearValueivANGLE",
     WrapAs<void (*)(GLint_t, const void*)>},
    {"glFramebufferPixelLocalClearValueuivANGLE",
     WrapAs<void (*)(GLint_t, const void*)>},
    {"glFramebufferPixelLocalStorageInterruptANGLE", WrapAs<void (*)()>},
    {"glFramebufferPixelLocalStorageRestoreANGLE", WrapAs<void (*)()>},
    {"glFramebufferTexturePixelLocalStorageANGLE",
     WrapAs<void (*)(GLint_t, GLuint_t, GLint_t, GLint_t)>},
    {"glGetFramebufferPixelLocalStorageParameterfvRobustANGLE",
     WrapAs<void (*)(GLint_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glGetFramebufferPixelLocalStorageParameterivRobustANGLE",
     WrapAs<void (*)(GLint_t, GLenum_t, GLsizei_t, void*, void*)>},
    {"glPixelLocalStorageBarrierANGLE", WrapAs<void (*)()>},

    // GL_CHROMIUM_copy_texture / GL_CHROMIUM_bind_uniform_location
    {"glBindUniformLocationCHROMIUM",
     WrapAs<void (*)(GLuint_t, GLint_t, const char*)>},
    {"glCopySubTextureCHROMIUM",
     WrapAs<void (*)(GLuint_t, GLint_t, GLenum_t, GLuint_t, GLint_t, GLint_t,
                     GLint_t, GLint_t, GLint_t, GLsizei_t, GLsizei_t, GLboolean_t,
                     GLboolean_t, GLboolean_t)>},
    {"glCopyTextureCHROMIUM",
     WrapAs<void (*)(GLuint_t, GLint_t, GLenum_t, GLuint_t, GLint_t, GLint_t,
                     GLenum_t, GLboolean_t, GLboolean_t, GLboolean_t)>},

    // GL_ANGLE_memory_object_flags / GL_ANGLE_vulkan_image
    {"glAcquireTexturesANGLE",
     WrapAs<void (*)(GLuint_t, const void*, const void*)>},
    {"glReleaseTexturesANGLE", WrapAs<void (*)(GLuint_t, const void*, void*)>},
    {"glTexStorageMemFlags2DANGLE",
     WrapAs<void (*)(GLenum_t, GLsizei_t, GLenum_t, GLsizei_t, GLsizei_t, GLuint_t,
                     GLuint64_t, GLbitfield_t, GLbitfield_t, const void*)>},

    // GL_ANGLE_blob_cache (guest callbacks — custom marshaller)
    {"glBlobCacheCallbacksANGLE", WrapAsCustom<DoTrampoline_glBlobCacheCallbacksANGLE>},

    // EGL_KHR_debug (guest callback — custom marshaller)
    {"eglDebugMessageControlKHR", WrapAsCustom<DoTrampoline_eglDebugMessageControlKHR>},

    // EGL_CHROMIUM_sync_control / EGL_ANGLE_sync_control_rate
    {"eglGetSyncValuesCHROMIUM",
     WrapAs<EGLBoolean_t (*)(void*, void*, void*, void*, void*)>},
    {"eglGetMscRateANGLE", WrapAs<EGLBoolean_t (*)(void*, void*, void*, void*)>},

    // Assorted ANGLE EGL extensions reachable on the Android Vulkan backend.
    {"eglExportVkImageANGLE", WrapAs<EGLBoolean_t (*)(void*, void*, void*, void*)>},
    {"eglHandleGPUSwitchANGLE", WrapAs<void (*)(void*)>},
    {"eglLockVulkanQueueANGLE", WrapAs<void (*)(void*)>},
    {"eglQueryDisplayAttribANGLE", WrapAs<EGLBoolean_t (*)(void*, EGLint_t, void*)>},
    {"eglQueryStringiANGLE", WrapAs<const char* (*)(void*, EGLint_t, EGLint_t)>},
    {"eglSetValidationEnabledANGLE", WrapAs<void (*)(EGLBoolean_t)>},
    {"eglUnlockVulkanQueueANGLE", WrapAs<void (*)(void*)>},
    {"eglWaitUntilWorkScheduledANGLE", WrapAs<void (*)(void*)>},
};

}  // namespace

const AngleProc* FindAngleProc(const char* name) {
  if (name == nullptr) {
    return nullptr;
  }
  for (const auto& proc : kAngleProcs) {
    if (strcmp(proc.name, name) == 0) {
      return &proc;
    }
  }
  return nullptr;
}

size_t AngleProcCount() {
  return sizeof(kAngleProcs) / sizeof(kAngleProcs[0]);
}

const AngleProc& AngleProcAt(size_t index) {
  return kAngleProcs[index];
}

}  // namespace berberis

#endif  // defined(__x86_64__)
