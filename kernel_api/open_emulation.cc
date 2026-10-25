/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "berberis/kernel_api/open_emulation.h"

// region digitalis
#include <errno.h>
// endregion
#include <fcntl.h>
#include <sys/stat.h>
// region digitalis
#include <sys/syscall.h>
// endregion
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
// region digitalis
#include <string>
#include <string_view>
// endregion
#include <utility>

#include "berberis/base/arena_alloc.h"
#include "berberis/base/arena_map.h"
// region digitalis
#include "berberis/base/arena_set.h"
// endregion
#include "berberis/base/arena_string.h"
#include "berberis/base/arena_vector.h"
#include "berberis/base/checks.h"
#include "berberis/base/fd.h"
#include "berberis/base/forever_alloc.h"
#include "berberis/base/tracing.h"
#include "berberis/guest_os_primitives/guest_map_shadow.h"
#include "berberis/guest_state/guest_addr.h"
#include "berberis/kernel_api/main_executable_real_path_emulation.h"

namespace berberis {

namespace {

class EmulatedFileDescriptors {
 public:
  explicit EmulatedFileDescriptors() : fds_(&arena_) {}

  static EmulatedFileDescriptors* GetInstance() {
    static auto* g_emulated_proc_self_maps_fds = NewForever<EmulatedFileDescriptors>();
    return g_emulated_proc_self_maps_fds;
  }

  // Not copyable or movable.
  EmulatedFileDescriptors(const EmulatedFileDescriptors&) = delete;
  EmulatedFileDescriptors& operator=(const EmulatedFileDescriptors&) = delete;

  void Add(int fd) {
    std::lock_guard lock(mutex_);
    auto [unused_it, inserted] = fds_.insert(std::make_pair(fd, 0));
    if (!inserted) {
      // We expect every fd to be added at most once. But if it breaks let's consider it non-fatal.
      TRACE("Detected duplicated fd in EmulatedFileDescriptors");
    }
  }

  bool Contains(int fd) {
    std::lock_guard lock(mutex_);
    return fds_.find(fd) != fds_.end();
  }

  void Remove(int fd) {
    std::lock_guard lock(mutex_);
    auto it = fds_.find(fd);
    if (it != fds_.end()) {
      fds_.erase(it);
    }
  }

 private:
  std::mutex mutex_;
  Arena arena_;
  // We use it as a set because we don't have ArenaSet, so client data isn't really used.
  ArenaMap<int, int> fds_;
};

// It's macro since we use it as string literal below.
#define PROC_SELF_MAPS "/proc/self/maps"

// Reader that works with custom allocator strings. Based on android::base::ReadFileToString.
template <typename String>
bool ReadProcSelfMapsToString(String& content) {
  int fd = open(PROC_SELF_MAPS, O_RDONLY);
  if (fd == -1) {
    return false;
  }
  char buf[4096] __attribute__((__uninitialized__));
  ssize_t n;
  while ((n = read(fd, &buf[0], sizeof(buf))) > 0) {
    content.append(buf, n);
  }
  close(fd);
  return n == 0;
}

// String split that works with custom allocator strings. Based on android::base::Split.
template <typename String>
ArenaVector<String> SplitLines(Arena* arena, const String& content) {
  ArenaVector<String> lines(arena);
  size_t base = 0;
  size_t found;
  while (true) {
    found = content.find_first_of('\n', base);
    lines.emplace_back(content, base, found - base, content.get_allocator());
    if (found == content.npos) break;
    base = found + 1;
  }
  return lines;
}

// region digitalis
#if defined(NATIVE_BRIDGE_GUEST_ARCH_ARM64)
// A mapped file, by the device and inode /proc/self/maps prints for it.
using MappedFileId = std::pair<uint64_t, uint64_t>;

// Reads the range, the host "x" bit and the file of a maps line. Returns false
// for a line that does not parse or maps no file (inode 0: anonymous memory,
// the stack, the vdso).
bool ParseMappedFileLine(const char* line,
                         uintptr_t* start,
                         uintptr_t* end,
                         bool* host_exec,
                         MappedFileId* file) {
  char perms[5];
  uint64_t offset;
  unsigned dev_major;
  unsigned dev_minor;
  uint64_t inode;
  if (sscanf(line,
             "%" SCNxPTR "-%" SCNxPTR " %4s %" SCNx64 " %x:%x %" SCNu64,
             start,
             end,
             perms,
             &offset,
             &dev_major,
             &dev_minor,
             &inode) != 7 ||
      inode == 0) {
    return false;
  }
  *host_exec = perms[2] == 'x';
  *file = MappedFileId((uint64_t{dev_major} << 32) | dev_minor, inode);
  return true;
}

bool HasGuestExecutablePart(GuestMapShadow* maps_shadow, uintptr_t start, uintptr_t end) {
  while (start < end) {
    auto [is_exec, region_size] =
        maps_shadow->GetExecutableRegionSize(GuestAddr(start), end - start);
    if (is_exec) {
      return true;
    }
    start += region_size;
  }
  return false;
}

// Host images: files the host has mapped with host code that the guest has not
// mapped as guest code, i.e. the x86_64 libraries and executables of the host
// side of the process. An arm64 device has none, and their in-memory headers
// are the host loader's: glibc relocates the d_ptr entries of a library's
// .dynamic in place, bionic does not. A guest integrity check that walks the
// maps for a system library (the host one carries an Android name), parses its
// dynamic section and adds the load bias again faults on a non-canonical
// address. A guest maps its own code without host "x" (the translator runs
// it), so a host "x" line is host code; a file that also holds guest code, as
// a guest JIT's double mapping can, stays the guest's.
template <typename Lines>
ArenaSet<MappedFileId> FindHostImages(Arena* arena, const Lines& lines, GuestMapShadow* maps_shadow) {
  ArenaSet<MappedFileId> host_code(arena);
  ArenaSet<MappedFileId> guest_code(arena);
  for (const auto& line : lines) {
    uintptr_t start;
    uintptr_t end;
    bool host_exec;
    MappedFileId file;
    if (!ParseMappedFileLine(line.c_str(), &start, &end, &host_exec, &file)) {
      continue;
    }
    if (HasGuestExecutablePart(maps_shadow, start, end)) {
      guest_code.insert(file);
    } else if (host_exec) {
      host_code.insert(file);
    }
  }
  for (const auto& file : guest_code) {
    host_code.erase(file);
  }
  return host_code;
}

template <typename String>
bool IsHostImageLine(const String& line, const ArenaSet<MappedFileId>& host_images) {
  uintptr_t start;
  uintptr_t end;
  bool host_exec;
  MappedFileId file;
  return ParseMappedFileLine(line.c_str(), &start, &end, &host_exec, &file) &&
         host_images.count(file) != 0;
}
#endif
// endregion

// Note that dirfd, flags and mode are only used to fallback to
// host's openat in case of failure.
// Avoid mallocs since bionic tests use it under malloc_disable (b/338211718).
int OpenatProcSelfMapsForGuest(int dirfd, int flags, mode_t mode) {
  TRACE("Openat for " PROC_SELF_MAPS);

  Arena arena;
  ArenaString file_data(&arena);
  bool success = ReadProcSelfMapsToString(file_data);
  if (!success) {
    TRACE("Cannot read " PROC_SELF_MAPS ", falling back to host's openat");
    return openat(dirfd, PROC_SELF_MAPS, flags, mode);
  }

  int mem_fd = CreateMemfdOrDie("[guest " PROC_SELF_MAPS "]");

  auto* maps_shadow = GuestMapShadow::GetInstance();

  auto lines = SplitLines(&arena, file_data);
  // region digitalis
#if defined(NATIVE_BRIDGE_GUEST_ARCH_ARM64)
  const auto host_images = FindHostImages(&arena, lines, maps_shadow);
#endif
  // endregion
  ArenaString guest_maps(&arena);
  for (size_t i = 0; i < lines.size(); i++) {
    uintptr_t start;
    uintptr_t end;
    int prot_offset;
    auto& cur_line = lines.at(i);
    if (sscanf(cur_line.c_str(), "%" SCNxPTR "-%" SCNxPTR " %n", &start, &end, &prot_offset) != 2) {
      if (!cur_line.empty()) {
        TRACE("Cannot parse " PROC_SELF_MAPS " line : %s", cur_line.c_str());
      }
      guest_maps.append(cur_line + "\n");
      continue;
    }
    // region digitalis
#if defined(NATIVE_BRIDGE_GUEST_ARCH_ARM64)
    // Give the guest a coherent ARM64 view of the dynamic linker. The process
    // has two linkers mapped: the guest ARM64 linker at
    // "/system/bin/arm64/linker64" (the real one for guest code, translated) and
    // the host x86_64 linker at "/apex/com.android.runtime/bin/linker64" (the
    // process's actual ELF interpreter). App introspection hard-codes the
    // canonical device linker paths — "/apex/com.android.runtime/bin/linker64",
    // "/system/bin/linker64" — and finds the linker's load base by matching one
    // of them in /proc/self/maps. On a real ARM64 device those paths ARE the
    // ARM64 linker; here they resolve to the HOST x86_64 linker, so an app that
    // pairs that host base with the ARM64 linker's symbol offset (which openat
    // redirection serves) reads host machine code as a guest pointer and
    // crashes (the MSA OAID SDK's soinfo-list anti-tamper walk did exactly this).
    // Rewrite the guest linker's path to the canonical location apps expect, and
    // drop the host linker's lines so introspection can't latch onto it.
    // Every other host image is dropped as well (FindHostImages).
    if (IsHostImageLine(cur_line, host_images)) {
      continue;
    }
    {
      static constexpr char kGuestArm64LinkerPath[] = "/system/bin/arm64/linker64";
      static constexpr char kCanonicalLinkerPath[] = "/apex/com.android.runtime/bin/linker64";
      size_t gpos = cur_line.find(kGuestArm64LinkerPath);
      if (gpos != ArenaString::npos) {
        cur_line.replace(gpos, sizeof(kGuestArm64LinkerPath) - 1, kCanonicalLinkerPath);
      } else if (cur_line.find(kCanonicalLinkerPath) != ArenaString::npos) {
        // Host x86_64 linker — hide it from the guest's view. FindHostImages
        // already drops it as a host image; this keeps the name check for a
        // linker mapped without host code.
        continue;
      }
    }
#endif
    // endregion
    // Split the line into guest exec / no-exec chunks.
    uintptr_t original_start = start;
    while (start < end) {
      auto [is_exec, region_size] =
          maps_shadow->GetExecutableRegionSize(GuestAddr(start), end - start);
      // prot_offset points to "rwxp", so offset of "x" is 2 symbols away.
      cur_line.at(prot_offset + 2) = is_exec ? 'x' : '-';
      if ((start == original_start) && ((start + region_size) >= end)) {
        // Most often we should be able to just take the whole host line.
        guest_maps.append(cur_line);
        guest_maps.append("\n");
        break;
      }
      // We cannot print into cur_line in place since we don't want the terminating null. Also the
      // new range can theoretically be longer than the old one. E.g. if "a000-ba000" (len=10) is
      // split into "a000-aa000" (len=10) and "aa000-ba000" (len=11).
      // At max, for 64-bit pointers, we need 16(ptr)+1(-)+16(ptr)+1(\0)=34 symbols buffer,
      // so 64-bytes should be more than enough.
      char addr_range_buf[64];
      int chars_num = snprintf(addr_range_buf,
                               sizeof(addr_range_buf),
                               "%" PRIxPTR "-%" PRIxPTR,
                               start,
                               start + region_size);
      CHECK_LT(static_cast<size_t>(chars_num), sizeof(addr_range_buf));
      guest_maps.append(addr_range_buf);
      // Append the rest of the line starting from protections and including the front space.
      guest_maps.append(cur_line.data() + prot_offset - 1);
      guest_maps.append("\n");
      start += region_size;
    }
  }

  // Normally /proc/self/maps doesn't have newline at the end.
  // It's simpler to remove it than to not add it in the loop.
  CHECK_EQ(guest_maps.back(), '\n');
  guest_maps.pop_back();

  TRACE("--------\n%s\n--------", guest_maps.c_str());

  WriteFullyOrDie(mem_fd, guest_maps.c_str(), guest_maps.size());

  lseek(mem_fd, 0, 0);

  EmulatedFileDescriptors::GetInstance()->Add(mem_fd);

  return mem_fd;
}

// region digitalis
// Whether `st` is the identity of the file at `reference_path` (same device and inode).
bool IsSameFileAs(const struct stat& st, const char* reference_path) {
  struct stat reference_stat;
  return stat(reference_path, &reference_stat) == 0 && st.st_ino == reference_stat.st_ino &&
         st.st_dev == reference_stat.st_dev;
}

bool IsProcSelfMapsStat(const struct stat& st) {
  return IsSameFileAs(st, PROC_SELF_MAPS);
}
// endregion

bool IsProcSelfMaps(int dirfd, const char* path, int flags) {
  struct stat cur_stat;
  // This check works for /proc/self/maps itself as well as symlinks (unless AT_SYMLINK_NOFOLLOW is
  // requested). As an added benefit it gracefully handles invalid pointers in path.
  // region digitalis
  // `path` is looked up relative to `dirfd`, like the openat it is part of. A relative path (for
  // example "maps" or "./maps" under an open /proc/self, or "self/maps" under /proc) must not be
  // resolved against the current directory: it would then miss the emulated view and the guest
  // would read the raw host file.
  // endregion
  return fstatat(dirfd, path, &cur_stat, 0) == 0 &&
         !(S_ISLNK(cur_stat.st_mode) && (flags & AT_SYMLINK_NOFOLLOW)) &&
         IsProcSelfMapsStat(cur_stat);
}

// In zygote this is not needed because native bridge is mounting
// /proc/cpuinfo to point to the emulated version. But for executables
// this does not happen and they end up reading host cpuinfo.
//
// Note that current selinux policies prevent us from mounting /proc/cpuinfo
// (replicating what zygote process does) for executables hence we need to
// emulate it here.
// region digitalis
// The arm64 guest must see its own cpuinfo on every host libc, not only on
// Android, so the host unit tests can check what OpenatForGuest serves.
#if defined(__ANDROID__) || defined(NATIVE_BRIDGE_GUEST_ARCH_ARM64)
#define BERBERIS_EMULATES_PROC_CPUINFO 1
#endif

// Whether `st` is /proc/cpuinfo, which the guest sees as its own cpuinfo.
bool IsProcCpuinfoStat([[maybe_unused]] const struct stat& st) {
#ifdef BERBERIS_EMULATES_PROC_CPUINFO
  return IsSameFileAs(st, "/proc/cpuinfo");
#else
  return false;
#endif
}
// endregion

const char* TryTranslateProcCpuinfoPath(int dirfd, const char* path, int flags) {
#ifdef BERBERIS_EMULATES_PROC_CPUINFO
  struct stat cur_stat;

  // region digitalis
  // Looked up relative to dirfd, see IsProcSelfMaps.
  // endregion
  if (fstatat(dirfd, path, &cur_stat, 0) == -1) {
    return nullptr;
  }

  if (S_ISLNK(cur_stat.st_mode) && (flags & AT_SYMLINK_NOFOLLOW)) {
    return nullptr;
  }

  if (IsProcCpuinfoStat(cur_stat)) {
    TRACE("openat: Translating %s to %s", path, kGuestCpuinfoPath);
    return kGuestCpuinfoPath;
  }
#else
  UNUSED(dirfd, path, flags);
#endif
  return nullptr;
}

// region digitalis
#if defined(NATIVE_BRIDGE_GUEST_ARCH_ARM64)
// Serve a guest /proc/cpuinfo synthesized from the real online CPU count out of
// a memfd, instead of opening the static kGuestCpuinfoPath file. This keeps the
// guest-visible core count in sync with the actual emulator/host CPU config
// rather than a hard-coded value. Mirrors OpenatProcSelfMapsForGuest's
// synthesize-into-a-memfd approach.
int OpenatProcCpuinfoForGuest(int dirfd, int flags, mode_t mode) {
  long online = sysconf(_SC_NPROCESSORS_ONLN);
  std::string content = FormatGuestCpuinfo(online > 0 ? static_cast<int>(online) : 1);
  if (content.empty()) {
    // Unreachable in practice (FormatGuestCpuinfo always emits >=1 block); fall
    // back to the static file so behaviour degrades rather than breaks.
    return openat(dirfd, kGuestCpuinfoPath, flags, mode);
  }
  int mem_fd = CreateMemfdOrDie("[guest /proc/cpuinfo]");
  WriteFullyOrDie(mem_fd, content.c_str(), content.size());
  lseek(mem_fd, 0, 0);
  TRACE("Openat for /proc/cpuinfo: synthesized %zu bytes for %ld online cpu(s)",
        content.size(), online);
  return mem_fd;
}
#endif
// endregion

}  // namespace

bool IsFileDescriptorEmulatedProcSelfMaps(int fd) {
  return EmulatedFileDescriptors::GetInstance()->Contains(fd);
}

void CloseEmulatedProcSelfMapsFileDescriptor(int fd) {
  EmulatedFileDescriptors::GetInstance()->Remove(fd);
}

// region digitalis
#if defined(NATIVE_BRIDGE_GUEST_ARCH_ARM64)
inline constexpr char kSystemArm64LibcxxPath[] = "/system/lib64/arm64/libc++.so";

// An app can ship the NDK's libc++.so, which is a GNU-ld linker script
// ("INPUT(-landroid_support -lc++_shared)"), not an ELF. The guest linker cannot
// parse it and aborts the dlopen ("too small to be an ELF executable"). Because
// the arm64 system library paths are flattened into the app namespace's search
// path with the app dir first (see native_bridge.cc CreateNamespace), this
// app-bundled script shadows the real /system/lib64/arm64/libc++.so — e.g.
// liblog.so (a transitive dependency of libmmkv.so) NEEDs libc++.so and resolves
// the broken script, crashing QQInput's TinkerSimpleApplication at startup. When
// the guest opens such a script, redirect to the real system libc++.so, which
// provides the same C++ runtime symbols.
const char* TryRedirectNdkLibcxxLinkerScript(const char* path) {
  if (path == nullptr) {
    return nullptr;
  }
  size_t len = strlen(path);
  static constexpr char kSuffix[] = "/libc++.so";
  constexpr size_t kSuffixLen = sizeof(kSuffix) - 1;
  if (len < kSuffixLen || strcmp(path + len - kSuffixLen, kSuffix) != 0) {
    return nullptr;
  }
  if (strcmp(path, kSystemArm64LibcxxPath) == 0) {
    return nullptr;  // already the real system copy
  }
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return nullptr;
  }
  char magic[4] = {};
  ssize_t n = read(fd, magic, sizeof(magic));
  close(fd);
  // A real ELF starts with 0x7f 'E' 'L' 'F' — leave those alone.
  if (n >= 4 && magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
    return nullptr;
  }
  // Non-ELF (the NDK GNU-ld linker script): redirect to the real system libc++.so.
  TRACE("openat: redirecting NDK libc++.so linker script \"%s\" to %s", path,
        kSystemArm64LibcxxPath);
  return kSystemArm64LibcxxPath;
}

inline constexpr char kGuestLinker64SelfPath[] = "/system/bin/linker64";
inline constexpr char kGuestLinker64RealPath[] = "/system/bin/arm64/linker64";

// The guest ARM64 dynamic linker sets its own realpath to the main executable's
// PT_INTERP string — "/system/bin/linker64" — and reports that as its name via
// dl_iterate_phdr. On the x86_64 host image that canonical path is a symlink to
// the HOST x86_64 linker (/apex/com.android.runtime/bin/linker64); the guest
// ARM64 linker actually lives at /system/bin/arm64/linker64. Guest code that
// resolves the linker's own non-exported internals by re-opening its reported
// path to read .symtab — ByteDance's xDL (used by ShadowHook and ByteHook), and
// any similar linker introspection — therefore opens a wrong-architecture ELF.
// It reads the section-header table from that x86_64 file at the *guest* linker's
// in-memory e_shoff, gets garbage, fails to locate .symtab, and cannot resolve
// symbols like soinfo::call_constructors — so ShadowHook aborts init with
// SHADOWHOOK_ERRNO_INIT_LINKER and native hooking is silently disabled. Redirect
// guest opens of the canonical linker path to the real ARM64 linker file so this
// introspection reads the correct ELF.
const char* TryRedirectGuestLinker64(const char* path) {
  if (path == nullptr || strcmp(path, kGuestLinker64SelfPath) != 0) {
    return nullptr;
  }
  TRACE("openat: redirecting guest linker \"%s\" to %s", path, kGuestLinker64RealPath);
  return kGuestLinker64RealPath;
}

inline constexpr char kGuestSystemLibraryDir[] = "/system/lib64/arm64";

// On the x86_64 host image /system/lib64 holds the host's libraries, and the
// runtime APEX's bionic directory links to them; the guest's arm64 copies are
// in /system/lib64/arm64. The guest linker searches that directory, but a guest
// that loads a library itself (a hardening loader that decrypts and maps an
// app library, then resolves its DT_NEEDED entries by opening each one at its
// canonical device path and reading its ELF header) would read an x86_64 ELF
// and give up on the library. Such a guest opens the arm64 copy instead, as it
// would on a device. A host library without an arm64 copy keeps its path.
std::string GuestSystemLibraryPathFor(const char* path, const char* guest_library_dir) {
  if (path == nullptr || guest_library_dir == nullptr) {
    return {};
  }
  static constexpr std::string_view kHostLibraryDirs[] = {
      "/system/lib64/",
      "/apex/com.android.runtime/lib64/bionic/",
  };
  const std::string_view requested(path);
  for (const auto dir : kHostLibraryDirs) {
    if (!requested.starts_with(dir)) {
      continue;
    }
    const auto name = requested.substr(dir.size());
    if (name.empty() || name == "." || name == ".." || name.find('/') != std::string_view::npos) {
      return {};
    }
    std::string guest_path(guest_library_dir);
    guest_path += '/';
    guest_path += name;
    struct stat guest_stat;
    if (stat(guest_path.c_str(), &guest_stat) != 0 || !S_ISREG(guest_stat.st_mode)) {
      return {};
    }
    return guest_path;
  }
  return {};
}
#endif  // NATIVE_BRIDGE_GUEST_ARCH_ARM64
// endregion

int OpenatForGuest(int dirfd, const char* path, int guest_flags, mode_t mode) {
  int host_flags = ToHostOpenFlags(guest_flags);

  if (IsProcSelfMaps(dirfd, path, host_flags)) {
    return OpenatProcSelfMapsForGuest(dirfd, host_flags, mode);
  }

  const char* real_path = nullptr;
  if ((host_flags & AT_SYMLINK_NOFOLLOW) == 0) {
    real_path = TryReadLinkToMainExecutableRealPath(dirfd, path);
  }

  if (real_path == nullptr) {
    real_path = TryTranslateProcCpuinfoPath(dirfd, path, host_flags);
  }

  // region digitalis
#if defined(NATIVE_BRIDGE_GUEST_ARCH_ARM64)
  if (real_path == nullptr) {
    real_path = TryRedirectNdkLibcxxLinkerScript(path);
  }
  if (real_path == nullptr) {
    real_path = TryRedirectGuestLinker64(path);
  }
  std::string guest_library_path;
  if (real_path == nullptr) {
    guest_library_path = GuestSystemLibraryPathFor(path, kGuestSystemLibraryDir);
    if (!guest_library_path.empty()) {
      TRACE("openat: opening the guest copy %s of host library \"%s\"",
            guest_library_path.c_str(),
            path);
      real_path = guest_library_path.c_str();
    }
  }
#endif

#if defined(NATIVE_BRIDGE_GUEST_ARCH_ARM64)
  // For the arm64 guest, synthesize /proc/cpuinfo from the real online CPU
  // count instead of opening the static kGuestCpuinfoPath file. TryTranslate...
  // returns exactly that sentinel pointer when it matched /proc/cpuinfo.
  if (real_path == kGuestCpuinfoPath) {
    return OpenatProcCpuinfoForGuest(dirfd, host_flags, mode);
  }
#endif
  // endregion

  return openat(dirfd, real_path != nullptr ? real_path : path, host_flags, mode);
}

int OpenForGuest(const char* path, int flags, mode_t mode) {
  return OpenatForGuest(AT_FDCWD, path, flags, mode);
}

// region digitalis
namespace {

#ifndef __NR_openat2
#define __NR_openat2 437
#endif

// struct open_how at its first version (OPEN_HOW_SIZE_VER0, still the latest). The layout does not
// depend on the architecture, so the guest's struct can be read, and the host's built, with it.
struct OpenHow {
  uint64_t flags;
  uint64_t mode;
  uint64_t resolve;
};
constexpr size_t kOpenHowSizeVer0 = sizeof(OpenHow);
static_assert(kOpenHowSizeVer0 == 24);
// The kernel does not limit the size of a larger struct; a guest passing more than a page is
// either broken or probing, and its tail cannot be vouched for. Refuse it the way the kernel
// refuses a struct with unknown fields set.
constexpr size_t kOpenHowMaxSize = 4096;
// RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH |
// RESOLVE_IN_ROOT | RESOLVE_CACHED.
constexpr uint64_t kValidResolveMask = 0x3f;
// The host's __O_TMPFILE; O_TMPFILE is this together with O_DIRECTORY.
constexpr int kHostOTmpfileBit = 020000000;
constexpr uint64_t kModeMask = 07777;

// Resolves `path` under `dirfd` with the guest's resolve restrictions, the way the host kernel
// would for the open itself, without opening it, and stores what it names in `*resolved`. Returns
// false, with the kernel's errno, if the kernel refuses. The open flags that change what the path
// names are carried over (O_NOFOLLOW keeps a final symlink as the symlink).
bool ResolveForOpenat2(
    int dirfd, const char* path, int host_flags, uint64_t resolve, struct stat* resolved) {
  OpenHow probe = {
      static_cast<uint64_t>(O_PATH | O_CLOEXEC | (host_flags & O_NOFOLLOW)), 0, resolve};
  int fd = static_cast<int>(syscall(__NR_openat2, dirfd, path, &probe, sizeof(probe)));
  if (fd < 0) {
    return false;
  }
  int result = fstat(fd, resolved);
  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
  return result == 0;
}

}  // namespace

int Openat2ForGuest(int dirfd, const char* path, const void* how_ptr, size_t size) {
  // Check the struct in the order the kernel does, so that a guest probing for the syscall's
  // error contract gets the same answers as on a real device.
  if (size < kOpenHowSizeVer0) {
    errno = EINVAL;
    return -1;
  }
  if (size > kOpenHowMaxSize) {
    errno = E2BIG;
    return -1;
  }
  if (how_ptr == nullptr) {
    errno = EFAULT;
    return -1;
  }
  const auto* bytes = static_cast<const unsigned char*>(how_ptr);
  OpenHow how;
  memcpy(&how, bytes, sizeof(how));
  for (size_t i = sizeof(how); i < size; ++i) {
    if (bytes[i] != 0) {
      errno = E2BIG;
      return -1;
    }
  }
  if (how.flags > UINT32_MAX || (how.resolve & ~kValidResolveMask) != 0) {
    errno = EINVAL;
    return -1;
  }
  const int host_flags = ToHostOpenFlags(static_cast<int>(static_cast<uint32_t>(how.flags)));
  const bool creates = (host_flags & (O_CREAT | kHostOTmpfileBit)) != 0;
  if (creates ? (how.mode & ~kModeMask) != 0 : how.mode != 0) {
    errno = EINVAL;
    return -1;
  }
  const mode_t mode = static_cast<mode_t>(how.mode);

  // Same emulated views as OpenatForGuest. Only O_CLOEXEC of the open flags applies to them.
  //
  // The resolve restrictions decide what the path names, or whether it names anything: on a real
  // device RESOLVE_NO_SYMLINKS fails on "/proc/self/maps" (ELOOP), RESOLVE_BENEATH fails on an
  // absolute path (EXDEV) and RESOLVE_IN_ROOT looks it up under dirfd. So when the guest asks for
  // any, the host kernel resolves the path under those restrictions first (see ResolveForOpenat2)
  // and the view is served only if that is the file the view stands for. A path the kernel refuses
  // gets its error, and no view. Without restrictions the lookup that OpenatForGuest does decides.
  bool serve_maps = false;
  bool serve_cpuinfo = false;
  if (how.resolve == 0) {
    serve_maps = IsProcSelfMaps(dirfd, path, host_flags);
    serve_cpuinfo = !serve_maps && TryTranslateProcCpuinfoPath(dirfd, path, host_flags) != nullptr;
  } else {
    struct stat resolved;
    if (ResolveForOpenat2(dirfd, path, host_flags, how.resolve, &resolved)) {
      serve_maps = IsProcSelfMapsStat(resolved);
      serve_cpuinfo = !serve_maps && IsProcCpuinfoStat(resolved);
    } else if (!creates) {
      return -1;
    }
    // A creating open may name a file that does not exist yet, which the resolution cannot find.
    // Nothing is served for it, and the host openat2 below gives the kernel's answer.
  }
  if (serve_maps) {
    return OpenatProcSelfMapsForGuest(dirfd, host_flags, mode);
  }
  if (serve_cpuinfo) {
#if defined(NATIVE_BRIDGE_GUEST_ARCH_ARM64)
    return OpenatProcCpuinfoForGuest(dirfd, host_flags, mode);
#else
    return static_cast<int>(openat(AT_FDCWD, kGuestCpuinfoPath, host_flags, mode));
#endif
  }

  // Anything else is the host's to open, with the guest's open flags in the host's encoding.
  OpenHow host_how = {static_cast<uint64_t>(static_cast<uint32_t>(host_flags)), how.mode,
                      how.resolve};
  return static_cast<int>(syscall(__NR_openat2, dirfd, path, &host_how, sizeof(host_how)));
}
// endregion

}  // namespace berberis
