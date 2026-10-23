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

#include "berberis/kernel_api/main_executable_real_path_emulation.h"

// region digitalis
#include <fcntl.h>
// endregion
#include <sys/stat.h>

#include "berberis/base/config_globals.h"
#include "berberis/base/scoped_errno.h"

namespace berberis {

const char* TryReadLinkToMainExecutableRealPath(int dirfd, const char* pathname) {
  ScopedErrno scoped_errno;

  // /proc/self/exe and /proc/<pid>/exe are the same file, as /proc/self is a link to /proc/<pid>!
  // So we only need to check if /proc/self/exe and 'pathname' refer to the same (link) file.
  // lstat doesn't follow symlinks (we still want program_runner to be accessible by direct path)!
  // The st_ino and st_dev fields taken together uniquely identify the file within the system.
  // Do not cache /proc/self/exe lstat to handle situations after fork/clone!
  struct stat cur_stat;
  struct stat exe_stat;
  // region digitalis
  // A relative `pathname` is looked up relative to `dirfd` (like the openat it is part of), not
  // relative to the current directory, so that openat(selffd, "exe") is recognised as well.
  const bool found_path = fstatat(dirfd, pathname, &cur_stat, AT_SYMLINK_NOFOLLOW) == 0;
  // endregion
  if (found_path && lstat("/proc/self/exe", &exe_stat) == 0 &&
      cur_stat.st_ino == exe_stat.st_ino && cur_stat.st_dev == exe_stat.st_dev) {
    return berberis::GetMainExecutableRealPath();
  }

  return nullptr;
}

}  // namespace berberis
