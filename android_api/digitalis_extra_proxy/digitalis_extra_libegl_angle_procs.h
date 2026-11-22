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

#ifndef BERBERIS_ANDROID_API_DIGITALIS_EXTRA_PROXY_DIGITALIS_EXTRA_LIBEGL_ANGLE_PROCS_H_
#define BERBERIS_ANDROID_API_DIGITALIS_EXTRA_PROXY_DIGITALIS_EXTRA_LIBEGL_ANGLE_PROCS_H_

#include <cstddef>

#include "berberis/runtime_primitives/host_code.h"

namespace berberis {

// One extension entry point the eglGetProcAddress override can make
// guest-callable: `wrap` registers the host function with the marshaller for
// its exact prototype.
struct AngleProc {
  const char* name;
  void (*wrap)(HostCode fn, const char* name);
};

// The wrap-table entry for `name`, or nullptr when the table does not cover it
// (or `name` is nullptr).
const AngleProc* FindAngleProc(const char* name);

// The table itself, for tests that check its coverage.
size_t AngleProcCount();
const AngleProc& AngleProcAt(size_t index);

}  // namespace berberis

#endif  // BERBERIS_ANDROID_API_DIGITALIS_EXTRA_PROXY_DIGITALIS_EXTRA_LIBEGL_ANGLE_PROCS_H_
