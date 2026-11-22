// SPDX-FileCopyrightText: 2026 Actinis OÜ
// SPDX-License-Identifier: EUPL-1.2

#include "gtest/gtest.h"

#include <cstring>
#include <set>
#include <string>

#include "digitalis_extra_libegl_angle_procs.h"

namespace berberis {

namespace {

// Every entry point of an extension ANGLE advertises must be wrappable:
// a guest that sees the extension and gets NULL for one of its procs either
// calls address 0 or, like Skia's GrGLInterface::validate(), drops the whole
// GL interface.
TEST(DigitalisEglAngleProcs, CoversAngleBaseVertexBaseInstance) {
  for (const char* name : {"glDrawArraysInstancedBaseInstanceANGLE",
                           "glDrawElementsInstancedBaseVertexBaseInstanceANGLE",
                           "glMultiDrawArraysInstancedBaseInstanceANGLE",
                           "glMultiDrawElementsInstancedBaseVertexBaseInstanceANGLE"}) {
    const AngleProc* proc = FindAngleProc(name);
    ASSERT_NE(proc, nullptr) << name;
    EXPECT_STREQ(proc->name, name);
    EXPECT_NE(proc->wrap, nullptr) << name;
  }
}

TEST(DigitalisEglAngleProcs, CoversChromiumBindUniformLocation) {
  EXPECT_NE(FindAngleProc("glBindUniformLocationCHROMIUM"), nullptr);
}

TEST(DigitalisEglAngleProcs, UnknownOrNullNameIsNotCovered) {
  EXPECT_EQ(FindAngleProc("glNotARealProcANGLE"), nullptr);
  EXPECT_EQ(FindAngleProc(""), nullptr);
  EXPECT_EQ(FindAngleProc(nullptr), nullptr);
}

TEST(DigitalisEglAngleProcs, EveryEntryIsNamedOnceAndWrappable) {
  std::set<std::string> names;
  ASSERT_GT(AngleProcCount(), 0u);
  for (size_t index = 0; index < AngleProcCount(); ++index) {
    const AngleProc& proc = AngleProcAt(index);
    ASSERT_NE(proc.name, nullptr) << index;
    EXPECT_GT(strlen(proc.name), 0u) << index;
    EXPECT_NE(proc.wrap, nullptr) << proc.name;
    EXPECT_TRUE(names.insert(proc.name).second) << "duplicate " << proc.name;
    EXPECT_EQ(FindAngleProc(proc.name), &proc) << proc.name;
  }
}

}  // namespace

}  // namespace berberis
