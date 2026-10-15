// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "adapter.h"

namespace vp {
// Process-local state of one handle, never a transferable cache or owner ID.
// Legacy calls leave session_active false and retain their existing behavior.
struct session_state {
    uint32_t used = 0;
    uint32_t generated = 0;
    bool ready = false;
    bool failed = false;
    bool session_active = false;
};

inline int32_t invalid_session(session_state * value) {
    if (value && value->session_active) {
        value->ready = false;
        value->failed = true;
    }
    return VP_INVALID;
}

inline bool session_sample_allowed(const session_state & value) {
    return value.generated < 1024 && (value.generated != 0 || value.used <= 12288);
}

// The production callbacks operate on the same already-synchronized context.
// Tests can exercise every failure boundary without a model or synthetic KV
// contents being admitted as an inference result. Any partial reset poisons the
// handle: callers must close it, never silently clear/reload and continue.
template<class Cancelled, class Synchronize, class Truncate, class Reset>
int32_t begin_session_turn(session_state & value, uint32_t retained, uint32_t capacity,
    Cancelled cancelled, Synchronize synchronize, Truncate truncate, Reset reset) {
    value.ready = false; // Old logits can never be sampled after begin_turn.
    if (value.failed || value.used > capacity || retained > value.used ||
        retained >= capacity || retained >= 12288) {
        value.failed = true;
        return VP_INVALID;
    }
    try {
        if (cancelled()) { value.failed = true; return VP_ABORTED; }
        synchronize();
        if (cancelled()) { value.failed = true; return VP_ABORTED; }
        if (!truncate(retained)) { value.failed = true; return VP_BACKEND; }
        if (cancelled()) { value.failed = true; return VP_ABORTED; }
        reset();
        if (cancelled()) { value.failed = true; return VP_ABORTED; }
        value.used = retained;
        value.generated = 0;
        value.session_active = true;
        return VP_OK;
    } catch (...) {
        value.failed = true;
        return VP_BACKEND;
    }
}
}
