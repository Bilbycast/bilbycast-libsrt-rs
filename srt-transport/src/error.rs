// Copyright (c) 2026 Reza Rahimi / Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Error mapping from libsrt C error codes to Rust SrtError.

use srt_protocol::error::SrtError;

/// Get the last SRT error from libsrt and convert to SrtError.
pub(crate) fn last_srt_error() -> SrtError {
    let code = libsrt_sys::last_error_code();
    SrtError::from_code(code)
}
