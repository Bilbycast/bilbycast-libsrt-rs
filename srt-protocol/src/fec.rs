// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Minimal FEC config parser for validation.
//!
//! The actual FEC encoding/decoding is handled by libsrt natively.
//! This module only provides [`FecConfig::parse`] so that the edge's
//! config validation can check packet_filter strings at load time.

use std::fmt;

/// FEC matrix layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecLayout {
    Even,
    Staircase,
}

/// ARQ interaction mode with FEC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArqMode {
    Always,
    OnReq,
    Never,
}

/// FEC filter configuration.
///
/// Parsed from the libsrt-compatible config string format:
/// `"fec,cols:10,rows:5,layout:staircase,arq:onreq"`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FecConfig {
    pub cols: usize,
    pub rows: usize,
    pub layout: FecLayout,
    pub arq: ArqMode,
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            cols: 10,
            rows: 1,
            layout: FecLayout::Staircase,
            arq: ArqMode::OnReq,
        }
    }
}

impl FecConfig {
    /// Parse a libsrt-compatible packet filter config string.
    ///
    /// Format: `"fec,cols:10,rows:5,layout:staircase,arq:onreq"`
    pub fn parse(config_str: &str) -> Result<Self, String> {
        let trimmed = config_str.trim();
        if trimmed.is_empty() {
            return Err("empty config string".to_string());
        }

        let parts: Vec<&str> = trimmed.splitn(2, ',').collect();
        if parts[0].trim() != "fec" {
            return Err(format!("config must start with 'fec', got '{}'", parts[0]));
        }

        let mut config = FecConfig::default();

        if parts.len() < 2 {
            return Ok(config);
        }

        for param in parts[1].split(',') {
            let param = param.trim();
            if param.is_empty() {
                continue;
            }
            let kv: Vec<&str> = param.splitn(2, ':').collect();
            if kv.len() != 2 {
                return Err(format!("invalid parameter '{}', expected key:value", param));
            }
            let key = kv[0].trim();
            let value = kv[1].trim();

            match key {
                "cols" => {
                    config.cols = value.parse::<usize>()
                        .map_err(|_| format!("invalid cols value: '{value}'"))?;
                    if config.cols == 0 {
                        return Err("cols must be >= 1".to_string());
                    }
                }
                "rows" => {
                    let raw: i64 = value.parse()
                        .map_err(|_| format!("invalid rows value: '{value}'"))?;
                    config.rows = raw.unsigned_abs() as usize;
                    if config.rows == 0 {
                        return Err("rows must be >= 1".to_string());
                    }
                }
                "layout" => {
                    config.layout = match value {
                        "even" => FecLayout::Even,
                        "staircase" => FecLayout::Staircase,
                        _ => return Err(format!("invalid layout: '{value}', expected 'even' or 'staircase'")),
                    };
                }
                "arq" => {
                    config.arq = match value {
                        "always" => ArqMode::Always,
                        "onreq" => ArqMode::OnReq,
                        "never" => ArqMode::Never,
                        _ => return Err(format!("invalid arq: '{value}', expected 'always', 'onreq', or 'never'")),
                    };
                }
                _ => {
                    // Ignore unknown keys (forward compatibility)
                }
            }
        }

        Ok(config)
    }
}

impl fmt::Display for FecConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let layout = match self.layout {
            FecLayout::Even => "even",
            FecLayout::Staircase => "staircase",
        };
        let arq = match self.arq {
            ArqMode::Always => "always",
            ArqMode::OnReq => "onreq",
            ArqMode::Never => "never",
        };
        write!(f, "fec,cols:{},rows:{},layout:{},arq:{}", self.cols, self.rows, layout, arq)
    }
}
