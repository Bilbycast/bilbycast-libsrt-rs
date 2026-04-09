// Copyright (c) 2026 Reza Rahimi / Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT error types.
//!
//! Provides [`SrtError`] with 35+ error codes matching the C `SRT_ERRNO` enum,
//! plus [`RejectReason`] for connection rejection causes.

use std::fmt;

/// Major error categories matching the C SRT library's CodeMajor enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    Success,
    Setup,
    Connection,
    SystemResource,
    FileSystem,
    NotSupported,
    Again,
    PeerError,
    Unknown,
}

/// SRT error codes matching the C `SRT_ERRNO` enum.
///
/// Error codes are structured as `major * 1000 + minor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SrtError {
    // Success
    Success = 0,

    // Setup errors (1xxx)
    ConnectionSetup = 1000,
    NoServer = 1001,
    ConnectionRejected = 1002,
    SocketFail = 1003,
    SecurityFail = 1004,
    SocketClosed = 1005,

    // Connection errors (2xxx)
    ConnectionFail = 2000,
    ConnectionLost = 2001,
    NoConnection = 2002,

    // System resource errors (3xxx)
    Resource = 3000,
    Thread = 3001,
    NoBuffer = 3002,
    SysObject = 3003,

    // File system errors (4xxx)
    File = 4000,
    InvalidReadOffset = 4001,
    ReadPermission = 4002,
    InvalidWriteOffset = 4003,
    WritePermission = 4004,

    // Not supported errors (5xxx)
    InvalidOperation = 5000,
    BoundSocket = 5001,
    ConnectedSocket = 5002,
    InvalidParam = 5003,
    InvalidSocket = 5004,
    UnboundSocket = 5005,
    NoListen = 5006,
    RendezvousNoServer = 5007,
    RendezvousUnbound = 5008,
    InvalidMessageApi = 5009,
    InvalidBufferApi = 5010,
    DuplicateListen = 5011,
    LargeMessage = 5012,
    InvalidPollId = 5013,
    PollEmpty = 5014,
    BindConflict = 5015,

    // Again errors (6xxx)
    AsyncFail = 6000,
    AsyncSend = 6001,
    AsyncRecv = 6002,
    Timeout = 6003,
    Congestion = 6004,

    // Peer error (7xxx)
    PeerError = 7000,

    // Unknown
    Unknown = -1,
}

impl SrtError {
    /// Get the major error category.
    pub fn kind(&self) -> ErrorKind {
        let code = *self as i32;
        if code < 0 {
            return ErrorKind::Unknown;
        }
        match code / 1000 {
            0 => ErrorKind::Success,
            1 => ErrorKind::Setup,
            2 => ErrorKind::Connection,
            3 => ErrorKind::SystemResource,
            4 => ErrorKind::FileSystem,
            5 => ErrorKind::NotSupported,
            6 => ErrorKind::Again,
            7 => ErrorKind::PeerError,
            _ => ErrorKind::Unknown,
        }
    }

    /// Get the raw error code as an i32.
    pub fn code(&self) -> i32 {
        *self as i32
    }

    /// Convert from a raw libsrt error code.
    pub fn from_code(code: i32) -> Self {
        match code {
            0 => Self::Success,
            1000 => Self::ConnectionSetup,
            1001 => Self::NoServer,
            1002 => Self::ConnectionRejected,
            1003 => Self::SocketFail,
            1004 => Self::SecurityFail,
            1005 => Self::SocketClosed,
            2000 => Self::ConnectionFail,
            2001 => Self::ConnectionLost,
            2002 => Self::NoConnection,
            3000 => Self::Resource,
            3001 => Self::Thread,
            3002 => Self::NoBuffer,
            3003 => Self::SysObject,
            4000 => Self::File,
            4001 => Self::InvalidReadOffset,
            4002 => Self::ReadPermission,
            4003 => Self::InvalidWriteOffset,
            4004 => Self::WritePermission,
            5000 => Self::InvalidOperation,
            5001 => Self::BoundSocket,
            5002 => Self::ConnectedSocket,
            5003 => Self::InvalidParam,
            5004 => Self::InvalidSocket,
            5005 => Self::UnboundSocket,
            5006 => Self::NoListen,
            5007 => Self::RendezvousNoServer,
            5008 => Self::RendezvousUnbound,
            5009 => Self::InvalidMessageApi,
            5010 => Self::InvalidBufferApi,
            5011 => Self::DuplicateListen,
            5012 => Self::LargeMessage,
            5013 => Self::InvalidPollId,
            5014 => Self::PollEmpty,
            5015 => Self::BindConflict,
            6000 => Self::AsyncFail,
            6001 => Self::AsyncSend,
            6002 => Self::AsyncRecv,
            6003 => Self::Timeout,
            6004 => Self::Congestion,
            7000 => Self::PeerError,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for SrtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::Success => "success",
            Self::ConnectionSetup => "connection setup failure",
            Self::NoServer => "connection timed out",
            Self::ConnectionRejected => "connection rejected by peer",
            Self::SocketFail => "unable to create/configure SRT socket",
            Self::SecurityFail => "encryption failure",
            Self::SocketClosed => "socket closed during operation",
            Self::ConnectionFail => "connection failure",
            Self::ConnectionLost => "connection lost",
            Self::NoConnection => "no connection",
            Self::Resource => "system resource failure",
            Self::Thread => "unable to create thread",
            Self::NoBuffer => "no memory space available",
            Self::SysObject => "unable to create system object",
            Self::File => "file system failure",
            Self::InvalidReadOffset => "cannot seek read position",
            Self::ReadPermission => "failure in read",
            Self::InvalidWriteOffset => "cannot seek write position",
            Self::WritePermission => "failure in write",
            Self::InvalidOperation => "operation not supported",
            Self::BoundSocket => "socket already bound",
            Self::ConnectedSocket => "socket already connected",
            Self::InvalidParam => "invalid parameter",
            Self::InvalidSocket => "invalid socket ID",
            Self::UnboundSocket => "socket not bound",
            Self::NoListen => "socket not in listening state",
            Self::RendezvousNoServer => "rendezvous connection mode with non-matching sockets",
            Self::RendezvousUnbound => "rendezvous connection but unbound socket",
            Self::InvalidMessageApi => "message API not valid in stream mode",
            Self::InvalidBufferApi => "buffer API not valid in message mode",
            Self::DuplicateListen => "another socket already listening on this port",
            Self::LargeMessage => "message too large for the configured payload size",
            Self::InvalidPollId => "invalid epoll ID",
            Self::PollEmpty => "epoll container empty",
            Self::BindConflict => "port already in use",
            Self::AsyncFail => "non-blocking call failure",
            Self::AsyncSend => "no buffer space available for sending",
            Self::AsyncRecv => "no data available for reading",
            Self::Timeout => "operation timed out",
            Self::Congestion => "congestion control",
            Self::PeerError => "error from peer",
            Self::Unknown => "unknown error",
        };
        write!(f, "{msg}")
    }
}

impl std::error::Error for SrtError {}

/// Rejection reason codes for handshake rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum RejectReason {
    Unknown = 0,
    System = 1,
    Peer = 2,
    Resource = 3,
    Rogue = 4,
    Backlog = 5,
    Ipe = 6,
    Close = 7,
    Version = 8,
    RdvCookie = 9,
    BadSecret = 10,
    Unsecure = 11,
    MessageApi = 12,
    Congestion = 13,
    Filter = 14,
    Group = 15,
    Timeout = 16,
    Crypto = 17,
}

impl RejectReason {
    pub fn from_code(code: i32) -> Self {
        match code {
            0 => Self::Unknown,
            1 => Self::System,
            2 => Self::Peer,
            3 => Self::Resource,
            4 => Self::Rogue,
            5 => Self::Backlog,
            6 => Self::Ipe,
            7 => Self::Close,
            8 => Self::Version,
            9 => Self::RdvCookie,
            10 => Self::BadSecret,
            11 => Self::Unsecure,
            12 => Self::MessageApi,
            13 => Self::Congestion,
            14 => Self::Filter,
            15 => Self::Group,
            16 => Self::Timeout,
            17 => Self::Crypto,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::Unknown => "unknown",
            Self::System => "system function error",
            Self::Peer => "rejected by peer",
            Self::Resource => "resource allocation failure",
            Self::Rogue => "incorrect data in handshake",
            Self::Backlog => "listener backlog exceeded",
            Self::Ipe => "internal program error",
            Self::Close => "socket is closing",
            Self::Version => "peer version too old",
            Self::RdvCookie => "rendezvous cookie collision",
            Self::BadSecret => "incorrect passphrase",
            Self::Unsecure => "password required or unexpected",
            Self::MessageApi => "stream/message API conflict",
            Self::Congestion => "incompatible congestion controller",
            Self::Filter => "incompatible packet filter",
            Self::Group => "incompatible group",
            Self::Timeout => "connection timeout",
            Self::Crypto => "incompatible crypto mode",
        };
        write!(f, "{msg}")
    }
}

/// Convenience type alias for SRT operations.
pub type Result<T> = std::result::Result<T, SrtError>;
