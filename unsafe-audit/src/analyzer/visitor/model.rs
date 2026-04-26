use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsafeFinding {
    #[serde(default)]
    pub site_id: String,
    pub kind: FindingKind,
    pub pattern: UnsafePattern,
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub snippet: String,
    pub severity: Severity,
    pub context: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingKind {
    UnsafeBlock,
    UnsafeFnDecl,
    UnsafeImplDecl,
    RiskyOperation,
    ExternItem,
}

impl std::fmt::Display for FindingKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            FindingKind::UnsafeBlock => "unsafe_block",
            FindingKind::UnsafeFnDecl => "unsafe_fn_decl",
            FindingKind::UnsafeImplDecl => "unsafe_impl_decl",
            FindingKind::RiskyOperation => "risky_operation",
            FindingKind::ExternItem => "extern_item",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnsafePattern {
    PtrDereference,
    PtrReadWrite,
    Transmute,
    UncheckedConversion,
    UncheckedIndex,
    UnreachableUnchecked,
    SimdIntrinsic,
    UninitMemory,
    UnionAccess,
    AddrOf,
    InlineAsm,
    ExternBlock,
    OtherUnsafe,
}

impl std::fmt::Display for UnsafePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            UnsafePattern::PtrDereference => "ptr_dereference",
            UnsafePattern::PtrReadWrite => "ptr_read_write",
            UnsafePattern::Transmute => "transmute",
            UnsafePattern::UncheckedConversion => "unchecked_conversion",
            UnsafePattern::UncheckedIndex => "unchecked_index",
            UnsafePattern::UnreachableUnchecked => "unreachable_unchecked",
            UnsafePattern::SimdIntrinsic => "simd_intrinsic",
            UnsafePattern::UninitMemory => "uninit_memory",
            UnsafePattern::UnionAccess => "union_access",
            UnsafePattern::AddrOf => "addr_of",
            UnsafePattern::InlineAsm => "inline_asm",
            UnsafePattern::ExternBlock => "extern_block",
            UnsafePattern::OtherUnsafe => "other_unsafe",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternCount {
    pub pattern: UnsafePattern,
    pub count: usize,
}
