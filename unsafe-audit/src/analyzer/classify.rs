use syn::{Expr, Type};

use super::visitor::{Severity, UnsafePattern};

pub fn is_simd_name(name: &str) -> bool {
    name.starts_with("_mm") || name.starts_with("_mm256") || name.starts_with("_mm512")
}

pub fn identify_expr_pattern(
    expr: &Expr,
    call_resolver: impl Fn(&syn::ExprCall) -> Option<(String, Vec<String>)>,
) -> (UnsafePattern, Severity) {
    match expr {
        Expr::Call(call) => identify_call_pattern(call, call_resolver),
        Expr::MethodCall(method) => match method.method.to_string().as_str() {
            "get_unchecked" | "get_unchecked_mut" => {
                (UnsafePattern::UncheckedIndex, Severity::Medium)
            }
            "assume_init" => (UnsafePattern::UninitMemory, Severity::High),
            name if is_simd_name(name) => (UnsafePattern::SimdIntrinsic, Severity::Medium),
            _ => (UnsafePattern::OtherUnsafe, Severity::Low),
        },
        Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Deref(_)) => {
            (UnsafePattern::PtrDereference, Severity::Medium)
        }
        Expr::Cast(cast) if matches!(&*cast.ty, Type::Ptr(_)) => {
            (UnsafePattern::PtrDereference, Severity::Medium)
        }
        _ => (UnsafePattern::OtherUnsafe, Severity::Low),
    }
}

pub fn identify_call_pattern(
    call: &syn::ExprCall,
    call_resolver: impl Fn(&syn::ExprCall) -> Option<(String, Vec<String>)>,
) -> (UnsafePattern, Severity) {
    let Some((name, path)) = call_resolver(call) else {
        return (UnsafePattern::OtherUnsafe, Severity::Low);
    };

    if is_simd_name(&name) {
        return (UnsafePattern::SimdIntrinsic, Severity::Medium);
    }

    match name.as_str() {
        "transmute" | "transmute_copy" => (UnsafePattern::Transmute, Severity::High),
        "from_utf8_unchecked"
        | "from_utf16_unchecked"
        | "from_raw_parts"
        | "from_raw_parts_mut" => (UnsafePattern::UncheckedConversion, Severity::High),
        "unreachable_unchecked" => (UnsafePattern::UnreachableUnchecked, Severity::High),
        "zeroed" | "uninitialized" => (UnsafePattern::UninitMemory, Severity::High),
        "read"
        | "read_unaligned"
        | "write"
        | "write_unaligned"
        | "copy"
        | "copy_nonoverlapping"
        | "swap" => {
            if path.iter().any(|segment| segment == "ptr") {
                (UnsafePattern::PtrReadWrite, Severity::Medium)
            } else {
                (UnsafePattern::OtherUnsafe, Severity::Low)
            }
        }
        _ => (UnsafePattern::OtherUnsafe, Severity::Low),
    }
}

pub fn identify_macro_pattern(
    _mac: &syn::Macro,
    path_segments: &[String],
) -> (UnsafePattern, Severity) {
    let name = path_segments.last().cloned().unwrap_or_default();
    match name.as_str() {
        "asm" | "llvm_asm" => (UnsafePattern::InlineAsm, Severity::High),
        "addr_of" | "addr_of_mut" => (UnsafePattern::AddrOf, Severity::Low),
        name if is_simd_name(name) => (UnsafePattern::SimdIntrinsic, Severity::Medium),
        _ => (UnsafePattern::OtherUnsafe, Severity::Low),
    }
}
