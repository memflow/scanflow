//! # scanflow memory scanning library
//!
//! scanflow is a memory scanning library built for use with memflow - a versatile memory
//! introspection library. scanflow provides many ways to find data in memory. The typical workflow
//! looks like so:
//!
//! 1. Find wanted memory address using `ValueScanner`.
//!
//! 2. Find global variables that indirectly reference the match with `PointerMap`.
//!
//! 3. Create unique code signature that references one of the global variables with `Sigmaker`.
//!
//! It may be worth trying out `scanflow-cli` - a command line interface built specificly around
//! this library.

pub mod value_scanner;
pub mod pointer_map;
pub mod disasm;
pub mod sigmaker;
pub mod pbar;

