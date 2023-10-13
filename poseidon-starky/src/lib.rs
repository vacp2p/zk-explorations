#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(stmt_expr_attributes)]
#![feature(no_coverage)]
#![feature(register_tool)]
#![register_tool(tarpaulin)]
#![deny(clippy::pedantic)]
#![deny(clippy::cargo)]
#![allow(clippy::missing_panics_doc)]

pub mod columns;
pub mod generation;
pub mod stark;
