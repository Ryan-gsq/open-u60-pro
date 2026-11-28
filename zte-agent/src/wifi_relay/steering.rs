//! Undo vocabulary used by relay journals from before shared performance ownership.

use crate::netfx::perf;

pub(crate) fn command(args: &[String]) -> Result<(), String> {
    perf::legacy_command(args)
}

pub(crate) fn present(args: &[String]) -> bool {
    perf::legacy_present(args)
}
