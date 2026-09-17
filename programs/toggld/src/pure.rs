//! Pure, standalone business-logic functions extracted out of the instruction
//! handlers so they can be unit-tested and fuzz-tested (via `cargo-fuzz`)
//! independently of the Anchor/BPF runtime, which cargo-fuzz cannot drive
//! directly (no LiteSVM/BPF support). Each function here takes only
//! primitive arguments and returns a plain `Result`/computed value — no
//! `Context`, no account access, no CPI. Behavior must stay byte-for-byte
//! identical to what used to be inlined in the handlers; this is a
//! testability refactor only.

use anchor_lang::prelude::*;

use crate::error::ErrorCode;

/// Exact (division-free) min-raise check: `bid * 10000 >= base * (10000 + min_raise_bps)`,
/// computed in `u128` so no lamport amount can overflow the multiplication and no
/// intermediate rounding can let a sub-min-raise bid slip through.
///
/// Extracted from `instructions::challenge::require_min_raise`.
pub fn require_min_raise(base: u64, bid: u64, min_raise_bps: u16) -> Result<()> {
    let required_scaled = (base as u128)
        .checked_mul(10_000u128.checked_add(min_raise_bps as u128).ok_or(ErrorCode::MathOverflow)?)
        .ok_or(ErrorCode::MathOverflow)?;
    let bid_scaled = (bid as u128)
        .checked_mul(10_000u128)
        .ok_or(ErrorCode::MathOverflow)?;
    require!(bid_scaled >= required_scaled, ErrorCode::BidTooLow);
    Ok(())
}

/// Anti-snipe window-extension calculation. Given the current window end
/// timestamp, the configured snipe-extend duration, and the timestamp `now`
/// a bid landed at, returns `(new_window_end_ts, extended)`.
///
/// The window is extended (by exactly `snipe_extend_secs`, added to the
/// *current* end — never reset to a fixed offset from `now`) iff `now` falls
/// within `snipe_extend_secs` of the current close. Otherwise the end is
/// returned unchanged.
///
/// Extracted from the inline snipe-threshold block in
/// `instructions::challenge::handler`.
pub fn compute_window_extension(
    window_end_ts: i64,
    snipe_extend_secs: u32,
    now: i64,
) -> Result<(i64, bool)> {
    let snipe_threshold = window_end_ts
        .checked_sub(snipe_extend_secs as i64)
        .ok_or(ErrorCode::MathOverflow)?;

    if now >= snipe_threshold {
        let new_end = window_end_ts
            .checked_add(snipe_extend_secs as i64)
            .ok_or(ErrorCode::MathOverflow)?;
        Ok((new_end, true))
    } else {
        Ok((window_end_ts, false))
    }
}

/// 15%/85%-style treasury/burn split of a winning bid, computed in `u128` to
/// avoid overflow on the intermediate multiplication. Returns
/// `(fee_amount, burn_amount)` where `fee_amount + burn_amount ==
/// winning_price` always (no lamport created or destroyed by the split).
///
/// Extracted from the inline fee/burn computation in
/// `instructions::settle::handler`.
pub fn compute_split(winning_price: u64, fee_bps: u16) -> Result<(u64, u64)> {
    let winning_price_u128 = winning_price as u128;
    let fee_amount_u128 = winning_price_u128
        .checked_mul(fee_bps as u128)
        .ok_or(ErrorCode::MathOverflow)?
        .checked_div(10_000u128)
        .ok_or(ErrorCode::MathOverflow)?;
    let fee_amount = u64::try_from(fee_amount_u128).map_err(|_| error!(ErrorCode::MathOverflow))?;
    let burn_amount = winning_price.checked_sub(fee_amount).ok_or(ErrorCode::MathOverflow)?;

    // No lamport created or destroyed by the split.
    require!(
        fee_amount
            .checked_add(burn_amount)
            .ok_or(ErrorCode::MathOverflow)?
            == winning_price,
        ErrorCode::MathOverflow
    );

    Ok((fee_amount, burn_amount))
}

/// Linear vesting release. Returns how much of `total` has unlocked by `now`:
/// `0` at/before `start_ts`, all of `total` at/after `start_ts + duration_secs`,
/// and a straight-line proportion in between. All math is saturating/checked so
/// no combination of arguments can panic or overflow.
///
/// A non-positive `duration_secs` degenerates to a cliff at `start_ts`
/// (everything unlocks the instant `now` passes `start_ts`); callers are
/// expected to pass a positive duration, this is only defensive.
///
/// Pure sibling of `compute_split` — no `Context`, no account access — so it is
/// unit-testable without the Anchor/BPF runtime. Used by `claim_vested()`.
pub fn compute_vested_unlocked(total: u64, start_ts: i64, duration_secs: i64, now: i64) -> u64 {
    if now <= start_ts {
        return 0;
    }
    if duration_secs <= 0 {
        return total;
    }
    let end_ts = start_ts.saturating_add(duration_secs);
    if now >= end_ts {
        return total;
    }
    // 0 < now - start_ts < duration_secs here, so both casts are non-negative
    // and the division is by a positive value.
    let elapsed = (now - start_ts) as u128;
    let duration = duration_secs as u128;
    let unlocked = (total as u128).saturating_mul(elapsed) / duration;
    // unlocked < total (strict, since elapsed < duration), so this cast is safe.
    unlocked as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_raise_exact_boundary_passes() {
        // base=100, min_raise_bps=500 (5%) -> required bid = 105
        assert!(require_min_raise(100, 105, 500).is_ok());
        assert!(require_min_raise(100, 104, 500).is_err());
    }

    #[test]
    fn window_extension_extends_on_late_bid() {
        let (new_end, extended) = compute_window_extension(1000, 10, 995).unwrap();
        assert!(extended);
        assert_eq!(new_end, 1010);
    }

    #[test]
    fn window_extension_unchanged_on_early_bid() {
        let (new_end, extended) = compute_window_extension(1000, 10, 500).unwrap();
        assert!(!extended);
        assert_eq!(new_end, 1000);
    }

    #[test]
    fn split_sums_to_original() {
        let (fee, burn) = compute_split(1_000_000, 1500).unwrap();
        assert_eq!(fee + burn, 1_000_000);
        assert_eq!(fee, 150_000);
        assert_eq!(burn, 850_000);
    }

    #[test]
    fn vested_zero_before_and_at_start() {
        assert_eq!(compute_vested_unlocked(1_000, 100, 900, 50), 0);
        assert_eq!(compute_vested_unlocked(1_000, 100, 900, 100), 0);
    }

    #[test]
    fn vested_linear_midpoint_and_quarter() {
        // start=0, duration=1000, total=1_000_000
        assert_eq!(compute_vested_unlocked(1_000_000, 0, 1000, 500), 500_000);
        assert_eq!(compute_vested_unlocked(1_000_000, 0, 1000, 250), 250_000);
    }

    #[test]
    fn vested_full_at_and_after_end() {
        assert_eq!(compute_vested_unlocked(1_000_000, 0, 1000, 1000), 1_000_000);
        assert_eq!(compute_vested_unlocked(1_000_000, 0, 1000, 5_000), 1_000_000);
    }

    #[test]
    fn vested_never_exceeds_total_and_floors() {
        // 1s into a 3s schedule of 10 tokens -> floor(10/3) = 3
        assert_eq!(compute_vested_unlocked(10, 0, 3, 1), 3);
        // one second before the end -> strictly less than total
        let almost = compute_vested_unlocked(u64::MAX, 0, 1_000_000, 999_999);
        assert!(almost < u64::MAX);
    }

    #[test]
    fn vested_no_overflow_on_extremes() {
        // Huge total, huge timestamps — must not panic.
        let v = compute_vested_unlocked(u64::MAX, i64::MIN / 2, i64::MAX / 2, 0);
        assert!(v <= u64::MAX);
    }

    #[test]
    fn vested_non_positive_duration_is_cliff_at_start() {
        assert_eq!(compute_vested_unlocked(1_000, 100, 0, 99), 0);
        assert_eq!(compute_vested_unlocked(1_000, 100, 0, 100), 0);
        assert_eq!(compute_vested_unlocked(1_000, 100, 0, 101), 1_000);
    }
}
