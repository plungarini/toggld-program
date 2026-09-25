use anchor_lang::prelude::*;

use crate::constants::*;
use crate::error::ErrorCode;
use crate::instructions::events::RefundClaimedEvent;
use crate::state::PendingRefund;

#[derive(Accounts)]
pub struct ClaimRefund<'info> {
    /// Permissionless caller — must equal the pending refund's own recorded
    /// owner (enforced below), so no one else can trigger a payout to a
    /// mismatched destination and no allowlist of possible recipients is
    /// needed: the recipient is derived from on-chain state, not supplied by
    /// the caller as an arbitrary account.
    #[account(mut)]
    pub claimant: Signer<'info>,

    /// Seeds are derived from the account's own recorded `bidder`, not from
    /// `claimant`, so an account that fails to deserialize (never created —
    /// nothing was ever pending for this key) or fails discriminator checks
    /// (already claimed — closed accounts fail to deserialize again) is
    /// rejected cleanly before the `constraint` below is even evaluated.
    ///
    /// `close = rent_payer`, not `claimant` — this account's rent-exempt
    /// reserve was never `claimant`'s money (see `rent_payer` below and
    /// `PendingRefund::rent_payer`'s doc comment), so the reserve must go
    /// back to whoever actually paid it. `claimant`'s own `amount` is paid
    /// out explicitly in the handler before this close runs, so by the time
    /// Anchor closes the account only the untouched rent reserve remains.
    #[account(
        mut,
        seeds = [REFUND_SEED, pending_refund.bidder.as_ref()],
        bump = pending_refund.bump,
        close = rent_payer,
        constraint = pending_refund.bidder == claimant.key() @ ErrorCode::NothingToRefund,
    )]
    pub pending_refund: Account<'info, PendingRefund>,

    /// CHECK: must equal `pending_refund.rent_payer`, enforced below — the
    /// on-chain-recorded payer of this account's rent, not a caller-supplied
    /// destination, so a claimant can never redirect the reserve to
    /// themselves or anyone else.
    #[account(mut, address = pending_refund.rent_payer @ ErrorCode::InvalidRentPayer)]
    pub rent_payer: UncheckedAccount<'info>,
}

pub(crate) fn handler(ctx: Context<ClaimRefund>) -> Result<()> {
    let amount = ctx.accounts.pending_refund.amount;
    // Defensive: the only way this account exists with `bidder == claimant`
    // is via `challenge()`'s outbid path, which always adds a nonzero
    // amount, so this should never trip in practice — but a claim must never
    // pay out (or silently "succeed" on) a zero/garbage amount.
    require!(amount > 0, ErrorCode::NothingToRefund);

    // Pays out exactly `amount` — `claimant`'s own refunded bid, nothing
    // more — via direct lamport debit/credit rather than a `system_program`
    // CPI: `pending_refund` is owned by THIS program, not the System
    // Program, so it cannot be the `from` side of a system-program transfer.
    // A program may freely debit lamports from any account it owns, and
    // credit any account regardless of who owns it.
    **ctx.accounts.pending_refund.to_account_info().try_borrow_mut_lamports()? -= amount;
    **ctx.accounts.claimant.to_account_info().try_borrow_mut_lamports()? += amount;

    // What's left in `pending_refund` after that debit is exactly its
    // rent-exempt reserve (nothing else was ever deposited into it) — the
    // `close = rent_payer` constraint above sweeps that remainder to
    // `rent_payer` and zeroes the account once this handler returns.

    emit!(RefundClaimedEvent {
        claimant: ctx.accounts.claimant.key(),
        amount,
    });

    Ok(())
}
