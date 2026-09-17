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
    #[account(
        mut,
        seeds = [REFUND_SEED, pending_refund.bidder.as_ref()],
        bump = pending_refund.bump,
        close = claimant,
        constraint = pending_refund.bidder == claimant.key() @ ErrorCode::NothingToRefund,
    )]
    pub pending_refund: Account<'info, PendingRefund>,
}

pub(crate) fn handler(ctx: Context<ClaimRefund>) -> Result<()> {
    let amount = ctx.accounts.pending_refund.amount;
    // Defensive: the only way this account exists with `bidder == claimant`
    // is via `challenge()`'s outbid path, which always adds a nonzero
    // amount, so this should never trip in practice — but a claim must never
    // pay out (or silently "succeed" on) a zero/garbage amount.
    require!(amount > 0, ErrorCode::NothingToRefund);

    // The `close = claimant` constraint above transfers this account's
    // entire remaining lamport balance — the accumulated refund amount plus
    // its own rent-exempt reserve — to `claimant` and zeroes the account
    // after this handler returns, so no separate CPI transfer is needed
    // here and rent is always returned to the claimant, never stranded.

    emit!(RefundClaimedEvent {
        claimant: ctx.accounts.claimant.key(),
        amount,
    });

    Ok(())
}
