use anchor_lang::prelude::*;
use anchor_lang::system_program::{self, System, Transfer};

use crate::constants::*;
use crate::error::ErrorCode;
use crate::instructions::events::ChallengeEvent;
use crate::pure::{compute_window_extension, require_min_raise};
use crate::state::{GlobalState, PendingRefund};

#[derive(Accounts)]
pub struct Challenge<'info> {
    #[account(mut)]
    pub challenger: Signer<'info>,

    #[account(mut, seeds = [GLOBAL_STATE_SEED], bump)]
    pub global_state: Account<'info, GlobalState>,

    /// CHECK: plain System-Program-owned vault PDA; validated by seeds/bump.
    #[account(mut, seeds = [VAULT_SEED], bump = global_state.vault_bump)]
    pub vault: UncheckedAccount<'info>,

    /// Claimable-refund PDA for whoever currently holds the top bid
    /// (`global_state.top_bidder`), keyed by that bidder's own pubkey --
    /// never by an account the bidder controls the ownership of, which is
    /// exactly what makes this immune to the self-reassign-ownership griefing
    /// attack the old inline-transfer design was vulnerable to. Lazily
    /// created (rent paid by `challenger`, the one placing this outbid) the
    /// first time this bidder is ever outbid, and simply accumulated into on
    /// every subsequent outbid before they call `claim_refund()`.
    ///
    /// `Option`al rather than mandatory: on a cold open
    /// (`global_state.top_bidder == Pubkey::default()`) there is no previous
    /// bidder to refund, so there is nothing for this account to ever hold.
    /// If it were mandatory, `init_if_needed` would still create and
    /// rent-fund a "null-bidder" PDA seeded by `Pubkey::default()` on every
    /// such cold open, permanently stranding that rent -- `claim_refund()`
    /// can never close it because no signer can ever equal the zero pubkey.
    /// A client passes this program's OWN address (`toggld`'s id, not the
    /// System Program's) as this account on a cold open (Anchor's runtime
    /// refuses to mark the invoked program's own address writable, which is
    /// exactly what makes it usable as an "omitted account" sentinel here —
    /// see `apps/web/lib/solana/toggld.ts`'s `OMITTED_OPTIONAL_ACCOUNT_SENTINEL`)
    /// to skip creating it entirely; the
    /// handler below additionally rejects a cold-open call that supplies a
    /// real account here, so the stranding can't happen even if a client
    /// gets this wrong.
    #[account(
        init_if_needed,
        payer = challenger,
        space = PendingRefund::SPACE,
        seeds = [REFUND_SEED, global_state.top_bidder.as_ref()],
        bump,
    )]
    pub pending_refund: Option<Account<'info, PendingRefund>>,

    pub system_program: Program<'info, System>,
}

pub(crate) fn handler(ctx: Context<Challenge>, bid_amount: u64) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let mut extended = false;
    let challenger_key = ctx.accounts.challenger.key();

    {
        let global_state = &mut ctx.accounts.global_state;

        if !global_state.window_active {
            // Pointless self-interaction: the holder already holds, so there
            // is nothing to defend against yet on a cold open. Legitimate
            // self-defend only ever happens mid-window, against a different
            // top_bidder -- see the `else` branch below.
            require!(challenger_key != global_state.holder, ErrorCode::CannotChallengeSelf);

            // Cold open: the resting price is treated as the "current top bid"
            // for min-raise purposes, so price still only moves up by at least
            // the min raise even on a fresh window.
            require_min_raise(global_state.current_price, bid_amount, global_state.min_raise_bps)?;

            global_state.window_active = true;
            global_state.window_end_ts = now
                .checked_add(global_state.base_window_secs as i64)
                .ok_or(ErrorCode::MathOverflow)?;
        } else {
            require!(now < global_state.window_end_ts, ErrorCode::WindowClosedPendingSettlement);

            // Pointless self-interaction: raising your own already-winning
            // bid accomplishes nothing. Does not affect the legitimate
            // self-defend case (holder outbidding a *different* top_bidder),
            // since there challenger == holder != top_bidder.
            require!(challenger_key != global_state.top_bidder, ErrorCode::AlreadyTopBidder);

            require_min_raise(global_state.top_bid_amount, bid_amount, global_state.min_raise_bps)?;

            // Extends from the current end (not from `now`), so repeated
            // late bids keep pushing the window out rather than resetting
            // to a fixed offset — sustained sniping stays expensive.
            let (new_window_end_ts, did_extend) = compute_window_extension(
                global_state.window_end_ts,
                global_state.snipe_extend_secs,
                now,
            )?;
            global_state.window_end_ts = new_window_end_ts;
            extended = did_extend;
        }
    }

    let previous_top_bidder = ctx.accounts.global_state.top_bidder;
    let previous_top_bid_amount = ctx.accounts.global_state.top_bid_amount;

    if previous_top_bidder != Pubkey::default() {
        // Pull-based refund: the previous top bid's lamports move out of the
        // vault and into this bidder's own `PendingRefund` PDA (never into an
        // account the bidder could tamper with the ownership of), where they
        // sit until the bidder signs `claim_refund()` to pull them out
        // themselves. This makes challenge() unconditional -- it can never be
        // blocked by anything the previous bidder does to their own wallet
        // (e.g. reassigning its owner away from the System Program to grief
        // every subsequent challenger, as the old inline-transfer-with-an
        // owner-check design allowed).
        let pending_refund_bump = ctx.bumps.pending_refund.ok_or(ErrorCode::MissingPendingRefundAccount)?;
        let pending_refund = ctx
            .accounts
            .pending_refund
            .as_mut()
            .ok_or(ErrorCode::MissingPendingRefundAccount)?;

        // `init_if_needed` only allocates/assigns the account on first
        // creation -- it does not populate our own fields. A freshly created
        // account is indistinguishable from an all-zero one, so detect "just
        // created" by `bidder == default` (no real bidder can ever be the
        // default pubkey: it has no private key and so can never sign a
        // `challenge()` as `challenger`, which is the only way to become
        // `top_bidder` in the first place).
        if pending_refund.bidder == Pubkey::default() {
            pending_refund.bidder = previous_top_bidder;
            pending_refund.bump = pending_refund_bump;
        } else {
            // Already-initialized account: its bidder must be exactly the
            // pubkey the PDA was derived from (guaranteed by the seeds
            // constraint above) -- this is a belt-and-suspenders check, not
            // a case expected to ever trip.
            require_keys_eq!(pending_refund.bidder, previous_top_bidder, ErrorCode::NothingToRefund);
        }

        pending_refund.amount = pending_refund
            .amount
            .checked_add(previous_top_bid_amount)
            .ok_or(ErrorCode::MathOverflow)?;

        let vault_bump = ctx.accounts.global_state.vault_bump;
        let vault_seeds: &[&[u8]] = &[VAULT_SEED, &[vault_bump]];
        let signer_seeds: &[&[&[u8]]] = &[vault_seeds];

        system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.key(),
                Transfer {
                    from: ctx.accounts.vault.to_account_info(),
                    to: pending_refund.to_account_info(),
                },
                signer_seeds,
            ),
            previous_top_bid_amount,
        )?;

        let global_state = &mut ctx.accounts.global_state;
        global_state.escrowed_amount = global_state
            .escrowed_amount
            .checked_sub(previous_top_bid_amount)
            .ok_or(ErrorCode::MathOverflow)?;
    } else {
        // Cold open: there is no previous bidder to refund, so there is
        // nothing for `pending_refund` to ever hold. Reject outright rather
        // than silently ignoring a supplied account -- if a client passes a
        // real account here anyway, `init_if_needed` would otherwise create
        // and rent-fund a "null-bidder" PDA (seeded by `Pubkey::default()`)
        // that `claim_refund()` could never close, permanently stranding
        // that rent. A rejected transaction reverts atomically, including
        // any account creation validation already performed for this
        // instruction, so nothing gets created or charged.
        require!(ctx.accounts.pending_refund.is_none(), ErrorCode::UnexpectedPendingRefundAccount);
    }

    system_program::transfer(
        CpiContext::new(
            ctx.accounts.system_program.key(),
            Transfer {
                from: ctx.accounts.challenger.to_account_info(),
                to: ctx.accounts.vault.to_account_info(),
            },
        ),
        bid_amount,
    )?;

    let global_state = &mut ctx.accounts.global_state;
    global_state.top_bidder = challenger_key;
    global_state.top_bid_amount = bid_amount;
    global_state.escrowed_amount = global_state
        .escrowed_amount
        .checked_add(bid_amount)
        .ok_or(ErrorCode::MathOverflow)?;

    emit!(ChallengeEvent {
        challenger: challenger_key,
        bid_amount,
        window_end_ts: global_state.window_end_ts,
        extended,
    });

    Ok(())
}
