use anchor_lang::prelude::*;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

use crate::constants::*;
use crate::error::ErrorCode;
use crate::instructions::events::VestedClaimedEvent;
use crate::pure::compute_vested_unlocked;
use crate::state::{GlobalState, TeamVesting};

/// Admin-gated. Transfers whatever has newly vested (per the immutable schedule
/// recorded by `init_team_vesting()`) from the vesting PDA's ATA to the admin's
/// own $TOGGLD ATA. Reverts before `start_ts` and when nothing new has unlocked.
#[derive(Accounts)]
pub struct ClaimVested<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        seeds = [GLOBAL_STATE_SEED],
        bump,
        has_one = admin @ ErrorCode::Unauthorized,
    )]
    pub global_state: Account<'info, GlobalState>,

    #[account(
        mut,
        seeds = [TEAM_VESTING_SEED],
        bump = team_vesting.bump,
    )]
    pub team_vesting: Account<'info, TeamVesting>,

    #[account(address = team_vesting.mint @ ErrorCode::TokenNotConfigured)]
    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = team_vesting,
    )]
    pub team_vesting_ata: Account<'info, TokenAccount>,

    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = admin,
    )]
    pub admin_toggld_ata: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

pub(crate) fn handler(ctx: Context<ClaimVested>) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;

    let (total_amount, start_ts, duration_secs, claimed_amount, bump) = {
        let v = &ctx.accounts.team_vesting;
        (
            v.total_amount,
            v.start_ts,
            v.duration_secs,
            v.claimed_amount,
            v.bump,
        )
    };

    require!(now >= start_ts, ErrorCode::VestingNotStarted);

    let unlocked = compute_vested_unlocked(total_amount, start_ts, duration_secs, now);
    let amount = unlocked
        .checked_sub(claimed_amount)
        .ok_or(ErrorCode::MathOverflow)?;
    require!(amount > 0, ErrorCode::NothingVestedToClaim);

    let vesting_seeds: &[&[u8]] = &[TEAM_VESTING_SEED, &[bump]];
    let signer_seeds: &[&[&[u8]]] = &[vesting_seeds];

    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.key(),
            Transfer {
                from: ctx.accounts.team_vesting_ata.to_account_info(),
                to: ctx.accounts.admin_toggld_ata.to_account_info(),
                authority: ctx.accounts.team_vesting.to_account_info(),
            },
            signer_seeds,
        ),
        amount,
    )?;

    let claimed_total = claimed_amount
        .checked_add(amount)
        .ok_or(ErrorCode::MathOverflow)?;
    ctx.accounts.team_vesting.claimed_amount = claimed_total;

    emit!(VestedClaimedEvent {
        amount,
        claimed_total,
        unlocked,
    });

    Ok(())
}
