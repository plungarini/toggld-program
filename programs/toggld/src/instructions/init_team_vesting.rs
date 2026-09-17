use anchor_lang::prelude::*;
use anchor_lang::system_program::System;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

use crate::constants::*;
use crate::error::ErrorCode;
use crate::instructions::events::TeamVestingInitializedEvent;
use crate::state::{GlobalState, TeamVesting};

/// One-time, admin-gated. Locks the team's allocation into an immutable linear
/// release: records `total_amount`/`start_ts`/`duration_secs` on a `TeamVesting`
/// PDA and moves `total_amount` $TOGGLD from the admin's own ATA into an ATA
/// owned by that PDA in the same transaction.
///
/// There is no instruction anywhere in the program that can accelerate, pause,
/// or rewrite the schedule once this runs — `claim_vested()` only ever reads it.
#[derive(Accounts)]
pub struct InitTeamVesting<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        seeds = [GLOBAL_STATE_SEED],
        bump,
        has_one = admin @ ErrorCode::Unauthorized,
    )]
    pub global_state: Account<'info, GlobalState>,

    #[account(
        init,
        payer = admin,
        space = TeamVesting::SPACE,
        seeds = [TEAM_VESTING_SEED],
        bump,
    )]
    pub team_vesting: Account<'info, TeamVesting>,

    pub mint: Account<'info, Mint>,

    #[account(
        init,
        payer = admin,
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
    pub system_program: Program<'info, System>,
}

pub(crate) fn handler(
    ctx: Context<InitTeamVesting>,
    total_amount: u64,
    start_ts: i64,
    duration_secs: i64,
) -> Result<()> {
    require!(total_amount > 0, ErrorCode::InvalidVestingAmount);

    // The schedule must be a real forward-looking linear release. A far-past
    // `start_ts` (or a `start_ts + duration` already elapsed) would make the
    // whole allocation claimable on the first `claim_vested()` call, defeating
    // the lock that is the entire point of this instruction.
    let now = Clock::get()?.unix_timestamp;
    require!(
        start_ts >= now.saturating_sub(TeamVesting::MAX_START_BACKDATE_SECS),
        ErrorCode::InvalidVestingSchedule
    );
    require!(
        (TeamVesting::MIN_DURATION_SECS..=TeamVesting::MAX_DURATION_SECS)
            .contains(&duration_secs),
        ErrorCode::InvalidVestingSchedule
    );

    token::transfer(
        CpiContext::new(
            ctx.accounts.token_program.key(),
            Transfer {
                from: ctx.accounts.admin_toggld_ata.to_account_info(),
                to: ctx.accounts.team_vesting_ata.to_account_info(),
                authority: ctx.accounts.admin.to_account_info(),
            },
        ),
        total_amount,
    )?;

    let team_vesting = &mut ctx.accounts.team_vesting;
    team_vesting.mint = ctx.accounts.mint.key();
    team_vesting.total_amount = total_amount;
    team_vesting.start_ts = start_ts;
    team_vesting.duration_secs = duration_secs;
    team_vesting.claimed_amount = 0;
    team_vesting.bump = ctx.bumps.team_vesting;

    emit!(TeamVestingInitializedEvent {
        mint: ctx.accounts.mint.key(),
        total_amount,
        start_ts,
        duration_secs,
    });

    Ok(())
}
