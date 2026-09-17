use anchor_lang::prelude::*;
use anchor_lang::system_program::{self, System, Transfer};

use crate::constants::*;
use crate::error::ErrorCode;
use crate::instructions::events::TreasuryWithdrawEvent;
use crate::state::GlobalState;

#[derive(Accounts)]
pub struct WithdrawTreasury<'info> {
    pub admin: Signer<'info>,

    #[account(
        mut,
        seeds = [GLOBAL_STATE_SEED],
        bump,
        has_one = admin @ ErrorCode::Unauthorized,
        has_one = treasury @ ErrorCode::InvalidTreasuryAccount,
    )]
    pub global_state: Account<'info, GlobalState>,

    /// CHECK: plain System-Program-owned vault PDA; validated by seeds/bump.
    #[account(mut, seeds = [VAULT_SEED], bump = global_state.vault_bump)]
    pub vault: UncheckedAccount<'info>,

    /// CHECK: must equal `global_state.treasury`, enforced via `has_one` above.
    #[account(mut)]
    pub treasury: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub(crate) fn handler(ctx: Context<WithdrawTreasury>) -> Result<()> {
    let global_state = &mut ctx.accounts.global_state;

    require!(global_state.treasury_balance > 0, ErrorCode::NothingToWithdraw);

    let amount = global_state.treasury_balance;
    global_state.treasury_balance = 0;
    let vault_bump = global_state.vault_bump;

    let vault_seeds: &[&[u8]] = &[VAULT_SEED, &[vault_bump]];
    let signer_seeds: &[&[&[u8]]] = &[vault_seeds];

    system_program::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.key(),
            Transfer {
                from: ctx.accounts.vault.to_account_info(),
                to: ctx.accounts.treasury.to_account_info(),
            },
            signer_seeds,
        ),
        amount,
    )?;

    let timestamp = Clock::get()?.unix_timestamp;

    // Emitted unconditionally on every successful call, so treasury draws
    // are publicly auditable independent of any indexer.
    emit!(TreasuryWithdrawEvent {
        admin: ctx.accounts.admin.key(),
        treasury: ctx.accounts.treasury.key(),
        amount,
        timestamp,
    });

    Ok(())
}
