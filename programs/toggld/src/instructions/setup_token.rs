use anchor_lang::prelude::*;
use anchor_lang::system_program::{self, CreateAccount, System};
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token::{Mint, Token, TokenAccount};

use crate::constants::*;
use crate::error::ErrorCode;
use crate::instructions::events::TokenConfiguredEvent;
use crate::state::{GlobalState, TokenConfig};

/// One-time, admin-gated wiring of the $TOGGLD token launch.
///
/// After this runs:
///  * `TokenConfig` records the mint, swap venue, pool/config addresses, and
///    the keeper slippage ceiling.
///  * `burn_vault` exists as a plain System-Program-owned lamport account
///    (mirrors `vault`), created here via a PDA-signed `create_account` CPI.
///  * `burn_vault`'s associated $TOGGLD token account exists (owned by the
///    `burn_vault` PDA) to hold swap output until it is burned.
///  * `global_state.burn_address` is repointed from the incinerator to
///    `burn_vault`, so `settle()`'s 85% burn leg needs no code change.
#[derive(Accounts)]
#[instruction(toggld_mint: Pubkey)]
pub struct SetupToken<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        mut,
        seeds = [GLOBAL_STATE_SEED],
        bump,
        has_one = admin @ ErrorCode::Unauthorized,
    )]
    pub global_state: Account<'info, GlobalState>,

    #[account(
        init,
        payer = admin,
        space = TokenConfig::SPACE,
        seeds = [TOKEN_CONFIG_SEED],
        bump,
    )]
    pub token_config: Account<'info, TokenConfig>,

    /// CHECK: created in the handler via a PDA-signed `system_program::create_account`
    /// CPI, funded with exactly the rent-exempt minimum for a 0-byte account so
    /// it stays plain System-Program-owned (never owned by `toggld`), exactly
    /// like `vault`. `init` cannot be used here for that reason.
    #[account(mut, seeds = [BURN_VAULT_SEED], bump)]
    pub burn_vault: UncheckedAccount<'info>,

    #[account(address = toggld_mint)]
    pub mint: Account<'info, Mint>,

    #[account(
        init,
        payer = admin,
        associated_token::mint = mint,
        associated_token::authority = burn_vault,
    )]
    pub burn_vault_toggld_ata: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

pub(crate) fn handler(
    ctx: Context<SetupToken>,
    toggld_mint: Pubkey,
    venue: u8,
    pool_address: Pubkey,
    venue_config: Pubkey,
    max_slippage_bps: u16,
) -> Result<()> {
    // A second call is already impossible — `init` on `token_config` fails once
    // the account exists — but assert the pre-state explicitly so the one-time
    // guarantee is provable, not just implied.
    require!(
        ctx.accounts.global_state.burn_address == INCINERATOR,
        ErrorCode::TokenAlreadyConfigured
    );

    require!(
        venue == TokenConfig::VENUE_DBC_CURVE
            || venue == TokenConfig::VENUE_DAMM_V1
            || venue == TokenConfig::VENUE_DAMM_V2,
        ErrorCode::InvalidVenue
    );
    require!(
        max_slippage_bps <= MAX_SLIPPAGE_BPS_CEILING,
        ErrorCode::SlippageToleranceTooWide
    );

    // --- create `burn_vault` as a plain 0-byte System-owned account ---
    let burn_vault_bump = ctx.bumps.burn_vault;
    let burn_vault_seeds: &[&[u8]] = &[BURN_VAULT_SEED, &[burn_vault_bump]];
    let signer_seeds: &[&[&[u8]]] = &[burn_vault_seeds];
    let rent_exempt_reserve = Rent::get()?.minimum_balance(0);

    system_program::create_account(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.key(),
            CreateAccount {
                from: ctx.accounts.admin.to_account_info(),
                to: ctx.accounts.burn_vault.to_account_info(),
            },
            signer_seeds,
        ),
        rent_exempt_reserve,
        0,
        &system_program::ID,
    )?;

    // Canonical ATA bump — Anchor derives the ATA address itself but does not
    // expose the bump in `ctx.bumps`, so recompute it for storage.
    let (_ata, burn_vault_ata_bump) = Pubkey::find_program_address(
        &[
            ctx.accounts.burn_vault.key().as_ref(),
            ctx.accounts.token_program.key().as_ref(),
            ctx.accounts.mint.key().as_ref(),
        ],
        &anchor_spl::associated_token::ID,
    );

    let token_config = &mut ctx.accounts.token_config;
    token_config.toggld_mint = toggld_mint;
    token_config.burn_vault_bump = burn_vault_bump;
    token_config.burn_vault_ata_bump = burn_vault_ata_bump;
    token_config.venue = venue;
    token_config.pool_address = pool_address;
    token_config.venue_config = venue_config;
    token_config.max_slippage_bps = max_slippage_bps;
    token_config.total_tokens_burned = 0;
    token_config.reserved = [0u8; 64];

    // Repoint the burn destination. `settle()` keeps its existing
    // `address = global_state.burn_address` check unchanged — the target is now
    // a program PDA instead of the incinerator, and a SOL transfer works
    // identically either way. No split/mechanic field is touched.
    ctx.accounts.global_state.burn_address = ctx.accounts.burn_vault.key();

    emit!(TokenConfiguredEvent {
        mint: toggld_mint,
        burn_vault: ctx.accounts.burn_vault.key(),
        venue,
        pool_address,
        venue_config,
        max_slippage_bps,
    });

    Ok(())
}
