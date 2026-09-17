use anchor_lang::prelude::*;
use anchor_lang::system_program::{self, System, Transfer as SystemTransfer};
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token::{self, Burn, CloseAccount, Mint, SyncNative, Token, TokenAccount};

use crate::constants::*;
use crate::dbc_cpi::{self, SwapMode, SwapParameters2};
use crate::error::ErrorCode;
use crate::instructions::events::TokensBurnedEvent;
use crate::state::TokenConfig;

/// Permissionless (no caller-authority check — same precedent as `settle()`).
///
/// In one atomic transaction: sweep `burn_vault`'s SOL (keeping its rent-exempt
/// reserve), wrap it into a short-lived `burn_vault`-owned WSOL ATA, swap
/// WSOL -> $TOGGLD against the configured venue via an on-chain CPI, burn every
/// $TOGGLD received, and close the WSOL ATA back to `burn_vault`.
///
/// Supported venues: `VENUE_DBC_CURVE` (0, pre-graduation) and `VENUE_DAMM_V2`
/// (2, the post-graduation target pinned at pool creation). `VENUE_DAMM_V1` is
/// rejected with `InvalidVenue` — $TOGGLD is never migrated there (§4A.8).
///
/// Every account that ever holds SOL or tokens here is a `burn_vault`-owned
/// PDA/ATA — the `caller` only signs and pays the tx fee (+ transient WSOL ATA
/// rent, recovered to `burn_vault` on close). The §1 invariant "SOL/tokens
/// never rest in a keeper-owned address" is fully preserved.
#[derive(Accounts)]
pub struct BurnTokens<'info> {
    /// Permissionless caller — pays the tx fee and the transient WSOL ATA rent.
    #[account(mut)]
    pub caller: Signer<'info>,

    #[account(mut, seeds = [TOKEN_CONFIG_SEED], bump)]
    pub token_config: Account<'info, TokenConfig>,

    /// CHECK: plain System-Program-owned burn vault PDA; validated by seeds/bump.
    #[account(mut, seeds = [BURN_VAULT_SEED], bump = token_config.burn_vault_bump)]
    pub burn_vault: UncheckedAccount<'info>,

    /// $TOGGLD mint — `mut` because `token::burn` reduces its supply.
    #[account(mut, address = token_config.toggld_mint)]
    pub mint: Account<'info, Mint>,

    #[account(address = WSOL_MINT)]
    pub wsol_mint: Account<'info, Mint>,

    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = burn_vault,
    )]
    pub burn_vault_toggld_ata: Account<'info, TokenAccount>,

    #[account(
        init_if_needed,
        payer = caller,
        associated_token::mint = wsol_mint,
        associated_token::authority = burn_vault,
    )]
    pub burn_vault_wsol_ata: Account<'info, TokenAccount>,

    // --- Meteora `swap2` accounts. The set is identical for DBC (venue 0) and
    //     DAMM v2 (venue 2) except `dbc_config`, which is `Some` + address-checked
    //     for DBC and `None` for DAMM v2 (whose `swap2` has no `config` account).
    //     The handler branches on `token_config.venue` (PHASE_8_PLAN §4A.8). ---
    /// CHECK: DBC pool-authority PDA / DAMM v2 `pool_authority` PDA (a fixed
    /// constant PDA under the venue program). The venue validates it internally;
    /// a wrong value only makes the CPI revert.
    pub dbc_pool_authority: UncheckedAccount<'info>,

    /// CHECK: DBC partner config key — `Some` and pinned to
    /// `token_config.venue_config` for venue 0. Pass `None` for DAMM v2 (Anchor
    /// skips the address check when the optional account is absent).
    #[account(address = token_config.venue_config)]
    pub dbc_config: Option<UncheckedAccount<'info>>,

    /// CHECK: DBC virtual pool / DAMM v2 pool for $TOGGLD. Pinned to the value
    /// recorded at `setup_token()` / `promote_burn_venue()` time.
    #[account(mut, address = token_config.pool_address)]
    pub dbc_pool: UncheckedAccount<'info>,

    /// CHECK: pool base-token vault (DAMM v2: `token_a_vault`). The venue checks
    /// `pool.has_one`; the handler also reads its SPL balance for the on-chain
    /// expected-out floor.
    #[account(mut)]
    pub dbc_base_vault: UncheckedAccount<'info>,

    /// CHECK: pool quote-token vault (DAMM v2: `token_b_vault`). The venue checks
    /// `pool.has_one`; the handler also reads its SPL balance for the on-chain
    /// expected-out floor.
    #[account(mut)]
    pub dbc_quote_vault: UncheckedAccount<'info>,

    /// CHECK: venue `#[event_cpi]` event-authority PDA. Validated by the venue.
    pub dbc_event_authority: UncheckedAccount<'info>,

    /// CHECK: the venue program account itself. A runtime `require!` in the
    /// handler pins this to the program id implied by `token_config.venue`
    /// (`DBC_PROGRAM_ID` for venue 0, `DAMM_V2_PROGRAM_ID` for venue 2).
    pub dbc_program: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

/// Byte offset of the `sqrt_price` (Q64.64 `u128`) field inside each venue's
/// pool account (after the 8-byte Anchor discriminator). Cross-checked against
/// the Meteora IDLs (DBC `VirtualPool` 0.1.6; DAMM v2 `Pool` 0.2.0) — see
/// PHASE_8_PLAN §4A.8.
const DBC_POOL_SQRT_PRICE_OFFSET: usize = 280;
const DAMM_V2_POOL_SQRT_PRICE_OFFSET: usize = 456;

/// Read the venue pool's current `sqrt_price` (Meteora Q64.64: `sqrt(price) *
/// 2^64`, where `price` is raw-quote-units per raw-base-unit). Used as the
/// on-chain expected-out reference for the slippage floor — far more accurate
/// for a sqrt-price curve/AMM than a constant-product estimate off the vault
/// balances (which over-predicts a DBC bonding curve by ~50%, empirically).
fn read_pool_sqrt_price(pool: &AccountInfo, offset: usize) -> Result<u128> {
    let data = pool.try_borrow_data().map_err(|_| error!(ErrorCode::MalformedPoolAccount))?;
    let end = offset
        .checked_add(16)
        .ok_or(ErrorCode::MalformedPoolAccount)?;
    require!(data.len() >= end, ErrorCode::MalformedPoolAccount);
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&data[offset..end]);
    Ok(u128::from_le_bytes(buf))
}

pub(crate) fn handler(ctx: Context<BurnTokens>, min_out: u64) -> Result<()> {
    let venue = ctx.accounts.token_config.venue;
    let burn_vault_bump = ctx.accounts.token_config.burn_vault_bump;
    let max_slippage_bps = ctx.accounts.token_config.max_slippage_bps;

    // 0. Venue routing. Only the DBC curve (pre-graduation) and DAMM v2 (the
    //    graduation target pinned at DBC pool creation) are supported. DAMM v1 is
    //    never a migration target for $TOGGLD, so it is rejected even though the
    //    discriminant exists in the enum (PHASE_8_PLAN §4A.8).
    let program_id = match venue {
        TokenConfig::VENUE_DBC_CURVE => dbc_cpi::DBC_PROGRAM_ID,
        TokenConfig::VENUE_DAMM_V2 => dbc_cpi::DAMM_V2_PROGRAM_ID,
        _ => return Err(error!(ErrorCode::InvalidVenue)),
    };
    require!(
        ctx.accounts.dbc_program.key() == program_id,
        ErrorCode::InvalidVenue
    );
    // DBC `swap2` needs its `config` account; DAMM v2 has none.
    if venue == TokenConfig::VENUE_DBC_CURVE {
        require!(ctx.accounts.dbc_config.is_some(), ErrorCode::InvalidVenue);
    }

    // 1. Compute the sweep. The rent-exempt reserve for a 0-byte account is
    //    NEVER swept, so `burn_vault` can always pay its own rent and remain a
    //    live System-owned account (mirrors the vault-drain guard in settle).
    let rent_exempt_reserve = Rent::get()?.minimum_balance(0);
    let vault_lamports = ctx.accounts.burn_vault.lamports();
    let sweep = vault_lamports
        .checked_sub(rent_exempt_reserve)
        .ok_or(ErrorCode::SweepBelowRentExempt)?;
    require!(sweep >= MIN_SWEEP_LAMPORTS, ErrorCode::NothingToSweep);

    // 2. `min_out` is the on-chain price floor. `swap2` (ExactIn) reverts if the
    //    swap returns less than this, so a sandwich can never push our realized
    //    price below `min_out`. The keeper computes it from a read-only
    //    pre-quote as `expected_out * (1 - slippage)`; `setup_token()` has
    //    already clamped `token_config.max_slippage_bps` to
    //    `MAX_SLIPPAGE_BPS_CEILING`. The belt check below re-asserts that here.
    require!(min_out > 0, ErrorCode::MinOutZero);
    require!(
        max_slippage_bps <= MAX_SLIPPAGE_BPS_CEILING,
        ErrorCode::SlippageToleranceTooWide
    );

    // 2b. On-chain expected-out floor (PHASE_8_PLAN §4A.7/§4A.8).
    //
    //     Reference = the venue pool's own `sqrt_price` (Q64.64). With
    //     `price = sqrt_price^2 / 2^128` (raw quote per raw base),
    //     `expected_out = sweep / price = sweep * 2^128 / sqrt_price^2`, staged
    //     through two `u128` mul/div so no intermediate overflows:
    //         t            = sweep * 2^64 / sqrt_price
    //         expected_out  = t     * 2^64 / sqrt_price
    //     This tracks a sqrt-price curve/AMM to within a few percent (a
    //     constant-product estimate off vault balances over-predicts a DBC
    //     bonding curve by ~50%). `max_slippage_bps` (<= 500) is the headroom
    //     for fees + intra-tx price drift; a permissionless `min_out: 1`
    //     sandwich still trips `SlippageFloorNotMet`.
    let sqrt_price_offset = if venue == TokenConfig::VENUE_DBC_CURVE {
        DBC_POOL_SQRT_PRICE_OFFSET
    } else {
        DAMM_V2_POOL_SQRT_PRICE_OFFSET
    };
    let sqrt_price = read_pool_sqrt_price(&ctx.accounts.dbc_pool.to_account_info(), sqrt_price_offset)?;
    require!(sqrt_price > 0, ErrorCode::MalformedPoolAccount);
    const Q64: u128 = 1u128 << 64;
    let t = (sweep as u128)
        .checked_mul(Q64)
        .ok_or(ErrorCode::MathOverflow)?
        / sqrt_price;
    let expected_out = t
        .checked_mul(Q64)
        .ok_or(ErrorCode::MathOverflow)?
        / sqrt_price;
    let floor = expected_out
        .checked_mul(10_000u128 - max_slippage_bps as u128)
        .ok_or(ErrorCode::MathOverflow)?
        / 10_000u128;
    require!((min_out as u128) >= floor, ErrorCode::SlippageFloorNotMet);

    let burn_vault_seeds: &[&[u8]] = &[BURN_VAULT_SEED, &[burn_vault_bump]];
    let signer_seeds: &[&[&[u8]]] = &[burn_vault_seeds];

    // 3. Wrap the swept lamports into `burn_vault`'s WSOL ATA (the venue's quote
    //    mint is WSOL — the wrap is unavoidable, §4A.3).
    system_program::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.key(),
            SystemTransfer {
                from: ctx.accounts.burn_vault.to_account_info(),
                to: ctx.accounts.burn_vault_wsol_ata.to_account_info(),
            },
            signer_seeds,
        ),
        sweep,
    )?;
    token::sync_native(CpiContext::new(
        ctx.accounts.token_program.key(),
        SyncNative {
            account: ctx.accounts.burn_vault_wsol_ata.to_account_info(),
        },
    ))?;

    // 4. Swap WSOL -> $TOGGLD. `burn_vault` PDA signs as `payer`. `config` is
    //    present only for DBC.
    let toggld_before = ctx.accounts.burn_vault_toggld_ata.amount;
    let swap_accounts = dbc_cpi::Swap2Accounts {
        pool_authority: ctx.accounts.dbc_pool_authority.to_account_info(),
        config: ctx
            .accounts
            .dbc_config
            .as_ref()
            .map(|a| a.to_account_info()),
        pool: ctx.accounts.dbc_pool.to_account_info(),
        input_token_account: ctx.accounts.burn_vault_wsol_ata.to_account_info(),
        output_token_account: ctx.accounts.burn_vault_toggld_ata.to_account_info(),
        base_vault: ctx.accounts.dbc_base_vault.to_account_info(),
        quote_vault: ctx.accounts.dbc_quote_vault.to_account_info(),
        base_mint: ctx.accounts.mint.to_account_info(),
        quote_mint: ctx.accounts.wsol_mint.to_account_info(),
        payer: ctx.accounts.burn_vault.to_account_info(),
        token_base_program: ctx.accounts.token_program.to_account_info(),
        token_quote_program: ctx.accounts.token_program.to_account_info(),
        referral_token_account: None,
        event_authority: ctx.accounts.dbc_event_authority.to_account_info(),
        dbc_program: ctx.accounts.dbc_program.to_account_info(),
    };
    dbc_cpi::swap2(
        &swap_accounts,
        SwapParameters2 {
            amount_0: sweep,
            amount_1: min_out,
            swap_mode: SwapMode::ExactIn as u8,
        },
        program_id,
        signer_seeds,
    )?;

    // 5. Burn every $TOGGLD received this call.
    ctx.accounts.burn_vault_toggld_ata.reload()?;
    let received = ctx
        .accounts
        .burn_vault_toggld_ata
        .amount
        .checked_sub(toggld_before)
        .ok_or(ErrorCode::MathOverflow)?;
    require!(received > 0, ErrorCode::NothingToSweep);

    token::burn(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.key(),
            Burn {
                mint: ctx.accounts.mint.to_account_info(),
                from: ctx.accounts.burn_vault_toggld_ata.to_account_info(),
                authority: ctx.accounts.burn_vault.to_account_info(),
            },
            signer_seeds,
        ),
        received,
    )?;

    // 6. Close the transient WSOL ATA back to `burn_vault` — recovers the ATA
    //    rent and any un-swapped WSOL dust into the vault (which is itself
    //    burn-bound, so nothing leaks out of the burn path).
    token::close_account(CpiContext::new_with_signer(
        ctx.accounts.token_program.key(),
        CloseAccount {
            account: ctx.accounts.burn_vault_wsol_ata.to_account_info(),
            destination: ctx.accounts.burn_vault.to_account_info(),
            authority: ctx.accounts.burn_vault.to_account_info(),
        },
        signer_seeds,
    ))?;

    // 7. Running on-chain counter + public event.
    let token_config = &mut ctx.accounts.token_config;
    token_config.total_tokens_burned = token_config
        .total_tokens_burned
        .checked_add(received)
        .ok_or(ErrorCode::MathOverflow)?;

    emit!(TokensBurnedEvent {
        sol_swapped: sweep,
        tokens_received: received,
        tokens_burned: received,
    });

    Ok(())
}
