//! Hand-rolled CPI into Meteora Dynamic Bonding Curve (`swap2`).
//!
//! We deliberately do **not** depend on the `dynamic-bonding-curve` crate: its
//! transitive graph does not build cleanly against our Anchor toolchain
//! (`spl-list-view` solana-program v2/v3 split; `ruint 1.20` vs platform-tools
//! rustc — see `PHASE_8_PLAN.md` §4A.2). Instead we emit the instruction by
//! hand — 8-byte Anchor discriminator + Borsh-encoded params — and
//! `invoke_signed` it with the `burn_vault` PDA as `payer`/authority.
//!
//! Layout facts, all cross-checked against DBC IDL `0.1.6`
//! (`scripts/idl/release_0.1.6.json` in `MeteoraAg/dynamic-bonding-curve`) and
//! `programs/dynamic-bonding-curve/src/instructions/swap/ix_swap.rs`:
//!   * program id (devnet == mainnet): `dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN`
//!   * `swap2` discriminator: `[65, 75, 63, 76, 235, 91, 91, 136]`
//!   * `SwapParameters2 { amount_0: u64, amount_1: u64, swap_mode: u8 }`
//!   * `#[event_cpi]` on the callee => `event_authority` + `program` are the
//!     last two accounts and are mandatory.
//!   * `referral_token_account` is optional; when omitted, Anchor's convention
//!     is to pass the callee program id as a placeholder key.

#![allow(dead_code)]

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
};

/// Meteora DBC program — identical address on devnet and mainnet-beta.
pub const DBC_PROGRAM_ID: Pubkey = pubkey!("dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN");

/// Meteora DAMM v2 (`cp-amm`) program — the post-graduation swap venue for
/// $TOGGLD. Its `swap2` is account-for-account identical to DBC's `swap2`
/// *minus* the `config` account at meta index 1; same discriminator, same
/// `SwapParameters2` layout (PHASE_8_PLAN §4A.8).
pub const DAMM_V2_PROGRAM_ID: Pubkey = pubkey!("cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG");

/// `sha256("global:swap2")[..8]`.
const SWAP2_DISCRIMINATOR: [u8; 8] = [65, 75, 63, 76, 235, 91, 91, 136];

/// DBC `SwapMode` discriminant values (`process_swap.rs`).
#[repr(u8)]
pub enum SwapMode {
    ExactIn = 0,
    PartialFill = 1,
    ExactOut = 2,
}

/// Borsh-compatible mirror of DBC's `SwapParameters2`. Field order and types
/// must match the callee exactly.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug)]
pub struct SwapParameters2 {
    /// ExactIn / PartialFill: `amount_in`. ExactOut: `amount_out`.
    pub amount_0: u64,
    /// ExactIn / PartialFill: `minimum_amount_out`. ExactOut: `maximum_amount_in`.
    pub amount_1: u64,
    pub swap_mode: u8,
}

/// Accounts for a Meteora `swap2` CPI, in IDL order. Field names use DBC's
/// terminology; for DAMM v2 the positions are identical and map as follows
/// (PHASE_8_PLAN §4A.8):
///
/// - `config` -> omitted for DAMM v2 (pass `None`; DAMM v2 `swap2` has no
///   `config` account).
/// - `base_vault` / `quote_vault` -> DAMM v2 `token_a_vault` / `token_b_vault`.
/// - `base_mint` / `quote_mint` -> DAMM v2 `token_a_mint` / `token_b_mint`.
/// - everything else -> same account, same position.
pub struct Swap2Accounts<'info> {
    pub pool_authority: AccountInfo<'info>,
    /// `Some` for DBC (emitted at meta index 1); `None` for DAMM v2 (omitted).
    pub config: Option<AccountInfo<'info>>,
    pub pool: AccountInfo<'info>,
    /// Quote (WSOL) token account funds are swapped *from* — a `burn_vault` ATA.
    pub input_token_account: AccountInfo<'info>,
    /// Base ($TOGGLD) token account tokens are received *into* — a `burn_vault` ATA.
    pub output_token_account: AccountInfo<'info>,
    /// DBC pool base-token vault / DAMM v2 `token_a_vault`.
    pub base_vault: AccountInfo<'info>,
    /// DBC pool quote-token vault / DAMM v2 `token_b_vault`.
    pub quote_vault: AccountInfo<'info>,
    /// DBC `base_mint` / DAMM v2 `token_a_mint`.
    pub base_mint: AccountInfo<'info>,
    /// DBC `quote_mint` / DAMM v2 `token_b_mint`.
    pub quote_mint: AccountInfo<'info>,
    /// `burn_vault` PDA — signs via `signer_seeds`.
    pub payer: AccountInfo<'info>,
    pub token_base_program: AccountInfo<'info>,
    pub token_quote_program: AccountInfo<'info>,
    pub referral_token_account: Option<AccountInfo<'info>>,
    /// `#[event_cpi]` pair.
    pub event_authority: AccountInfo<'info>,
    /// The venue program account itself (also the `#[event_cpi]` `program`).
    pub dbc_program: AccountInfo<'info>,
}

/// Invoke Meteora `swap2` on `program_id` (DBC or DAMM v2), signed by the
/// `burn_vault` PDA. Pass `accts.config = Some(..)` for DBC and `None` for
/// DAMM v2 — the two layouts differ *only* by that account at meta index 1.
pub fn swap2(
    accts: &Swap2Accounts<'_>,
    params: SwapParameters2,
    program_id: Pubkey,
    signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    let mut data = Vec::with_capacity(8 + 8 + 8 + 1);
    data.extend_from_slice(&SWAP2_DISCRIMINATOR);
    params.serialize(&mut data)?;

    let referral_meta = match &accts.referral_token_account {
        Some(a) => AccountMeta::new(*a.key, false),
        None => AccountMeta::new_readonly(program_id, false),
    };

    let mut accounts = Vec::with_capacity(15);
    accounts.push(AccountMeta::new_readonly(*accts.pool_authority.key, false));
    if let Some(cfg) = &accts.config {
        accounts.push(AccountMeta::new_readonly(*cfg.key, false));
    }
    accounts.push(AccountMeta::new(*accts.pool.key, false));
    accounts.push(AccountMeta::new(*accts.input_token_account.key, false));
    accounts.push(AccountMeta::new(*accts.output_token_account.key, false));
    accounts.push(AccountMeta::new(*accts.base_vault.key, false));
    accounts.push(AccountMeta::new(*accts.quote_vault.key, false));
    accounts.push(AccountMeta::new_readonly(*accts.base_mint.key, false));
    accounts.push(AccountMeta::new_readonly(*accts.quote_mint.key, false));
    accounts.push(AccountMeta::new_readonly(*accts.payer.key, true));
    accounts.push(AccountMeta::new_readonly(*accts.token_base_program.key, false));
    accounts.push(AccountMeta::new_readonly(*accts.token_quote_program.key, false));
    accounts.push(referral_meta);
    accounts.push(AccountMeta::new_readonly(*accts.event_authority.key, false));
    accounts.push(AccountMeta::new_readonly(*accts.dbc_program.key, false));

    let ix = Instruction {
        program_id,
        accounts,
        data,
    };

    let mut infos = Vec::with_capacity(15);
    infos.push(accts.pool_authority.clone());
    if let Some(cfg) = &accts.config {
        infos.push(cfg.clone());
    }
    infos.push(accts.pool.clone());
    infos.push(accts.input_token_account.clone());
    infos.push(accts.output_token_account.clone());
    infos.push(accts.base_vault.clone());
    infos.push(accts.quote_vault.clone());
    infos.push(accts.base_mint.clone());
    infos.push(accts.quote_mint.clone());
    infos.push(accts.payer.clone());
    infos.push(accts.token_base_program.clone());
    infos.push(accts.token_quote_program.clone());
    match &accts.referral_token_account {
        Some(a) => infos.push(a.clone()),
        // Placeholder `AccountInfo` for the `None` case — the venue program
        // account, matching the placeholder key used in the meta above.
        None => infos.push(accts.dbc_program.clone()),
    }
    infos.push(accts.event_authority.clone());
    infos.push(accts.dbc_program.clone());

    invoke_signed(&ix, &infos, signer_seeds)?;
    Ok(())
}
