pub mod constants;
pub mod dbc_cpi;
pub mod error;
pub mod instructions;
pub mod pure;
pub mod state;

use anchor_lang::prelude::*;

pub use constants::*;
pub use instructions::*;
pub use state::*;

// Devnet and mainnet share this address by default (same program keypair,
// deployed independently per cluster, per CLAUDE.md's "Devnet BPF upgrade
// authority" note). The `devnet-scratch` feature swaps in a SEPARATE,
// devnet-only address for a disposable low-genesis-price deployment used
// purely for cheap real-money testing (2026-09-17) — price only ever moves
// up (a locked invariant, no reset instruction), so the shared devnet mirror
// gets permanently more expensive to test against over time; this lets a
// fresh, cheap deployment exist without touching the canonical
// devnet-mirrors-mainnet address above. Never build mainnet with this
// feature enabled — see Cargo.toml's `devnet-scratch` feature doc comment.
#[cfg(not(feature = "devnet-scratch"))]
declare_id!("TGLDv9L2xHKHRi2yQJSKt5QCKpH6fZrAz4kJ4wydPhR");
#[cfg(feature = "devnet-scratch")]
declare_id!("3VD3z82gxHoHneFdT3oVpYTfbzqfhYjhqREzTp1FyWhy");

// Gated `not(no-entrypoint)`, per `solana-security-txt`'s own README: the
// macro must never compile into a CPI/library build (a program that depends
// on this crate as a library, e.g. via `cpi = ["no-entrypoint"]`), or two
// copies of its `#[no_mangle] security_txt` static collide at link time
// ("multiple definition of security_txt").
//
// `source_revision` uses `default_env!` (the `env!` macro but with a
// fallback), the exact pattern this crate's own README recommends for this
// field, because plain `env!` has no default form and would hard-fail any
// build where the var isn't set. `TOGGLD_GIT_SHA` is NOT set by a plain
// `anchor build`/`cargo build-sbf` -- a real deploy's build wrapper MUST set
// it (e.g. `TOGGLD_GIT_SHA=$(git rev-parse HEAD) anchor build`) for this
// field to reflect the actually-deployed commit. Confirmed during Phase R7's
// local-validator pass that a freshly built binary's embedded revision
// matches `git rev-parse HEAD` before this is relied on for real. Without
// that env var, this falls back to the literal below, which must never be
// mistaken for a real revision.
#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "TOGGLD",
    project_url: "https://toggld.win",
    contacts: "email:pietro@lungarini.it",
    policy: "https://toggld.win/legal/risk-disclosure",
    source_code: "https://github.com/plungarini/toggld-program",
    source_revision: default_env::default_env!("TOGGLD_GIT_SHA", "unset-set-TOGGLD_GIT_SHA-at-build-time")
}

#[program]
pub mod toggld {
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
        treasury: Pubkey,
        admin: Pubkey,
        genesis_price: u64,
    ) -> Result<()> {
        initialize::handler(ctx, treasury, admin, genesis_price)
    }

    pub fn challenge(ctx: Context<Challenge>, bid_amount: u64) -> Result<()> {
        challenge::handler(ctx, bid_amount)
    }

    pub fn settle(ctx: Context<Settle>) -> Result<()> {
        settle::handler(ctx)
    }

    pub fn claim_refund(ctx: Context<ClaimRefund>) -> Result<()> {
        claim_refund::handler(ctx)
    }

    pub fn withdraw_treasury(ctx: Context<WithdrawTreasury>) -> Result<()> {
        withdraw_treasury::handler(ctx)
    }

    // --- Phase 8 ($TOGGLD token launch) ---

    /// One-time, admin-gated. Wires the program to the $TOGGLD mint + swap
    /// venue, creates the `burn_vault` PDA and its $TOGGLD ATA, and repoints
    /// `settle()`'s burn leg to the burn vault.
    pub fn setup_token(
        ctx: Context<SetupToken>,
        toggld_mint: Pubkey,
        venue: u8,
        pool_address: Pubkey,
        venue_config: Pubkey,
        max_slippage_bps: u16,
    ) -> Result<()> {
        setup_token::handler(
            ctx,
            toggld_mint,
            venue,
            pool_address,
            venue_config,
            max_slippage_bps,
        )
    }

    /// One-time, admin-gated. Repoints the swap venue after the DBC curve
    /// graduates to a DAMM pool. Cannot touch any split/burn/mechanic field.
    pub fn promote_burn_venue(
        ctx: Context<PromoteBurnVenue>,
        new_venue: u8,
        new_pool_address: Pubkey,
        new_venue_config: Pubkey,
    ) -> Result<()> {
        promote_burn_venue::handler(ctx, new_venue, new_pool_address, new_venue_config)
    }

    /// One-time, admin-gated. Locks the team's allocation into an immutable
    /// linear-release schedule held by a program PDA.
    pub fn init_team_vesting(
        ctx: Context<InitTeamVesting>,
        total_amount: u64,
        start_ts: i64,
        duration_secs: i64,
    ) -> Result<()> {
        init_team_vesting::handler(ctx, total_amount, start_ts, duration_secs)
    }

    /// Admin-gated. Transfers whatever has newly vested to the admin's ATA.
    /// The schedule itself is immutable — nothing here can accelerate it.
    pub fn claim_vested(ctx: Context<ClaimVested>) -> Result<()> {
        claim_vested::handler(ctx)
    }

    /// Permissionless (like `settle()`). Sweeps the burn vault's SOL into
    /// $TOGGLD via an on-chain swap CPI and burns it, reducing supply.
    pub fn burn_tokens(ctx: Context<BurnTokens>, min_out: u64) -> Result<()> {
        burn_tokens::handler(ctx, min_out)
    }

    // --- Phase R3 (Win NFT) ---

    /// Permissionless, callable by the winner recorded on `win_record` at
    /// any later time (no dependency on still being the current holder).
    /// Mints a snapshot-once, immutable Metaplex Core asset for that win.
    pub fn mint_win_nft(ctx: Context<MintWinNft>, uri: String, content_hash: [u8; 32]) -> Result<()> {
        mint_win_nft::handler(ctx, uri, content_hash)
    }

    /// One-time, admin-gated. Creates the shared mpl-core Collection every
    /// future `mint_win_nft()` call links its new asset into.
    pub fn init_nft_collection(ctx: Context<InitNftCollection>, name: String, uri: String) -> Result<()> {
        init_nft_collection::handler(ctx, name, uri)
    }
}
