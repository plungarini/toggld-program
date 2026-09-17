use anchor_lang::prelude::*;

/// Winning-bid split sent to treasury, in basis points. Immutable from deploy.
pub const FEE_BPS: u16 = 1500;

/// Solana's well-known unspendable incinerator address. Used as the burn destination because it
/// is System-Program-owned with no known keypair, so burned SOL is provably unspendable
/// independent of this program's own upgrade authority.
pub const INCINERATOR: Pubkey = pubkey!("1nc1nerator11111111111111111111111111111111");

/// Params fixed at `initialize()` and never adjustable afterward by anyone,
/// including the dev (R7: `update_params()`/`lock_params()` were dropped
/// entirely -- there is nothing to tune and nothing to lock, because it's
/// immutable from the first instant).
pub const DEFAULT_MIN_RAISE_BPS: u16 = 500;
pub const DEFAULT_BASE_WINDOW_SECS: u32 = 30;
pub const DEFAULT_SNIPE_EXTEND_SECS: u32 = 10;

/// PDA seeds, shared across every instruction that needs to derive or verify
/// the `GlobalState` / `Vault` addresses.
pub const GLOBAL_STATE_SEED: &[u8] = b"global_state";
pub const VAULT_SEED: &[u8] = b"vault";
/// Seed prefix for a bidder's `PendingRefund` PDA; combined with the
/// bidder's own pubkey as the second seed. See `state::PendingRefund`.
pub const REFUND_SEED: &[u8] = b"refund";

// ---------------------------------------------------------------------------
// Phase R3 — Win NFT
// ---------------------------------------------------------------------------

/// Seed prefix for a win's `WinRecord` PDA; combined with the pre-increment
/// `global_state.holder_count` ordinal (as `u64` LE bytes) as the second
/// seed. See `state::WinRecord`. Ordinal `0` is permanently reserved for the
/// genesis holder's `WinRecord` (created by `initialize()`, not `settle()`)
/// and can never collide with a real flip's ordinal, which is always `>= 1`.
pub const WIN_RECORD_SEED: &[u8] = b"win_record";

/// Sanity ceiling on `mint_win_nft`'s `uri` argument length, in bytes. A
/// generous but bounded cap -- Irys/Arweave metadata URIs are short; this
/// only guards against an obviously-degenerate oversized value, not a real
/// limiter.
pub const MAX_NFT_URI_LEN: usize = 200;

/// Dedicated "metadata signer" keypair (Mechanism 2, win-NFT tamper-proofing
/// -- see WIN_NFT_PAYMENT_SECURITY_PLAN.md §2.2). Attests off-chain metadata
/// content hashes only; it never holds funds or has any authority over the
/// game's money flows, a materially different risk profile than a
/// funds-moving key. Baked in as a program constant, same pattern as
/// `INCINERATOR` -- rotating it means a program upgrade, which is acceptable
/// since the admin already holds upgrade authority (not yet locked, per root
/// CLAUDE.md) and this key can never move funds either way.
///
/// This is the real local-dev keypair's public half -- its secret lives in
/// `apps/web/.env.local` (gitignored) as `NFT_METADATA_SIGNER_SECRET`,
/// generated fresh 2026-09-15 via `lib/nft/metadata-signer.ts`'s
/// `@noble/curves/ed25519` signing path (see that file's module doc). It
/// matches `tests/toggld.rs`'s `METADATA_SIGNER_SEED` fixture, so LiteSVM
/// tests exercise a genuine Ed25519Program attestation end-to-end -- but it
/// is still only a local-dev/test key. A genuinely different keypair MUST be
/// minted for a real mainnet/production deploy (same posture as every other
/// dev-vs-prod secret in this repo -- see root CLAUDE.md's "Local dev
/// environment" section), and this constant updated to match before that
/// deploy.
pub const METADATA_SIGNER: Pubkey = pubkey!("CmgGk8qipHS9bVSyD5e7PRyApBAh9k8cg4oGkyfk6xRB");

// ---------------------------------------------------------------------------
// Phase 8 — $TOGGLD token launch
// ---------------------------------------------------------------------------

/// Seeds for the one-time `TokenConfig` PDA created by `setup_token()`.
pub const TOKEN_CONFIG_SEED: &[u8] = b"token_config";
/// Seeds for the `burn_vault` PDA — a plain System-Program-owned account that
/// only holds lamports, mirroring `vault`. `settle()`'s 85% burn leg is
/// repointed here by `setup_token()` (it sets `global_state.burn_address` to
/// this PDA), and `burn_tokens()` sweeps it into $TOGGLD and burns it.
pub const BURN_VAULT_SEED: &[u8] = b"burn_vault";
/// Seeds for the `TeamVesting` PDA created by `init_team_vesting()`.
pub const TEAM_VESTING_SEED: &[u8] = b"team_vesting";

/// Native SOL wrapped-mint (WSOL). Meteora DBC's quote mint is WSOL, so
/// `burn_tokens()` must wrap the swept lamports into a short-lived
/// `burn_vault`-owned WSOL ATA before the swap CPI.
pub const WSOL_MINT: Pubkey = pubkey!("So11111111111111111111111111111111111111112");

/// Hard ceiling on the keeper-supplied `max_slippage_bps` stored in
/// `TokenConfig`. `setup_token()` rejects any value above this so a compromised
/// or buggy keeper can never widen the swap's slippage bound past 5%
/// (PHASE_8_PLAN §4A.7).
pub const MAX_SLIPPAGE_BPS_CEILING: u16 = 500;

/// Dust guard for `burn_tokens()`: a sweep smaller than this (after reserving
/// the burn vault's rent-exempt minimum) is rejected so the keeper never spends
/// more on tx fees / price impact than the sweep is worth. Mirrors the
/// keeper-side `MIN_SWEEP_LAMPORTS` (PHASE_8_PLAN §5).
pub const MIN_SWEEP_LAMPORTS: u64 = 10_000_000; // 0.01 SOL

/// Reference figures for the launch distribution (PHASE_8_PLAN §3). Not
/// enforced on-chain — the mint + initial distribution happen via scripts —
/// but kept here as the single source of truth the scripts/tests read.
pub const TOKEN_DECIMALS: u8 = 9;
/// 1,000,000,000 $TOGGLD at 9 decimals.
pub const TOTAL_TOKEN_SUPPLY: u64 = 1_000_000_000 * 1_000_000_000;
/// 5% (50,000,000 $TOGGLD) — the linearly-vesting team allocation.
pub const TEAM_ALLOCATION: u64 = 50_000_000 * 1_000_000_000;
/// 95% (950,000,000 $TOGGLD) — seeded into the liquidity venue.
pub const POOL_ALLOCATION: u64 = TOTAL_TOKEN_SUPPLY - TEAM_ALLOCATION;
