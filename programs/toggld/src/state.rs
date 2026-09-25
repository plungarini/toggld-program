use anchor_lang::prelude::*;

#[account]
pub struct GlobalState {
    pub holder: Pubkey,
    pub holder_since: i64,
    pub current_price: u64,
    pub is_on: bool,
    pub total_challenges: u64,

    /// Count of distinct holders this toggle has ever had, genesis included.
    /// Starts at 1 (the genesis/treasury holder) and increments by 1 on every
    /// FLIP (never on a defend). This is the "holder #" a Win NFT snapshots --
    /// deliberately separate from `total_challenges`, which counts every
    /// `settle()` call regardless of whether it flipped. Also used as the seed
    /// ordinal for that flip's `WinRecord` PDA (the PRE-increment value -- see
    /// `settle.rs`).
    pub holder_count: u64,

    pub treasury: Pubkey,
    pub burn_address: Pubkey,
    pub fee_bps: u16,
    pub admin: Pubkey,
    pub params_locked: bool,

    // beta-tunable (blocked once params_locked)
    pub min_raise_bps: u16,
    pub base_window_secs: u32,
    pub genesis_price: u64,

    // active-window state
    pub window_active: bool,
    pub window_end_ts: i64,
    pub top_bidder: Pubkey,
    pub top_bid_amount: u64,

    // vault accounting
    pub escrowed_amount: u64,
    pub treasury_balance: u64,

    pub vault_bump: u8,
}

/// One per bidder who has ever been outbid and not yet claimed their refund.
/// PDA-per-bidder (seeded by the bidder's own pubkey) rather than a single
/// embedded field on `GlobalState`: under the old inline-transfer design a
/// new challenge always fully resolved the previous bidder before becoming
/// the new top bid, so at most one refund was ever outstanding. Pull-based
/// refunds break that invariant -- a bidder can go unclaimed across many
/// subsequent outbids by *other* bidders -- so multiple distinct bidders can
/// legitimately have unclaimed refunds at the same time. A single shared
/// slot cannot represent that; a per-bidder account can, with no bound on
/// how many can be outstanding at once (the only cost is the rent-exempt
/// reserve, paid by whoever's bid creates the slot and refunded back to the
/// claimant when they claim).
#[account]
pub struct PendingRefund {
    /// The bidder this refund belongs to. Redundant with the PDA's own seed
    /// (which is derived from this same pubkey) but kept explicit so
    /// `claim_refund()` can enforce `claimant.key() == pending_refund.bidder`
    /// without re-deriving the PDA itself.
    pub bidder: Pubkey,
    /// Lamports owed, accumulated across every outbid this bidder has
    /// suffered without claiming in between. The actual lamports backing
    /// this amount live in this account's own balance (moved here out of
    /// the vault at outbid time), not in the vault -- so the vault's
    /// escrow/treasury invariant is unaffected by any number of unclaimed
    /// refunds sitting in these side accounts.
    pub amount: u64,
    pub bump: u8,
    /// Whoever's `challenge()` call paid this account's rent-exempt reserve
    /// on first creation (`init_if_needed`'s `payer = challenger` --
    /// `bidder`'s own outbidder, a different person than `bidder`). Set once,
    /// on creation, and never touched again by the accumulate-only path.
    ///
    /// `claim_refund()` must return this reserve to `rent_payer`, never to
    /// `bidder` -- `bidder` already gets exactly `amount` (their own money,
    /// nothing more). Before this field existed, the reserve went to
    /// `bidder` along with `amount`, silently moving `rent_payer`'s money to
    /// an unrelated third party on every claim -- a direct user-to-user
    /// transfer, which this program's invariants (see root `CLAUDE.md`)
    /// forbid. Every claim now pays out to exactly the two people who put
    /// money in: `bidder` gets `amount`, `rent_payer` gets the reserve.
    pub rent_payer: Pubkey,
}

impl PendingRefund {
    pub const SPACE: usize = 8 + 32 + 8 + 1 + 32;
}

// ---------------------------------------------------------------------------
// Phase R3 — Win NFT
// ---------------------------------------------------------------------------

/// One per FLIP (never created for a defend), plus exactly one more for the
/// genesis holder (see below). PDA seeded by `[WIN_RECORD_SEED,
/// &pre_increment_holder_count.to_le_bytes()]` -- a unique, client-derivable
/// ordinal known before calling `settle()` (it's just the current
/// `global_state.holder_count`). Created by `settle()` itself, manually
/// (`system_program::create_account` CPI + direct field writes), mirroring
/// the existing hand-rolled `vault` creation in `initialize.rs` -- NOT via
/// Anchor's `init`/`init_if_needed`, since whether this account gets created
/// at all depends on a runtime condition (`flipped`) the account macros
/// can't express.
///
/// The genesis holder (holder #1, assigned directly by `initialize()`) never
/// flips into holdership via `settle()`, so without a second creator they
/// could never earn a Win NFT for it. `initialize()` creates their
/// `WinRecord` itself, at the reserved seed ordinal `0` -- which can never
/// collide with a real flip's ordinal, always `>= 1` (`holder_count` starts
/// at `1` and only ever increments; see `settle.rs` and `initialize.rs`'s
/// handler for the full reasoning). It's the exact same manual
/// creation/serialization pattern, just inlined in `initialize()` instead of
/// gated behind `flipped`. `price_paid` is `0` for this one record (no
/// auction happened -- `initialize()` assigns `global_state.holder =
/// treasury` directly, not via a winning bid).
///
/// Eligibility to mint lives HERE, not on `GlobalState`: a holder can mint
/// their own recorded win at any later time, even after being outbid
/// again, since this record is independent of who currently holds the
/// toggle. `Account<'info, WinRecord>`'s own discriminator + owner check
/// is sufficient proof this was legitimately created by `settle()` -- no
/// separate PDA-derivation re-check is needed in `mint_win_nft`, only
/// `winner == caller` and `!minted`.
#[account]
pub struct WinRecord {
    pub winner: Pubkey,
    /// The holder # this win represents (post-increment -- "you are the
    /// Nth holder"), distinct from the seed ordinal used to derive this
    /// account's own address (which is the PRE-increment value).
    pub holder_count: u64,
    pub price_paid: u64,
    pub won_at: i64,
    pub minted: bool,
    pub bump: u8,
}

impl WinRecord {
    /// 8 (discriminator) + 32 winner + 8 holder_count + 8 price_paid
    /// + 8 won_at + 1 minted + 1 bump = 8 + 58.
    pub const SPACE: usize = 8 + 32 + 8 + 8 + 8 + 1 + 1;
}

/// One-time PDA (`seeds = [NFT_COLLECTION_CONFIG_SEED]`) written by
/// `init_nft_collection()`. Records the mpl-core Collection account every
/// `mint_win_nft()` call links its new asset into, so that account is
/// constrained (`address = nft_collection_config.collection`) rather than
/// trusted from caller input.
#[account]
pub struct NftCollectionConfig {
    /// The mpl-core Collection account address.
    pub collection: Pubkey,
    /// Bump for the `collection_authority` PDA (`seeds =
    /// [COLLECTION_AUTHORITY_SEED]`) -- the Collection's on-chain
    /// `update_authority`, used to `invoke_signed` the per-mint linkage CPI.
    pub collection_authority_bump: u8,
    pub bump: u8,
}

impl NftCollectionConfig {
    /// 8 (discriminator) + 32 collection + 1 collection_authority_bump + 1 bump.
    pub const SPACE: usize = 8 + 32 + 1 + 1;
}

// ---------------------------------------------------------------------------
// Phase 8 — $TOGGLD token launch
// ---------------------------------------------------------------------------

/// One-time PDA (`seeds = [TOKEN_CONFIG_SEED]`) written by `setup_token()`.
///
/// Deliberately a *separate* account rather than a `GlobalState` realloc:
/// `GlobalState` is already live on mainnet holding real user funds in
/// `escrowed_amount`, its space is a hand-computed literal with no reserved
/// padding, and growing it would need a migration instruction plus a window
/// where old/new-shape readers disagree. `TokenConfig` is `init`-only and
/// touches zero bytes of `GlobalState`. See PHASE_8_PLAN §2.1.
#[account]
pub struct TokenConfig {
    /// The $TOGGLD SPL mint this program is wired to.
    pub toggld_mint: Pubkey,
    /// Bump for the `burn_vault` PDA (`seeds = [BURN_VAULT_SEED]`).
    pub burn_vault_bump: u8,
    /// Bump for `burn_vault`'s associated $TOGGLD token account. Stored so
    /// `burn_tokens()` never has to re-derive it.
    pub burn_vault_ata_bump: u8,
    /// Swap-venue discriminant — MUST be a discriminant, not a single address,
    /// because the venue changes when the DBC curve graduates to DAMM v1/v2:
    /// `0 = DbcCurve`, `1 = DammV1`, `2 = DammV2` (PHASE_8_PLAN §4A.5).
    pub venue: u8,
    /// The DBC virtual pool / DAMM pool this program swaps against.
    pub pool_address: Pubkey,
    /// DBC partner config key (venue 0) / DAMM pool config (venue 1/2).
    pub venue_config: Pubkey,
    /// Hard ceiling on the keeper-supplied swap slippage bound, in bps.
    /// Clamped to `MAX_SLIPPAGE_BPS_CEILING` at `setup_token()` time.
    pub max_slippage_bps: u16,
    /// On-chain running total of $TOGGLD burned by `burn_tokens()` — a
    /// belt-and-suspenders counter independent of the off-chain indexer.
    pub total_tokens_burned: u64,
    /// Forward padding. `TokenConfig` is `init`-only, but leave room.
    pub reserved: [u8; 64],
}

impl TokenConfig {
    /// 8 (discriminator)
    /// + 32 toggld_mint + 1 burn_vault_bump + 1 burn_vault_ata_bump + 1 venue
    /// + 32 pool_address + 32 venue_config + 2 max_slippage_bps
    /// + 8 total_tokens_burned + 64 reserved = 8 + 173.
    pub const SPACE: usize = 8 + 32 + 1 + 1 + 1 + 32 + 32 + 2 + 8 + 64;

    pub const VENUE_DBC_CURVE: u8 = 0;
    pub const VENUE_DAMM_V1: u8 = 1;
    pub const VENUE_DAMM_V2: u8 = 2;
}

/// One-time PDA (`seeds = [TEAM_VESTING_SEED]`) written by
/// `init_team_vesting()`. Records an immutable linear-release schedule for the
/// team's 5% allocation — there is no instruction anywhere in the program that
/// can accelerate, pause, or change it once written. See PHASE_8_PLAN §2.2.
#[account]
pub struct TeamVesting {
    /// The $TOGGLD mint this schedule locks. Recorded so `claim_vested()` can
    /// pin its `mint` account without needing `TokenConfig` in scope (vesting
    /// is initialized during the launch mint, before `setup_token()` runs).
    pub mint: Pubkey,
    /// Total $TOGGLD locked in this schedule (held in the PDA's own ATA).
    pub total_amount: u64,
    /// Unix timestamp the linear release begins at. Nothing is claimable
    /// before this.
    pub start_ts: i64,
    /// Length of the linear release, in seconds. `total_amount` is fully
    /// unlocked at `start_ts + duration_secs`.
    pub duration_secs: i64,
    /// Cumulative $TOGGLD already claimed via `claim_vested()`.
    pub claimed_amount: u64,
    pub bump: u8,
}

impl TeamVesting {
    /// 8 (discriminator) + 32 mint + 8 total_amount + 8 start_ts
    /// + 8 duration_secs + 8 claimed_amount + 1 bump = 8 + 65.
    pub const SPACE: usize = 8 + 32 + 8 + 8 + 8 + 8 + 1;

    /// Guard rails for `init_team_vesting` args. `start_ts` may sit slightly in
    /// the past (clock skew / tx delay) but not far enough to make a meaningful
    /// slice unlock instantly, which would defeat the lock. `duration_secs` must
    /// be a real release window, not effectively-instant.
    pub const MAX_START_BACKDATE_SECS: i64 = 3_600; // 1 hour
    pub const MIN_DURATION_SECS: i64 = 30 * 24 * 3_600; // 30 days
    pub const MAX_DURATION_SECS: i64 = 10 * 365 * 24 * 3_600; // 10 years
}
