use anchor_lang::prelude::*;

/// Emitted on every successful `challenge()` call.
#[event]
pub struct ChallengeEvent {
    pub challenger: Pubkey,
    pub bid_amount: u64,
    pub window_end_ts: i64,
    /// True when this bid reset an already-active window to `now + base_window_secs`;
    /// false for a cold open, which starts a fresh window instead.
    pub extended: bool,
}

/// Emitted on every successful `settle()` call.
#[event]
pub struct SettleEvent {
    pub winner: Pubkey,
    pub previous_holder: Pubkey,
    /// True when this settlement changed the holder (a "flip"); false for a
    /// successful defense by the existing holder.
    pub flipped: bool,
    pub winning_price: u64,
    pub treasury_cut: u64,
    pub burned_amount: u64,
}

/// Emitted unconditionally on every successful `withdraw_treasury()` call, so
/// treasury draws are publicly auditable on-chain.
#[event]
pub struct TreasuryWithdrawEvent {
    pub admin: Pubkey,
    pub treasury: Pubkey,
    pub amount: u64,
    pub timestamp: i64,
}

/// Emitted on every successful `claim_refund()` call.
#[event]
pub struct RefundClaimedEvent {
    pub claimant: Pubkey,
    pub amount: u64,
}

// ---------------------------------------------------------------------------
// Phase 8 — $TOGGLD token launch
// ---------------------------------------------------------------------------

/// Emitted by the one-time `setup_token()` call, so it is publicly verifiable
/// which mint / venue / pool the contract's burn path is wired to.
#[event]
pub struct TokenConfiguredEvent {
    pub mint: Pubkey,
    pub burn_vault: Pubkey,
    pub venue: u8,
    pub pool_address: Pubkey,
    pub venue_config: Pubkey,
    pub max_slippage_bps: u16,
}

/// Emitted by the one-time `init_team_vesting()` call, so the full unlock
/// timeline is publicly checkable from day one.
#[event]
pub struct TeamVestingInitializedEvent {
    pub mint: Pubkey,
    pub total_amount: u64,
    pub start_ts: i64,
    pub duration_secs: i64,
}

/// Emitted on every successful `claim_vested()` call.
#[event]
pub struct VestedClaimedEvent {
    /// Amount transferred to the admin on this call.
    pub amount: u64,
    /// Cumulative claimed after this call.
    pub claimed_total: u64,
    /// Total unlocked by the schedule as of this call.
    pub unlocked: u64,
}

/// Emitted on every successful `burn_tokens()` call — this is the event the
/// indexer folds into the live "total $TOGGLD burned" figure.
#[event]
pub struct TokensBurnedEvent {
    /// Lamports consumed from `burn_vault` for this sweep.
    pub sol_swapped: u64,
    /// $TOGGLD received from the swap (pre-burn).
    pub tokens_received: u64,
    /// $TOGGLD actually burned — equals `tokens_received`; kept distinct for a
    /// possible future partial-burn case.
    pub tokens_burned: u64,
}

/// Emitted by `promote_burn_venue()` after the DBC curve graduates to a DAMM
/// pool. Records only the new swap routing — it can never touch a
/// split/burn/mechanic invariant.
#[event]
pub struct BurnVenuePromotedEvent {
    pub venue: u8,
    pub pool_address: Pubkey,
    pub venue_config: Pubkey,
}

// ---------------------------------------------------------------------------
// Phase R3 — Win NFT
// ---------------------------------------------------------------------------

/// Emitted on every successful `mint_win_nft()` call — gives the
/// keeper/indexer a clean on-chain record without re-deriving it from
/// `SettleEvent` plus timing.
#[event]
pub struct WinNftMintedEvent {
    pub winner: Pubkey,
    pub asset: Pubkey,
    pub holder_count: u64,
    pub price_paid: u64,
    pub won_at: i64,
    pub minted_at: i64,
    pub uri: String,
}

/// Emitted by the one-time `init_nft_collection()` call, so the collection's
/// address and its royalty/creator terms are publicly verifiable from day one.
#[event]
pub struct NftCollectionInitializedEvent {
    pub collection: Pubkey,
    pub treasury: Pubkey,
    pub royalty_basis_points: u16,
}
