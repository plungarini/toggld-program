use anchor_lang::prelude::*;

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized signer")]
    Unauthorized,

    #[msg("No active bidding window")]
    NoActiveWindow,

    #[msg("Bidding window closed; pending settlement")]
    WindowClosedPendingSettlement,

    #[msg("Window has not closed yet")]
    WindowNotClosed,

    #[msg("Bid amount is below the required minimum raise")]
    BidTooLow,

    #[msg("Nothing to refund for this account")]
    NothingToRefund,

    #[msg("Burn account does not match the configured burn address")]
    InvalidBurnAddress,

    #[msg("Treasury account does not match the configured treasury address")]
    InvalidTreasuryAccount,

    #[msg("Treasury balance is empty")]
    NothingToWithdraw,

    #[msg("Arithmetic overflow")]
    MathOverflow,

    #[msg("Genesis price must be greater than zero")]
    InvalidGenesisPrice,

    #[msg("Treasury address must not be zero")]
    InvalidTreasury,

    #[msg("Admin address must not be zero")]
    InvalidAdmin,

    #[msg("pending_refund account is required to refund the previous top bidder")]
    MissingPendingRefundAccount,

    #[msg("pending_refund account must be omitted on a cold-open challenge")]
    UnexpectedPendingRefundAccount,

    // --- Phase 8 ($TOGGLD token launch) ---
    #[msg("Token launch is already configured")]
    TokenAlreadyConfigured,

    #[msg("Token launch has not been configured yet")]
    TokenNotConfigured,

    #[msg("Nothing to sweep from the burn vault")]
    NothingToSweep,

    #[msg("Sweep would drop the burn vault below its rent-exempt minimum")]
    SweepBelowRentExempt,

    #[msg("Requested slippage tolerance is wider than the configured ceiling")]
    SlippageToleranceTooWide,

    #[msg("min_out must be greater than zero")]
    MinOutZero,

    #[msg("Vesting has not started yet")]
    VestingNotStarted,

    #[msg("Nothing has newly vested to claim")]
    NothingVestedToClaim,

    #[msg("Vesting total amount must be greater than zero")]
    InvalidVestingAmount,

    #[msg("Vesting start_ts / duration_secs is outside the allowed range")]
    InvalidVestingSchedule,

    #[msg("Unknown or unsupported swap venue")]
    InvalidVenue,

    #[msg("Burn venue can only advance (curve -> DAMM), never revert")]
    VenueCannotRevert,

    #[msg("Realized swap output is below the on-chain slippage floor")]
    SlippageFloorNotMet,

    #[msg("Swap venue pool account is malformed or has unexpected layout")]
    MalformedPoolAccount,

    #[msg("Holder cannot cold-open a challenge on themselves")]
    CannotChallengeSelf,

    #[msg("Bidder is already the top bidder")]
    AlreadyTopBidder,

    // --- Phase R3 (Win NFT) ---
    #[msg("Caller is not the recorded winner of this win")]
    NotWinRecordOwner,

    #[msg("This win has already been minted")]
    WinNftAlreadyMinted,

    #[msg("uri must be non-empty and no longer than the configured maximum")]
    InvalidNftUri,

    #[msg("Missing or invalid Ed25519 metadata-signer attestation for this content hash")]
    InvalidMetadataSignature,
}
