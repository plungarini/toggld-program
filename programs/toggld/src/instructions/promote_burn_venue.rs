use anchor_lang::prelude::*;

use crate::constants::*;
use crate::error::ErrorCode;
use crate::instructions::events::BurnVenuePromotedEvent;
use crate::state::{GlobalState, TokenConfig};

/// Admin-gated, event-emitting. Run once after Meteora's migrator graduates the
/// DBC curve to a DAMM v2 pool: repoints `TokenConfig.venue`/`pool_address`/
/// `venue_config` so `burn_tokens()` swaps against the graduated pool instead of
/// the dead curve.
///
/// This instruction can **only** change swap routing. It has no access to the
/// split (`fee_bps`), the burn mechanic, `treasury`, or any other locked
/// invariant — none of those fields are in `TokenConfig` at all.
#[derive(Accounts)]
pub struct PromoteBurnVenue<'info> {
    pub admin: Signer<'info>,

    #[account(
        seeds = [GLOBAL_STATE_SEED],
        bump,
        has_one = admin @ ErrorCode::Unauthorized,
    )]
    pub global_state: Account<'info, GlobalState>,

    #[account(mut, seeds = [TOKEN_CONFIG_SEED], bump)]
    pub token_config: Account<'info, TokenConfig>,
}

pub(crate) fn handler(
    ctx: Context<PromoteBurnVenue>,
    new_venue: u8,
    new_pool_address: Pubkey,
    new_venue_config: Pubkey,
) -> Result<()> {
    // Forward-only by construction, and must never disagree with
    // `burn_tokens()`'s own venue match: the only accepted promotion target is
    // `VENUE_DAMM_V2`. `VENUE_DAMM_V1` is rejected here too — $TOGGLD is never
    // migrated there (see `burn_tokens()`'s doc comment) — so this instruction
    // can never leave `TokenConfig.venue` pointed at a value `burn_tokens()`
    // unconditionally rejects. There is also no path back to `VENUE_DBC_CURVE`
    // (whose liquidity is gone once Meteora's migrator graduates the pool).
    // Still repeatable (not one-shot) so a wrong pool/config wiring can be
    // corrected without changing the venue itself.
    require!(new_venue == TokenConfig::VENUE_DAMM_V2, ErrorCode::InvalidVenue);
    require!(
        ctx.accounts.token_config.venue != new_venue
            || ctx.accounts.token_config.pool_address != new_pool_address
            || ctx.accounts.token_config.venue_config != new_venue_config,
        ErrorCode::VenueCannotRevert
    );

    let token_config = &mut ctx.accounts.token_config;
    token_config.venue = new_venue;
    token_config.pool_address = new_pool_address;
    token_config.venue_config = new_venue_config;

    emit!(BurnVenuePromotedEvent {
        venue: new_venue,
        pool_address: new_pool_address,
        venue_config: new_venue_config,
    });

    Ok(())
}
