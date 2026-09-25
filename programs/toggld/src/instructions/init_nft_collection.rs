use anchor_lang::prelude::*;
use anchor_lang::system_program::System;
use mpl_core::instructions::CreateCollectionV1CpiBuilder;
use mpl_core::types::{Creator, Plugin, PluginAuthority, PluginAuthorityPair, Royalties, RuleSet, UpdateDelegate, VerifiedCreators, VerifiedCreatorsSignature};

use crate::constants::*;
use crate::error::ErrorCode;
use crate::instructions::events::NftCollectionInitializedEvent;
use crate::state::{GlobalState, NftCollectionConfig};

/// One-time, admin-gated. Creates the shared mpl-core Collection every future
/// `mint_win_nft()` call links its new asset into, so the whole Win NFT
/// series shows up as one browsable/verifiable collection on marketplaces
/// (Tensor, Magic Eden) instead of standalone assets.
///
/// The collection's `update_authority` is `admin` itself, a real wallet --
/// deliberately NOT the `collection_authority` PDA -- so the project can
/// actually sign marketplace ownership-verification flows and manage the
/// collection's listing there. Permissionless per-winner minting still works
/// via a narrowly-scoped `UpdateDelegate` plugin naming the PDA as an
/// additional delegate (see the handler below).
#[derive(Accounts)]
pub struct InitNftCollection<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        seeds = [GLOBAL_STATE_SEED],
        bump,
        has_one = admin @ ErrorCode::Unauthorized,
    )]
    pub global_state: Account<'info, GlobalState>,

    #[account(
        init,
        payer = admin,
        space = NftCollectionConfig::SPACE,
        seeds = [NFT_COLLECTION_CONFIG_SEED],
        bump,
    )]
    pub nft_collection_config: Account<'info, NftCollectionConfig>,

    /// CHECK: brand-new mpl-core Collection keypair, `init`-equivalent via the
    /// Core CPI itself, same pattern as `asset` in `mint_win_nft`.
    #[account(mut)]
    pub collection: Signer<'info>,

    /// CHECK: pure-signing PDA, never holds data. NOT the collection's
    /// `update_authority` (that's `admin`, a real wallet -- see the handler)
    /// -- instead added as an `UpdateDelegate` additional delegate, scoped
    /// just to linking new assets into the collection, so `mint_win_nft()`
    /// can `invoke_signed` on the collection's behalf without admin needing
    /// to co-sign every future player-triggered mint.
    #[account(seeds = [COLLECTION_AUTHORITY_SEED], bump)]
    pub collection_authority: UncheckedAccount<'info>,

    /// CHECK: validated by address against the well-known mpl-core program id.
    #[account(address = mpl_core::ID)]
    pub mpl_core_program: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub(crate) fn handler(ctx: Context<InitNftCollection>, name: String, uri: String) -> Result<()> {
    require!(
        !name.is_empty() && name.len() <= MAX_COLLECTION_NAME_LEN,
        ErrorCode::InvalidCollectionName
    );
    require!(
        !uri.is_empty() && uri.len() <= MAX_COLLECTION_URI_LEN,
        ErrorCode::InvalidNftUri
    );

    let treasury = ctx.accounts.global_state.treasury;

    // Royalties on secondary sales, paid entirely to treasury. Authority is
    // `UpdateAuthority`, resolving to `admin` -- there is no instruction
    // anywhere in this program that can change it once set, so it is fixed
    // in practice even though it is not the stronger `None`. Admin (a real
    // wallet) legitimately CAN edit this later via a direct mpl-core call if
    // ever needed (e.g. adjusting the royalty split) -- unlike the mint path,
    // this is not a security-sensitive per-user-call surface.
    let royalties_plugin = PluginAuthorityPair {
        plugin: Plugin::Royalties(Royalties {
            basis_points: NFT_ROYALTY_BASIS_POINTS,
            creators: vec![Creator { address: treasury, percentage: 100 }],
            rule_set: RuleSet::None,
        }),
        authority: Some(PluginAuthority::UpdateAuthority),
    };

    // Attribution only, never tied to royalty payout (that's `Royalties`
    // above, paid to `treasury`). `verified: false` here, NOT `true`: LiteSVM
    // testing against the real mpl-core program proved mpl-core rejects a
    // `verified: true` entry set this way at `CreateCollectionV1` time
    // ("Verified creators: Rejected", custom error 0x28) even when the
    // attested address (`admin`/`treasury`) is genuinely the transaction's
    // signer/payer -- collection creation is not the mechanism mpl-core uses
    // to prove a creator signature; that needs a separate, dedicated
    // verification call after the collection exists. Marking it unverified
    // is honest (it genuinely hasn't been cryptographically verified by
    // mpl-core yet) and never rejected; wiring up the real verify step is
    // tracked as a follow-up, not required for the collection/royalty/
    // immutability guarantees this instruction exists for.
    let verified_creators_plugin = PluginAuthorityPair {
        plugin: Plugin::VerifiedCreators(VerifiedCreators {
            signatures: vec![VerifiedCreatorsSignature { address: ctx.accounts.admin.key(), verified: false }],
        }),
        authority: Some(PluginAuthority::UpdateAuthority),
    };

    // Delegates ONLY the "link a new asset into this collection" capability to
    // the program-controlled `collection_authority` PDA -- the collection's
    // real `update_authority` (set below) is `admin`, a genuine wallet with a
    // real private key, specifically so the project can sign marketplace
    // ownership-verification flows (Tensor's Creator Portal, Magic Eden, etc.)
    // and edit the collection's own listing there. Without this delegate,
    // `mint_win_nft()` (called by an arbitrary winner, never admin) would have
    // no way to authorize linking their new asset into the collection.
    let update_delegate_plugin = PluginAuthorityPair {
        plugin: Plugin::UpdateDelegate(UpdateDelegate {
            additional_delegates: vec![ctx.accounts.collection_authority.key()],
        }),
        authority: Some(PluginAuthority::UpdateAuthority),
    };

    CreateCollectionV1CpiBuilder::new(&ctx.accounts.mpl_core_program.to_account_info())
        .collection(&ctx.accounts.collection.to_account_info())
        .update_authority(Some(&ctx.accounts.admin.to_account_info()))
        .payer(&ctx.accounts.admin.to_account_info())
        .system_program(&ctx.accounts.system_program.to_account_info())
        .name(name)
        .uri(uri)
        .plugins(vec![royalties_plugin, verified_creators_plugin, update_delegate_plugin])
        .invoke()?;

    let nft_collection_config = &mut ctx.accounts.nft_collection_config;
    nft_collection_config.collection = ctx.accounts.collection.key();
    nft_collection_config.collection_authority_bump = ctx.bumps.collection_authority;
    nft_collection_config.bump = ctx.bumps.nft_collection_config;

    emit!(NftCollectionInitializedEvent {
        collection: ctx.accounts.collection.key(),
        treasury,
        royalty_basis_points: NFT_ROYALTY_BASIS_POINTS,
    });

    Ok(())
}
