use anchor_lang::prelude::*;
use anchor_lang::system_program::System;
use mpl_core::instructions::CreateV1CpiBuilder;
use mpl_core::types::{Attribute, Attributes, ImmutableMetadata, Plugin, PluginAuthority, PluginAuthorityPair};

use crate::constants::{COLLECTION_AUTHORITY_SEED, MAX_NFT_URI_LEN, METADATA_SIGNER, NFT_COLLECTION_CONFIG_SEED};
use crate::error::ErrorCode;
use crate::instructions::events::WinNftMintedEvent;
use crate::state::{NftCollectionConfig, WinRecord};

#[derive(Accounts)]
pub struct MintWinNft<'info> {
    /// Must be the WINNER RECORDED ON `win_record`, not necessarily the
    /// current holder -- enforced against `win_record.winner` in the
    /// handler (a plain `require!`, since which record they're minting is
    /// caller-chosen, not derivable from `global_state` the way the current
    /// holder is elsewhere in this program). `mut`: pays for `asset`'s rent
    /// via the Core CPI below (`payer = caller`).
    #[account(mut)]
    pub caller: Signer<'info>,

    /// The specific win being minted. Anchor's `Account<'info, WinRecord>`
    /// deserialization already proves this was legitimately created by
    /// `settle()` (correct discriminator + owned by this program) -- no
    /// additional seeds/bump re-derivation needed here.
    #[account(mut)]
    pub win_record: Account<'info, WinRecord>,

    /// CHECK: brand-new mpl-core asset keypair, `init`-equivalent via the
    /// Core CPI itself (Core's `CreateV1` creates the account -- Anchor's
    /// own `init` is not used here since the account is owned by mpl-core's
    /// program, not this program).
    #[account(mut)]
    pub asset: Signer<'info>,

    /// The shared Win NFT collection -- constrained against the one-time
    /// `init_nft_collection()` record so a caller can never substitute a
    /// different collection here.
    #[account(
        seeds = [NFT_COLLECTION_CONFIG_SEED],
        bump = nft_collection_config.bump,
    )]
    pub nft_collection_config: Account<'info, NftCollectionConfig>,

    /// CHECK: the mpl-core Collection account itself, address-constrained
    /// against `nft_collection_config.collection`.
    #[account(mut, address = nft_collection_config.collection @ ErrorCode::InvalidNftCollection)]
    pub collection: UncheckedAccount<'info>,

    /// CHECK: pure-signing PDA, an `UpdateDelegate` additional delegate on
    /// the collection (not its literal `update_authority`, which is `admin`
    /// -- a real wallet, so marketplace ownership-verification flows can be
    /// signed for real; see `init_nft_collection.rs`). `invoke_signed` below
    /// authorizes linking this asset into the collection on the collection's
    /// behalf -- required because `caller` (an arbitrary winner) is never
    /// admin.
    #[account(seeds = [COLLECTION_AUTHORITY_SEED], bump = nft_collection_config.collection_authority_bump)]
    pub collection_authority: UncheckedAccount<'info>,

    /// CHECK: validated by address against the well-known mpl-core program id.
    #[account(address = mpl_core::ID)]
    pub mpl_core_program: UncheckedAccount<'info>,

    /// CHECK: the runtime Instructions sysvar, address-constrained so a
    /// caller can never substitute a fake sysvar-shaped account (see
    /// WIN_NFT_PAYMENT_SECURITY_PLAN.md §7). Used to introspect the
    /// instruction immediately preceding this one for the Ed25519
    /// metadata-signer attestation (Mechanism 2, §2.2 below).
    #[account(address = solana_instructions_sysvar::ID)]
    pub instructions_sysvar: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

/// Native `Ed25519Program` instruction data layout (single-signature,
/// same-instruction-embedded form -- the shape produced by both
/// `solana_sdk::ed25519_instruction::new_ed25519_instruction` and web3.js's
/// `Ed25519Program.createInstructionWithPublicKey`):
///
/// ```text
/// [0]      num_signatures (u8) -- must be exactly 1, this program only ever
///          expects a single metadata-signer attestation per mint.
/// [1]      padding (u8), unused
/// [2..16]  one Ed25519SignatureOffsets record (14 bytes, all u16 LE):
///            signature_offset, signature_instruction_index,
///            public_key_offset, public_key_instruction_index,
///            message_data_offset, message_data_size, message_instruction_index
/// [16..]   signature (64 bytes) || public_key (32 bytes) || message bytes,
///          referenced by the offsets above (each *_instruction_index must
///          be `u16::MAX`, meaning "this same instruction").
/// ```
///
/// Returns `(signer_pubkey, message_bytes)` on a well-formed single-signature
/// instruction; `None` on anything malformed or using the cross-instruction
/// form (which this program never expects and therefore treats as invalid).
fn parse_ed25519_instruction_data(data: &[u8]) -> Option<(Pubkey, &[u8])> {
    const HEADER_LEN: usize = 2;
    const OFFSETS_LEN: usize = 14;
    const SAME_INSTRUCTION: u16 = u16::MAX;

    if data.len() < HEADER_LEN + OFFSETS_LEN {
        return None;
    }
    let num_signatures = data[0];
    if num_signatures != 1 {
        return None;
    }

    let offsets = &data[HEADER_LEN..HEADER_LEN + OFFSETS_LEN];
    let read_u16 = |o: usize| u16::from_le_bytes([offsets[o], offsets[o + 1]]);

    let signature_instruction_index = read_u16(2);
    let public_key_offset = read_u16(4) as usize;
    let public_key_instruction_index = read_u16(6);
    let message_data_offset = read_u16(8) as usize;
    let message_data_size = read_u16(10) as usize;
    let message_instruction_index = read_u16(12);

    if signature_instruction_index != SAME_INSTRUCTION
        || public_key_instruction_index != SAME_INSTRUCTION
        || message_instruction_index != SAME_INSTRUCTION
    {
        return None;
    }

    let public_key_end = public_key_offset.checked_add(32)?;
    let message_end = message_data_offset.checked_add(message_data_size)?;
    if public_key_end > data.len() || message_end > data.len() {
        return None;
    }

    let pubkey_bytes: [u8; 32] = data[public_key_offset..public_key_end].try_into().ok()?;
    let signer_pubkey = Pubkey::new_from_array(pubkey_bytes);
    let message = &data[message_data_offset..message_end];

    Some((signer_pubkey, message))
}

/// Mechanism 2 (WIN_NFT_PAYMENT_SECURITY_PLAN.md §2.2/§7): proves the
/// transaction carries a genuine `METADATA_SIGNER` attestation over exactly
/// `content_hash`, positioned as the instruction *immediately* preceding
/// this one -- not merely present somewhere in the transaction, which would
/// let a stale-but-validly-signed attestation from an unrelated prior mint
/// be replayed. The native `Ed25519Program` has already performed the actual
/// cryptographic signature verification by the time this instruction runs
/// (a failed verification aborts the whole transaction before it gets here);
/// this only needs to check *which* instruction it was, *who* signed it, and
/// *what* it signed.
fn verify_metadata_signature(
    instructions_sysvar: &UncheckedAccount,
    content_hash: &[u8; 32],
) -> Result<()> {
    let ix_sysvar_info = instructions_sysvar.to_account_info();

    let current_index = solana_instructions_sysvar::load_current_index_checked(&ix_sysvar_info)
        .map_err(|_| error!(ErrorCode::InvalidMetadataSignature))?;

    // Must have a preceding instruction at all -- `mint_win_nft` can never
    // legitimately be the very first instruction in a valid transaction.
    require!(current_index > 0, ErrorCode::InvalidMetadataSignature);

    let preceding = solana_instructions_sysvar::load_instruction_at_checked(
        (current_index - 1) as usize,
        &ix_sysvar_info,
    )
    .map_err(|_| error!(ErrorCode::InvalidMetadataSignature))?;

    require_keys_eq!(
        preceding.program_id,
        solana_sdk_ids::ed25519_program::ID,
        ErrorCode::InvalidMetadataSignature
    );

    let (signer_pubkey, message) =
        parse_ed25519_instruction_data(&preceding.data).ok_or(error!(ErrorCode::InvalidMetadataSignature))?;

    require_keys_eq!(signer_pubkey, METADATA_SIGNER, ErrorCode::InvalidMetadataSignature);
    require!(message == content_hash.as_slice(), ErrorCode::InvalidMetadataSignature);

    Ok(())
}

fn to_hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub(crate) fn handler(ctx: Context<MintWinNft>, uri: String, content_hash: [u8; 32]) -> Result<()> {
    let win_record = &mut ctx.accounts.win_record;

    require!(win_record.winner == ctx.accounts.caller.key(), ErrorCode::NotWinRecordOwner);
    require!(!win_record.minted, ErrorCode::WinNftAlreadyMinted);
    require!(
        !uri.is_empty() && uri.len() <= MAX_NFT_URI_LEN,
        ErrorCode::InvalidNftUri
    );
    verify_metadata_signature(&ctx.accounts.instructions_sysvar, &content_hash)?;

    // Snapshot-once, immutable -- but via two targeted, mpl-core-enforced
    // plugin-level locks instead of nulling the whole asset's
    // `update_authority`, because this asset is a Collection member (its
    // `update_authority` is `Collection(collection_authority)`, mutually
    // exclusive with `None` -- collection membership IS the update-authority
    // mechanism in mpl-core, not a separate field). The two locks:
    //  1. The `Attributes` plugin's OWN authority is `PluginAuthority::None`,
    //     not `UpdateAuthority` -- so the actual win data below is frozen
    //     regardless of who controls the collection's authority.
    //  2. `ImmutableMetadata` freezes `name`/`uri` too ("cannot be removed
    //     after addition", per mpl-core's docs) -- so which JSON metadata
    //     file this asset points to, and its display name, are equally
    //     permanent. Together these cover every field that actually carries
    //     meaning; only entirely-new future plugins could theoretically be
    //     added by the collection authority, which -- like every other
    //     capability in this program -- depends on this program's own code
    //     never doing that, the same trust boundary every instruction here
    //     already has until upgrade authority is eventually revoked.
    let name = format!("TOGGLD Win #{}", win_record.holder_count);

    // Mechanism 1 (§2.1): the NFT's ground-truth facts, sourced directly
    // from the already-deserialized, program-verified `win_record` -- never
    // from client-supplied values -- so a client can never forge the
    // winner/holder#/price/timestamp a viewer sees on-chain.
    let metadata_hash_hex = to_hex(&content_hash);
    let attributes_plugin = PluginAuthorityPair {
        plugin: Plugin::Attributes(Attributes {
            attribute_list: vec![
                Attribute { key: "winner".into(), value: win_record.winner.to_string() },
                Attribute { key: "holder_count".into(), value: win_record.holder_count.to_string() },
                Attribute { key: "price_paid".into(), value: win_record.price_paid.to_string() },
                Attribute { key: "won_at".into(), value: win_record.won_at.to_string() },
                Attribute { key: "metadata_hash".into(), value: metadata_hash_hex },
            ],
        }),
        authority: Some(PluginAuthority::None),
    };
    let immutable_metadata_plugin = PluginAuthorityPair {
        plugin: Plugin::ImmutableMetadata(ImmutableMetadata {}),
        authority: Some(PluginAuthority::UpdateAuthority),
    };

    let collection_authority_bump = ctx.accounts.nft_collection_config.collection_authority_bump;
    let collection_authority_seeds: &[&[u8]] =
        &[COLLECTION_AUTHORITY_SEED, &[collection_authority_bump]];
    let signer_seeds: &[&[&[u8]]] = &[collection_authority_seeds];

    CreateV1CpiBuilder::new(&ctx.accounts.mpl_core_program.to_account_info())
        .asset(&ctx.accounts.asset.to_account_info())
        .collection(Some(&ctx.accounts.collection.to_account_info()))
        .authority(Some(&ctx.accounts.collection_authority.to_account_info()))
        .payer(&ctx.accounts.caller.to_account_info())
        .owner(Some(&ctx.accounts.caller.to_account_info()))
        .update_authority(None)
        .system_program(&ctx.accounts.system_program.to_account_info())
        .name(name)
        .uri(uri.clone())
        .plugins(vec![attributes_plugin, immutable_metadata_plugin])
        .invoke_signed(signer_seeds)?;

    win_record.minted = true;

    emit!(WinNftMintedEvent {
        winner: ctx.accounts.caller.key(),
        asset: ctx.accounts.asset.key(),
        holder_count: win_record.holder_count,
        price_paid: win_record.price_paid,
        won_at: win_record.won_at,
        minted_at: Clock::get()?.unix_timestamp,
        uri,
    });

    Ok(())
}
