use anchor_lang::prelude::*;
use anchor_lang::system_program::{self, CreateAccount, System};

use crate::constants::*;
use crate::error::ErrorCode;
use crate::state::{GlobalState, WinRecord};

/// 8-byte Anchor discriminator + the exact byte size of every `GlobalState`
/// field, in declaration order:
/// holder(32) + holder_since(8) + current_price(8) + is_on(1) + total_challenges(8)
/// + holder_count(8)
/// + treasury(32) + burn_address(32) + fee_bps(2) + admin(32) + params_locked(1)
/// + min_raise_bps(2) + base_window_secs(4) + genesis_price(8)
/// + window_active(1) + window_end_ts(8) + top_bidder(32) + top_bid_amount(8)
/// + escrowed_amount(8) + treasury_balance(8) + vault_bump(1) = 244
pub(crate) const GLOBAL_STATE_SPACE: usize = 8 + 244;

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init,
        payer = payer,
        space = GLOBAL_STATE_SPACE,
        seeds = [GLOBAL_STATE_SEED],
        bump,
    )]
    pub global_state: Account<'info, GlobalState>,

    /// CHECK: not yet created on-chain; created in the handler below via a
    /// `system_program::create_account` CPI signed with this PDA's own seeds,
    /// funded with exactly the rent-exempt minimum for a 0-byte account so it
    /// stays a plain System-Program-owned account (never owned by `toggld`).
    #[account(mut, seeds = [VAULT_SEED], bump)]
    pub vault: UncheckedAccount<'info>,

    /// CHECK: the genesis holder's `WinRecord` -- not yet created on-chain;
    /// created in the handler below via the exact same manual
    /// `system_program::create_account` CPI pattern `settle()` uses for a
    /// flip's `WinRecord` (see that file), NOT Anchor's `init`/
    /// `init_if_needed`, for consistency with `vault` above and because this
    /// account list is otherwise deliberately built entirely from manually
    /// -created PDAs. Seeded by the reserved ordinal `0` -- see the handler
    /// below for why `0` can never collide with a real flip's `WinRecord`
    /// seed ordinal (always `>= 1`). Funded by `payer`, same signer that
    /// already funds `vault`'s creation just above.
    #[account(mut, seeds = [WIN_RECORD_SEED, &0u64.to_le_bytes()], bump)]
    pub win_record: UncheckedAccount<'info>,

    /// This program's own executable account. `programdata_address()` reads
    /// its on-chain data and returns `Some(program_data.key())` only when
    /// `program` is owned by `BPFLoaderUpgradeable` and its `Program` variant
    /// points at exactly the `program_data` account supplied below -- so this
    /// constraint also rejects a non-upgradeable deployment outright, since a
    /// non-upgradeable program's `programdata_address()` is `None`.
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ ErrorCode::Unauthorized)]
    pub program: Program<'info, crate::program::Toggld>,

    /// The `BPFLoaderUpgradeable` `ProgramData` account for this program.
    /// Gating `initialize()` on `upgrade_authority_address == payer` -- read
    /// at runtime, never a hardcoded pubkey -- means only whoever currently
    /// holds this program's upgrade authority can ever call `initialize()`,
    /// closing the front-running window where any signer's transaction could
    /// land first and permanently become admin/treasury. This stays correct
    /// across a legitimate authority rotation and is identical on devnet and
    /// mainnet.
    #[account(constraint = program_data.upgrade_authority_address == Some(payer.key()) @ ErrorCode::Unauthorized)]
    pub program_data: Account<'info, ProgramData>,

    pub system_program: Program<'info, System>,
}

pub(crate) fn handler(
    ctx: Context<Initialize>,
    treasury: Pubkey,
    admin: Pubkey,
    genesis_price: u64,
) -> Result<()> {
    require!(genesis_price > 0, ErrorCode::InvalidGenesisPrice);
    require!(treasury != Pubkey::default(), ErrorCode::InvalidTreasury);
    require!(admin != Pubkey::default(), ErrorCode::InvalidAdmin);

    let vault_bump = ctx.bumps.vault;
    let vault_seeds: &[&[u8]] = &[VAULT_SEED, &[vault_bump]];
    let signer_seeds: &[&[&[u8]]] = &[vault_seeds];

    let rent_exempt_reserve = Rent::get()?.minimum_balance(0);

    system_program::create_account(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.key(),
            CreateAccount {
                from: ctx.accounts.payer.to_account_info(),
                to: ctx.accounts.vault.to_account_info(),
            },
            signer_seeds,
        ),
        rent_exempt_reserve,
        0,
        &system_program::ID,
    )?;

    let now = Clock::get()?.unix_timestamp;
    let global_state = &mut ctx.accounts.global_state;

    // Genesis holder defaults to the treasury address, per the build plan.
    global_state.holder = treasury;
    global_state.holder_since = now;
    global_state.current_price = genesis_price;
    global_state.is_on = false;
    global_state.total_challenges = 0;
    // Genesis holder counts as holder #1 -- the first FLIP (to holder #2)
    // increments this, per `state::GlobalState::holder_count`'s doc comment.
    global_state.holder_count = 1;

    global_state.treasury = treasury;
    // Never instruction arguments: the burn address and fee split are
    // hardcoded from the immutable program constants so no caller, including
    // the deployer, can ever pick a different split or burn target.
    global_state.burn_address = INCINERATOR;
    global_state.fee_bps = FEE_BPS;
    global_state.admin = admin;
    global_state.params_locked = false;

    global_state.min_raise_bps = DEFAULT_MIN_RAISE_BPS;
    global_state.base_window_secs = DEFAULT_BASE_WINDOW_SECS;
    global_state.genesis_price = genesis_price;

    global_state.window_active = false;
    global_state.window_end_ts = 0;
    global_state.top_bidder = Pubkey::default();
    global_state.top_bid_amount = 0;

    global_state.escrowed_amount = 0;
    global_state.treasury_balance = 0;

    global_state.vault_bump = vault_bump;

    // --- Genesis Win NFT eligibility ---------------------------------------
    // Holder #1 (the genesis/treasury holder) never goes through `settle()`
    // -- unlike every later holder, they didn't win an auction, so without
    // this they could never mint a Win NFT for the win that seeded the whole
    // game. This creates their `WinRecord` here, mirroring `settle()`'s flip
    // path exactly (same manual `system_program::create_account` CPI +
    // direct field writes, same `WinRecord::SPACE`), so `mint_win_nft` needs
    // zero special-casing to handle it -- it's just another `Account<'info,
    // WinRecord>` with the correct discriminator and program owner.
    //
    // Seed ordinal `0`: `settle()` always seeds a flip's `WinRecord` by the
    // PRE-increment `global_state.holder_count` ordinal, which is always
    // `>= 1` -- `holder_count` is set to `1` directly above and only ever
    // incremented from there (never decremented, never reset), so no real
    // flip's pre-increment ordinal can ever be `0`. That makes `0` a
    // permanently-reserved ordinal for exactly this one record, with no
    // collision risk against any flip's `WinRecord` PDA, ever -- and it's
    // derivable by any client with zero on-chain reads beyond knowing "this
    // is the genesis record".
    let win_record_bump = ctx.bumps.win_record;
    let win_record_seeds: &[&[u8]] = &[WIN_RECORD_SEED, &0u64.to_le_bytes(), &[win_record_bump]];
    let win_record_signer_seeds: &[&[&[u8]]] = &[win_record_seeds];

    system_program::create_account(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.key(),
            CreateAccount {
                from: ctx.accounts.payer.to_account_info(),
                to: ctx.accounts.win_record.to_account_info(),
            },
            win_record_signer_seeds,
        ),
        Rent::get()?.minimum_balance(WinRecord::SPACE),
        WinRecord::SPACE as u64,
        &crate::ID,
    )?;

    let win_record_data = WinRecord {
        winner: treasury,
        // Genesis holder counts as holder #1 -- matches `global_state.holder_count` above.
        holder_count: 1,
        // No auction ever happened for the genesis holder -- `initialize()`
        // assigns `global_state.holder = treasury` directly, with no bid to
        // record. `0` honestly reflects "no purchase occurred"; using
        // `genesis_price` here would misrepresent an unpaid assignment as a
        // real winning bid.
        price_paid: 0,
        won_at: now,
        minted: false,
        bump: win_record_bump,
    };

    let mut win_record_bytes = ctx.accounts.win_record.try_borrow_mut_data()?;
    let mut writer: &mut [u8] = &mut win_record_bytes;
    win_record_data.try_serialize(&mut writer)?;

    Ok(())
}
