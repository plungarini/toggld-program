use anchor_lang::system_program::{self, CreateAccount, System, Transfer};
use anchor_lang::prelude::*;

use crate::constants::*;
use crate::error::ErrorCode;
use crate::instructions::events::SettleEvent;
use crate::pure::compute_split;
use crate::state::{GlobalState, WinRecord};

#[derive(Accounts)]
pub struct Settle<'info> {
    /// Permissionless: anyone can trigger settlement once the window has
    /// closed. `mut`: on a flip, this account funds the newly-created
    /// `WinRecord`'s rent-exempt reserve (see `win_record` below) -- a
    /// no-op cost on a defend, where nothing is created.
    #[account(mut)]
    pub caller: Signer<'info>,

    #[account(mut, seeds = [GLOBAL_STATE_SEED], bump)]
    pub global_state: Account<'info, GlobalState>,

    /// CHECK: plain System-Program-owned vault PDA; validated by seeds/bump.
    #[account(mut, seeds = [VAULT_SEED], bump = global_state.vault_bump)]
    pub vault: UncheckedAccount<'info>,

    /// CHECK: must equal `global_state.burn_address` — enforced below so the
    /// burn destination can never be substituted by the caller.
    #[account(mut, address = global_state.burn_address @ ErrorCode::InvalidBurnAddress)]
    pub burn_address: UncheckedAccount<'info>,

    /// CHECK: `WinRecord` PDA for this settle's pre-increment
    /// `global_state.holder_count` ordinal. Must be derived and passed on
    /// EVERY `settle()` call (flip or defend) -- the ordinal is only knowable
    /// from on-chain state at call time, and Anchor's `seeds`/`bump`
    /// constraint here just validates the supplied address matches the
    /// derived PDA, without requiring the account to already exist (same
    /// pattern as `vault`/`burn_address` above and `initialize.rs`'s own
    /// `vault`). The handler below only actually creates and populates this
    /// account when the settlement flips the holder; on a defend it is
    /// never written to and no rent is spent. Manually created via a
    /// `system_program::create_account` CPI (not Anchor's `init`/
    /// `init_if_needed`), since whether this account gets created at all
    /// depends on the runtime `flipped` condition, which the account macros
    /// can't express.
    #[account(mut, seeds = [WIN_RECORD_SEED, &global_state.holder_count.to_le_bytes()], bump)]
    pub win_record: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub(crate) fn handler(ctx: Context<Settle>) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;

    let (
        winner,
        winning_price,
        previous_holder,
        flipped,
        fee_amount,
        burn_amount,
        vault_bump,
        pre_increment_holder_count,
        post_increment_holder_count,
    );

    {
        let global_state = &mut ctx.accounts.global_state;

        require!(global_state.window_active, ErrorCode::NoActiveWindow);
        require!(now >= global_state.window_end_ts, ErrorCode::WindowNotClosed);

        winner = global_state.top_bidder;
        winning_price = global_state.top_bid_amount;
        previous_holder = global_state.holder;
        flipped = winner != global_state.holder;
        pre_increment_holder_count = global_state.holder_count;

        if flipped {
            global_state.holder = winner;
            global_state.is_on = !global_state.is_on;
            global_state.holder_since = now;
            global_state.holder_count = global_state
                .holder_count
                .checked_add(1)
                .ok_or(ErrorCode::MathOverflow)?;
        }
        // A successful defense (`!flipped`) leaves `holder_since` /
        // `holder_count` untouched — it continues the same holding streak
        // rather than starting a new one.
        post_increment_holder_count = global_state.holder_count;

        global_state.current_price = winning_price;

        let (computed_fee_amount, computed_burn_amount) =
            compute_split(winning_price, global_state.fee_bps)?;
        fee_amount = computed_fee_amount;
        burn_amount = computed_burn_amount;

        global_state.escrowed_amount = global_state
            .escrowed_amount
            .checked_sub(winning_price)
            .ok_or(ErrorCode::MathOverflow)?;
        global_state.treasury_balance = global_state
            .treasury_balance
            .checked_add(fee_amount)
            .ok_or(ErrorCode::MathOverflow)?;

        vault_bump = global_state.vault_bump;

        global_state.window_active = false;
        global_state.window_end_ts = 0;
        global_state.top_bidder = Pubkey::default();
        global_state.top_bid_amount = 0;
        global_state.total_challenges = global_state
            .total_challenges
            .checked_add(1)
            .ok_or(ErrorCode::MathOverflow)?;
    }

    let vault_seeds: &[&[u8]] = &[VAULT_SEED, &[vault_bump]];
    let signer_seeds: &[&[&[u8]]] = &[vault_seeds];

    system_program::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.key(),
            Transfer {
                from: ctx.accounts.vault.to_account_info(),
                to: ctx.accounts.burn_address.to_account_info(),
            },
            signer_seeds,
        ),
        burn_amount,
    )?;

    if flipped {
        // Seeded by the PRE-increment ordinal (the value `holder_count` held
        // before this settlement's increment above) — see `WinRecord`'s doc
        // comment in `state.rs`.
        let win_record_bump = ctx.bumps.win_record;
        let win_record_ordinal_bytes = pre_increment_holder_count.to_le_bytes();
        let win_record_seeds: &[&[u8]] =
            &[WIN_RECORD_SEED, &win_record_ordinal_bytes, &[win_record_bump]];
        let win_record_signer_seeds: &[&[&[u8]]] = &[win_record_seeds];

        system_program::create_account(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.key(),
                CreateAccount {
                    from: ctx.accounts.caller.to_account_info(),
                    to: ctx.accounts.win_record.to_account_info(),
                },
                win_record_signer_seeds,
            ),
            Rent::get()?.minimum_balance(WinRecord::SPACE),
            WinRecord::SPACE as u64,
            &crate::ID,
        )?;

        let win_record_data = WinRecord {
            winner,
            holder_count: post_increment_holder_count,
            price_paid: winning_price,
            won_at: now,
            minted: false,
            bump: win_record_bump,
        };

        let mut data = ctx.accounts.win_record.try_borrow_mut_data()?;
        let mut writer: &mut [u8] = &mut data;
        win_record_data.try_serialize(&mut writer)?;
    }

    emit!(SettleEvent {
        winner,
        previous_holder,
        flipped,
        winning_price,
        treasury_cut: fee_amount,
        burned_amount: burn_amount,
    });

    Ok(())
}
