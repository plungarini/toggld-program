//! Phase 1 LiteSVM integration tests for the TOGGLD core challenge/defend contract.
//!
//! Every test drives the real compiled `.so` (LiteSVM, in-process, no devnet dependency).
//! Time-based logic (window expiry, anti-snipe boundary) is exercised by directly
//! overwriting the `Clock` sysvar via `LiteSVM::set_sysvar`, giving each test full,
//! deterministic control over `now` rather than relying on wall-clock elapsed time.

use {
    anchor_lang::{
        prelude::Pubkey,
        solana_program::{
            bpf_loader_upgradeable, bpf_loader_upgradeable::UpgradeableLoaderState,
            instruction::Instruction,
        },
        AccountDeserialize, AccountSerialize, InstructionData, ToAccountMetas,
    },
    ed25519_dalek::{Signer as DalekSigner, SigningKey},
    litesvm::LiteSVM,
    solana_account::Account as SvmAccount,
    solana_clock::Clock as SolanaClock,
    solana_keypair::Keypair,
    solana_message::{Message, VersionedMessage},
    solana_signer::Signer,
    solana_transaction::versioned::VersionedTransaction,
    litesvm::types::TransactionResult,
    toggld::{
        constants::{
            BURN_VAULT_SEED, DEFAULT_BASE_WINDOW_SECS, DEFAULT_MIN_RAISE_BPS, FEE_BPS, GLOBAL_STATE_SEED, INCINERATOR,
            MAX_NFT_URI_LEN, MAX_SLIPPAGE_BPS_CEILING,
            METADATA_SIGNER, MIN_SWEEP_LAMPORTS, REFUND_SEED, TEAM_VESTING_SEED, TOKEN_CONFIG_SEED,
            TOTAL_TOKEN_SUPPLY, VAULT_SEED, WIN_RECORD_SEED, WSOL_MINT,
        },
        dbc_cpi::DBC_PROGRAM_ID,
        state::{GlobalState, PendingRefund, TeamVesting, TokenConfig, WinRecord},
    },
};

// ---------------------------------------------------------------------------
// Generic setup / plumbing
// ---------------------------------------------------------------------------

fn system_program_id() -> Pubkey {
    anchor_lang::system_program::ID
}

/// Derives the `BPFLoaderUpgradeable` `ProgramData` PDA for `program_id` -
/// shared by the test harness (to rewrite the upgrade authority) and every
/// `ix_initialize` call (to pass the correct account).
fn programdata_address(program_id: Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[program_id.as_ref()], &bpf_loader_upgradeable::ID).0
}

/// `LiteSVM::add_program` always deploys under `BPFLoaderUpgradeable` with
/// `upgrade_authority_address: None` (see the crate's `add_program_internal`).
/// `initialize()` now gates its caller to the program's real upgrade
/// authority, so every test needs a known authority wired into that
/// `ProgramData` account. This overwrites just the fixed-size metadata header
/// (`UpgradeableLoaderState::size_of_programdata_metadata()` is a constant
/// 45 bytes regardless of variant) in place, leaving the trailing program
/// bytes untouched and the account's total size unchanged.
fn set_upgrade_authority(svm: &mut LiteSVM, program_id: Pubkey, authority: Pubkey) {
    let program_data = programdata_address(program_id);
    let mut account = svm
        .get_account(&program_data)
        .expect("programdata account should exist after add_program");

    let header = bincode::serialize(&UpgradeableLoaderState::ProgramData {
        slot: 0,
        upgrade_authority_address: Some(authority),
    })
    .expect("ProgramData header should serialize");
    let metadata_len = UpgradeableLoaderState::size_of_programdata_metadata();
    assert!(
        header.len() <= metadata_len,
        "serialized ProgramData header ({}) must fit within the metadata region ({metadata_len})",
        header.len()
    );
    account.data[..header.len()].copy_from_slice(&header);

    svm.set_account(program_data, account)
        .expect("set_account should succeed");
}

/// Fresh LiteSVM instance with the compiled program loaded, plus the derived
/// `GlobalState` / `Vault` PDAs for that instance's program id and a funded
/// keypair wired up as the program's upgrade authority (see
/// `set_upgrade_authority`) - the only signer `initialize()` will now accept.
fn new_svm() -> (LiteSVM, Pubkey, Pubkey, Keypair) {
    let program_id = toggld::id();
    let mut svm = LiteSVM::new();
    let bytes = include_bytes!("../target/deploy/toggld.so");
    svm.add_program(program_id, bytes).unwrap();

    // Real Metaplex Core program bytecode (dumped from devnet -- see
    // `tests/fixtures/mpl_core.so`), loaded so `mint_win_nft`'s `CreateV1`
    // CPI can actually execute end-to-end in these tests, not just be
    // reasoned about. This is deliberately the real deployed program, not a
    // hand-rolled mock, since the whole point of Phase R3's mint tests is
    // proving the CPI itself succeeds and produces a real Core asset.
    let mpl_core_bytes = include_bytes!("fixtures/mpl_core.so");
    svm.add_program(mpl_core::ID, mpl_core_bytes).unwrap();

    let (global_state, _) = Pubkey::find_program_address(&[GLOBAL_STATE_SEED], &program_id);
    let (vault, _) = Pubkey::find_program_address(&[VAULT_SEED], &program_id);

    let authority = new_funded_keypair(&mut svm, 10_000_000_000);
    set_upgrade_authority(&mut svm, program_id, authority.pubkey());

    (svm, global_state, vault, authority)
}

fn new_funded_keypair(svm: &mut LiteSVM, lamports: u64) -> Keypair {
    let kp = Keypair::new();
    svm.airdrop(&kp.pubkey(), lamports).unwrap();
    kp
}

/// Sends a single-instruction transaction signed and fee-paid by `signer`.
/// Every instruction in this program needs exactly one signer, so this covers
/// all of them.
// TransactionResult's Err variant size is dictated by litesvm, not this crate; boxing it here would ripple into every call site for no test-quality benefit.
#[allow(clippy::result_large_err)]
fn send(svm: &mut LiteSVM, signer: &Keypair, ix: Instruction) -> TransactionResult {
    // Two structurally identical instructions (same signer, same accounts, same
    // args - e.g. back-to-back `settle()` calls with no arguments) would
    // otherwise produce byte-identical messages/signatures and collide as
    // `AlreadyProcessed`, masking the real on-chain error. Force a fresh
    // blockhash on every send so each transaction is unique.
    svm.expire_blockhash();
    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(&[ix], Some(&signer.pubkey()), &blockhash);
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), &[signer]).unwrap();
    svm.send_transaction(tx)
}

/// Like `send`, but for instructions needing more than one signer (e.g.
/// `claim_refund()` when the claimant is not the transaction's fee payer -
/// a claimant whose wallet was reassigned away from the System Program can
/// no longer pay a fee itself, but can still sign to authorize the claim).
#[allow(clippy::result_large_err)]
fn send_with_signers(
    svm: &mut LiteSVM,
    fee_payer: &Keypair,
    signers: &[&Keypair],
    ix: Instruction,
) -> TransactionResult {
    svm.expire_blockhash();
    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(&[ix], Some(&fee_payer.pubkey()), &blockhash);
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), signers).unwrap();
    svm.send_transaction(tx)
}

/// Like `send_with_signers`, but for a multi-instruction transaction (e.g.
/// the atomic `settle()` + Ed25519 attestation + `mint_win_nft()` happy path,
/// or a standalone Ed25519 attestation + `mint_win_nft()` pair).
#[allow(clippy::result_large_err)]
fn send_multi(svm: &mut LiteSVM, fee_payer: &Keypair, signers: &[&Keypair], ixs: &[Instruction]) -> TransactionResult {
    svm.expire_blockhash();
    let blockhash = svm.latest_blockhash();
    let msg = Message::new_with_blockhash(ixs, Some(&fee_payer.pubkey()), &blockhash);
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), signers).unwrap();
    svm.send_transaction(tx)
}

fn set_clock_ts(svm: &mut LiteSVM, unix_timestamp: i64) {
    let mut clock: SolanaClock = svm.get_sysvar();
    clock.unix_timestamp = unix_timestamp;
    svm.set_sysvar(&clock);
}

fn get_global_state(svm: &LiteSVM, global_state: Pubkey) -> GlobalState {
    let account = svm
        .get_account(&global_state)
        .expect("global_state account should exist");
    GlobalState::try_deserialize(&mut account.data.as_slice())
        .expect("GlobalState should deserialize")
}

/// Returns `None` when the account doesn't exist yet or fails to
/// deserialize as a `PendingRefund` (e.g. already closed by a prior claim) -
/// both cases mean "nothing pending for this address" from the caller's
/// point of view.
fn get_pending_refund(svm: &LiteSVM, pubkey: Pubkey) -> Option<PendingRefund> {
    let account = svm.get_account(&pubkey)?;
    PendingRefund::try_deserialize(&mut account.data.as_slice()).ok()
}

/// The cheapest way to catch a lamport-accounting bug anywhere: the vault's
/// balance above its rent-exempt reserve must always equal exactly the sum of
/// escrowed bid funds and undrawn treasury balance.
fn assert_vault_invariant(svm: &LiteSVM, vault: Pubkey, gs: &GlobalState) {
    let vault_lamports = svm.get_balance(&vault).expect("vault account should exist");
    let reserve = svm.minimum_balance_for_rent_exemption(0);
    assert_eq!(
        vault_lamports - reserve,
        gs.escrowed_amount + gs.treasury_balance,
        "vault invariant violated: vault={vault_lamports}, reserve={reserve}, escrowed={}, treasury={}",
        gs.escrowed_amount,
        gs.treasury_balance
    );
}

/// Ceiling-exact minimum raise for a given base and bps, matching the
/// `require_min_raise` check in `challenge.rs`: the smallest `bid` satisfying
/// `bid * 10000 >= base * (10000 + bps)`.
fn min_raise_amount(base: u64, bps: u16) -> u64 {
    let required = (base as u128) * (10_000u128 + bps as u128);
    required.div_ceil(10_000) as u64
}

/// Simple deterministic 64-bit LCG (Numerical Recipes constants) - not a real
/// PRNG crate dependency, just enough to drive a fixed, reproducible sequence
/// of pseudo-random choices across a fuzz-lite test.
fn lcg_next(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    *state
}

/// Asserts a transaction failed and that its logs mention the given Anchor
/// `ErrorCode` variant name.
fn assert_err_contains(res: &TransactionResult, code_name: &str) {
    match res {
        Ok(meta) => panic!("expected error {code_name}, but transaction succeeded: {meta:?}"),
        Err(failed) => {
            let found = failed.meta.logs.iter().any(|l| l.contains(code_name));
            assert!(
                found,
                "expected logs to contain {code_name:?}, got: {:#?}",
                failed.meta.logs
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Instruction builders
// ---------------------------------------------------------------------------

fn ix_initialize(
    global_state: Pubkey,
    vault: Pubkey,
    payer: Pubkey,
    treasury: Pubkey,
    admin: Pubkey,
    genesis_price: u64,
) -> Instruction {
    let program_id = toggld::id();
    Instruction::new_with_bytes(
        program_id,
        &toggld::instruction::Initialize {
            treasury,
            admin,
            genesis_price,
        }
        .data(),
        toggld::accounts::Initialize {
            payer,
            global_state,
            vault,
            win_record: genesis_win_record_pda(),
            program: program_id,
            program_data: programdata_address(program_id),
            system_program: system_program_id(),
        }
        .to_account_metas(None),
    )
}

/// Derives the genesis holder's `WinRecord` PDA -- seeded by the reserved
/// ordinal `0`, created by `initialize()` itself (never `settle()`). See
/// `state::WinRecord` / `initialize.rs`'s handler for why `0` can never
/// collide with a real flip's `WinRecord` seed ordinal (always `>= 1`).
fn genesis_win_record_pda() -> Pubkey {
    win_record_pda(0)
}

/// Derives a bidder's `PendingRefund` PDA - the account `challenge()` pays
/// an outbid bidder's refund into, and the account `claim_refund()` pays it
/// back out of. Seeded by the bidder's own pubkey, never by anything they
/// control the ownership of.
fn pending_refund_pda(bidder: Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[REFUND_SEED, bidder.as_ref()], &toggld::id()).0
}

/// `previous_top_bidder` must be the *actual current* `global_state.top_bidder`
/// (or `Pubkey::default()` on a cold open) - it derives the `pending_refund`
/// PDA address the on-chain seeds constraint checks against, so passing a
/// stale or fabricated value here fails validation on-chain, not silently.
///
/// Mirrors what a well-behaved client does: on a cold open
/// (`previous_top_bidder == Pubkey::default()`) there is no previous bidder
/// to refund, so `pending_refund` is omitted entirely (`None`, which Anchor's
/// generated client encodes as the System Program id sentinel) rather than
/// pointing at the "null-bidder" PDA -- see `test_cold_open_omits_pending_refund_account`
/// and `test_cold_open_rejects_supplied_pending_refund_account` for the
/// on-chain behavior this depends on.
fn ix_challenge(
    global_state: Pubkey,
    vault: Pubkey,
    challenger: Pubkey,
    previous_top_bidder: Pubkey,
    bid_amount: u64,
) -> Instruction {
    Instruction::new_with_bytes(
        toggld::id(),
        &toggld::instruction::Challenge { bid_amount }.data(),
        toggld::accounts::Challenge {
            challenger,
            global_state,
            vault,
            pending_refund: if previous_top_bidder == Pubkey::default() {
                None
            } else {
                Some(pending_refund_pda(previous_top_bidder))
            },
            system_program: system_program_id(),
        }
        .to_account_metas(None),
    )
}

/// Like `ix_challenge`, but always passes an explicit `pending_refund`
/// account (never `None`) regardless of `previous_top_bidder` - used to
/// exercise a client that (mistakenly, or adversarially) supplies a real
/// account on a cold open, which the contract must now reject outright.
fn ix_challenge_with_explicit_pending_refund(
    global_state: Pubkey,
    vault: Pubkey,
    challenger: Pubkey,
    pending_refund: Pubkey,
    bid_amount: u64,
) -> Instruction {
    Instruction::new_with_bytes(
        toggld::id(),
        &toggld::instruction::Challenge { bid_amount }.data(),
        toggld::accounts::Challenge {
            challenger,
            global_state,
            vault,
            pending_refund: Some(pending_refund),
            system_program: system_program_id(),
        }
        .to_account_metas(None),
    )
}

fn ix_claim_refund(claimant: Pubkey) -> Instruction {
    Instruction::new_with_bytes(
        toggld::id(),
        &toggld::instruction::ClaimRefund {}.data(),
        toggld::accounts::ClaimRefund {
            claimant,
            pending_refund: pending_refund_pda(claimant),
        }
        .to_account_metas(None),
    )
}

/// `win_record` must be `win_record_pda(gs.holder_count)` for the CURRENT
/// on-chain `global_state` (a well-behaved client always re-reads
/// `global_state` immediately before building a `settle()` transaction) --
/// every call site passes a `gs` it just fetched, same as it already does
/// for `gs.window_end_ts` to compute the settle-time clock. Passing a stale
/// value here fails on-chain (the `seeds` constraint on `win_record`), not
/// silently.
fn ix_settle(global_state: Pubkey, vault: Pubkey, caller: Pubkey, burn_address: Pubkey, win_record: Pubkey) -> Instruction {
    Instruction::new_with_bytes(
        toggld::id(),
        &toggld::instruction::Settle {}.data(),
        toggld::accounts::Settle {
            caller,
            global_state,
            vault,
            burn_address,
            win_record,
            system_program: system_program_id(),
        }
        .to_account_metas(None),
    )
}

/// Derives a win's `WinRecord` PDA for the pre-increment
/// `global_state.holder_count` ordinal it was created at. See
/// `state::WinRecord` / `settle.rs`.
fn win_record_pda(pre_increment_holder_count: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[WIN_RECORD_SEED, &pre_increment_holder_count.to_le_bytes()],
        &toggld::id(),
    )
    .0
}

fn get_win_record(svm: &LiteSVM, pubkey: Pubkey) -> Option<WinRecord> {
    let account = svm.get_account(&pubkey)?;
    WinRecord::try_deserialize(&mut account.data.as_slice()).ok()
}

fn ix_mint_win_nft(
    caller: Pubkey,
    win_record: Pubkey,
    asset: Pubkey,
    uri: String,
    content_hash: [u8; 32],
) -> Instruction {
    Instruction::new_with_bytes(
        toggld::id(),
        &toggld::instruction::MintWinNft { uri, content_hash }.data(),
        toggld::accounts::MintWinNft {
            caller,
            win_record,
            asset,
            mpl_core_program: mpl_core::ID,
            instructions_sysvar: solana_instructions_sysvar::ID,
            system_program: system_program_id(),
        }
        .to_account_metas(None),
    )
}

// ---------------------------------------------------------------------------
// Ed25519 metadata-signer attestation (Mechanism 2, WIN_NFT_PAYMENT_SECURITY_PLAN.md §2.2)
// ---------------------------------------------------------------------------

/// Fixed, dev-only 32-byte ed25519 seed whose public key is exactly
/// `constants::METADATA_SIGNER` (see that constant's doc comment in
/// `constants.rs`) -- lets these LiteSVM tests build a genuine,
/// Ed25519Program-verifiable attestation end-to-end, not a mock. This is the
/// real local-dev seed decoded from `apps/web/.env.local`'s
/// `NFT_METADATA_SIGNER_SECRET` (first 32 of its 64 raw bytes), so it stays
/// in sync with the real `METADATA_SIGNER` constant above.
const METADATA_SIGNER_SEED: [u8; 32] = [107, 146, 155, 99, 84, 148, 132, 26, 123, 32, 235, 212, 14, 232, 10, 126, 174, 172, 109, 129, 74, 137, 101, 109, 139, 196, 51, 81, 183, 39, 216, 10];

/// A different, valid ed25519 keypair whose public key does NOT match
/// `METADATA_SIGNER` -- the "wrong signer" `InvalidMetadataSignature` case.
const WRONG_SIGNER_SEED: [u8; 32] = *b"TOGGLDTESTWRONGSIGNERSEED0000000";

/// Builds a native `Ed25519Program` instruction attesting to `message`,
/// signed by the keypair derived from `seed` -- the single-signature,
/// same-instruction-embedded layout `mint_win_nft.rs`'s
/// `parse_ed25519_instruction_data` parses. Mirrors the shape produced by
/// `solana_sdk::ed25519_instruction::new_ed25519_instruction` / web3.js's
/// `Ed25519Program.createInstructionWithPublicKey`.
fn ed25519_attestation_ix(seed: &[u8; 32], message: &[u8]) -> Instruction {
    let signing_key = SigningKey::from_bytes(seed);
    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign(message);

    const HEADER_LEN: u16 = 2;
    const OFFSETS_LEN: u16 = 14;
    const DATA_START: u16 = HEADER_LEN + OFFSETS_LEN;
    const SAME_INSTRUCTION: u16 = u16::MAX;

    let signature_offset = DATA_START;
    let public_key_offset = signature_offset + 64;
    let message_data_offset = public_key_offset + 32;
    let message_data_size = message.len() as u16;

    let mut data = Vec::with_capacity(DATA_START as usize + 64 + 32 + message.len());
    data.push(1u8); // num_signatures
    data.push(0u8); // padding
    data.extend_from_slice(&signature_offset.to_le_bytes());
    data.extend_from_slice(&SAME_INSTRUCTION.to_le_bytes());
    data.extend_from_slice(&public_key_offset.to_le_bytes());
    data.extend_from_slice(&SAME_INSTRUCTION.to_le_bytes());
    data.extend_from_slice(&message_data_offset.to_le_bytes());
    data.extend_from_slice(&message_data_size.to_le_bytes());
    data.extend_from_slice(&SAME_INSTRUCTION.to_le_bytes());
    data.extend_from_slice(&signature.to_bytes());
    data.extend_from_slice(&verifying_key.to_bytes());
    data.extend_from_slice(message);

    Instruction {
        program_id: solana_sdk_ids::ed25519_program::ID,
        accounts: vec![],
        data,
    }
}

fn ix_withdraw_treasury(
    global_state: Pubkey,
    vault: Pubkey,
    admin: Pubkey,
    treasury: Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        toggld::id(),
        &toggld::instruction::WithdrawTreasury {}.data(),
        toggld::accounts::WithdrawTreasury {
            admin,
            global_state,
            vault,
            treasury,
            system_program: system_program_id(),
        }
        .to_account_metas(None),
    )
}

// ---------------------------------------------------------------------------
// 1. Full happy-path lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_lifecycle_challenge_outbid_flip_defend_withdraw() {
    let (mut svm, global_state, vault, payer) = new_svm();

    let admin = new_funded_keypair(&mut svm, 10_000_000_000);
    let treasury_kp = new_funded_keypair(&mut svm, 10_000_000_000);
    let treasury = treasury_kp.pubkey();
    let user_a = new_funded_keypair(&mut svm, 10_000_000_000);
    let user_b = new_funded_keypair(&mut svm, 10_000_000_000);

    let t0: i64 = 1_000_000;
    set_clock_ts(&mut svm, t0);

    // --- initialize -------------------------------------------------------
    let genesis_price = 1_000_000u64;
    let res = send(
        &mut svm,
        &payer,
        ix_initialize(global_state, vault, payer.pubkey(), treasury, admin.pubkey(), genesis_price),
    );
    assert!(res.is_ok(), "{:?}", res.err());

    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.holder, treasury);
    assert_eq!(gs.holder_since, t0);
    assert_eq!(gs.current_price, genesis_price);
    assert!(!gs.is_on);
    assert_eq!(gs.total_challenges, 0);
    assert_eq!(gs.fee_bps, FEE_BPS);
    assert_eq!(gs.burn_address, INCINERATOR);
    assert!(!gs.window_active);
    assert_vault_invariant(&svm, vault, &gs);

    // --- challenge: cold open by user_a, exactly the 5% min raise ---------
    let bid_a = 1_050_000u64; // 1_000_000 * 1.05
    let prev_top_bidder_1 = get_global_state(&svm, global_state).top_bidder;
    let res = send(
        &mut svm,
        &user_a,
        ix_challenge(global_state, vault, user_a.pubkey(), prev_top_bidder_1, bid_a),
    );
    assert!(res.is_ok(), "{:?}", res.err());

    let gs = get_global_state(&svm, global_state);
    assert!(gs.window_active);
    assert_eq!(gs.window_end_ts, t0 + gs.base_window_secs as i64);
    assert_eq!(gs.top_bidder, user_a.pubkey());
    assert_eq!(gs.top_bid_amount, bid_a);
    assert_eq!(gs.escrowed_amount, bid_a);
    assert_vault_invariant(&svm, vault, &gs);
    let window_end_after_open = gs.window_end_ts;

    // --- challenge: outbid by user_b, well before the snipe threshold -----
    set_clock_ts(&mut svm, t0 + 10); // window_end - 20, not near the snipe threshold
    let bid_b = 1_102_500u64; // 1_050_000 * 1.05
    let prev_top_bidder_2 = get_global_state(&svm, global_state).top_bidder;
    let res = send(
        &mut svm,
        &user_b,
        ix_challenge(global_state, vault, user_b.pubkey(), prev_top_bidder_2, bid_b),
    );
    assert!(res.is_ok(), "{:?}", res.err());

    // user_a's refund must become pull-claimable for exactly its bid amount,
    // no more, no less -- it is not paid out to user_a's wallet directly.
    let user_a_refund =
        get_pending_refund(&svm, pending_refund_pda(user_a.pubkey())).expect("user_a should have a pending refund");
    assert_eq!(user_a_refund.bidder, user_a.pubkey());
    assert_eq!(user_a_refund.amount, bid_a);

    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.top_bidder, user_b.pubkey());
    assert_eq!(gs.top_bid_amount, bid_b);
    assert_eq!(gs.escrowed_amount, bid_b);
    // Not within the snipe-extend window, so the deadline must not move.
    assert_eq!(gs.window_end_ts, window_end_after_open);
    assert_vault_invariant(&svm, vault, &gs);

    // --- settle: flip (user_b != holder(treasury)) -------------------------
    set_clock_ts(&mut svm, gs.window_end_ts);
    let res = send(
        &mut svm,
        &user_b,
        ix_settle(global_state, vault, user_b.pubkey(), INCINERATOR, win_record_pda(gs.holder_count)),
    );
    assert!(res.is_ok(), "{:?}", res.err());

    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.holder, user_b.pubkey());
    assert_eq!(gs.holder_since, t0 + 30);
    assert!(gs.is_on); // flipped from false
    assert_eq!(gs.current_price, bid_b);
    assert!(!gs.window_active);
    assert_eq!(gs.top_bidder, Pubkey::default());
    assert_eq!(gs.top_bid_amount, 0);
    assert_eq!(gs.total_challenges, 1);
    let expected_fee = (bid_b as u128 * FEE_BPS as u128 / 10_000u128) as u64;
    let expected_burn = bid_b - expected_fee;
    assert_eq!(gs.treasury_balance, expected_fee);
    assert_eq!(gs.escrowed_amount, 0);
    assert_eq!(expected_fee + expected_burn, bid_b);
    assert_vault_invariant(&svm, vault, &gs);
    let holder_since_after_flip = gs.holder_since;
    let treasury_balance_after_flip = gs.treasury_balance;

    // --- cold-open self-challenge by the current holder is now rejected ----
    // No active window and no other bidder involved: the holder already
    // holds, so there's nothing to defend against yet. This must be
    // rejected with `CannotChallengeSelf`, not silently succeed.
    let t1 = t0 + 1_000;
    set_clock_ts(&mut svm, t1);
    let self_challenge_attempt = min_raise_amount(gs.current_price, DEFAULT_MIN_RAISE_BPS);
    let res = send(
        &mut svm,
        &user_b,
        ix_challenge(global_state, vault, user_b.pubkey(), Pubkey::default(), self_challenge_attempt),
    );
    assert_err_contains(&res, "CannotChallengeSelf");
    // Rejected atomically -- window must still be untouched.
    let gs = get_global_state(&svm, global_state);
    assert!(!gs.window_active);
    assert_vault_invariant(&svm, vault, &gs);

    // --- challenge: cold open by a different bidder (user_c), then the -----
    // --- holder (user_b) outbids them within the window to defend ----------
    let user_c = new_funded_keypair(&mut svm, 10_000_000_000);
    let bid_c = min_raise_amount(gs.current_price, DEFAULT_MIN_RAISE_BPS);
    let res = send(
        &mut svm,
        &user_c,
        ix_challenge(global_state, vault, user_c.pubkey(), Pubkey::default(), bid_c),
    );
    assert!(res.is_ok(), "{:?}", res.err());

    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.top_bidder, user_c.pubkey());
    assert_eq!(gs.top_bid_amount, bid_c);
    assert_vault_invariant(&svm, vault, &gs);

    // Legitimate self-defend: challenger (holder, user_b) != top_bidder
    // (user_c) -- must remain fully allowed.
    let bid_defend = min_raise_amount(bid_c, DEFAULT_MIN_RAISE_BPS);
    let res = send(
        &mut svm,
        &user_b,
        ix_challenge(global_state, vault, user_b.pubkey(), user_c.pubkey(), bid_defend),
    );
    assert!(res.is_ok(), "{:?}", res.err());

    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.top_bidder, user_b.pubkey());
    assert_eq!(gs.top_bid_amount, bid_defend);
    assert_vault_invariant(&svm, vault, &gs);

    // A direct already-top-bidder re-raise (holder raising their own already
    // top bid, mid-window) must also be rejected.
    let self_raise_attempt = min_raise_amount(bid_defend, DEFAULT_MIN_RAISE_BPS);
    let res = send(
        &mut svm,
        &user_b,
        ix_challenge(global_state, vault, user_b.pubkey(), user_b.pubkey(), self_raise_attempt),
    );
    assert_err_contains(&res, "AlreadyTopBidder");
    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.top_bidder, user_b.pubkey());
    assert_eq!(gs.top_bid_amount, bid_defend);
    assert_vault_invariant(&svm, vault, &gs);

    // --- settle: defend (winner == holder) ---------------------------------
    set_clock_ts(&mut svm, gs.window_end_ts);
    let res = send(
        &mut svm,
        &user_b,
        ix_settle(global_state, vault, user_b.pubkey(), INCINERATOR, win_record_pda(gs.holder_count)),
    );
    assert!(res.is_ok(), "{:?}", res.err());

    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.holder, user_b.pubkey(), "holder must not change on a defend");
    // The key defend-logic assertion: holder_since is NOT reset on a successful defense.
    assert_eq!(gs.holder_since, holder_since_after_flip);
    assert_eq!(gs.current_price, bid_defend);
    assert_eq!(gs.total_challenges, 2);
    let expected_fee_2 = (bid_defend as u128 * FEE_BPS as u128 / 10_000u128) as u64;
    assert_eq!(gs.treasury_balance, treasury_balance_after_flip + expected_fee_2);
    assert_eq!(gs.escrowed_amount, 0);
    assert_vault_invariant(&svm, vault, &gs);

    // --- withdraw_treasury ---------------------------------------------
    let treasury_balance_before_withdraw = svm.get_balance(&treasury).unwrap();
    let expected_withdraw = gs.treasury_balance;
    let res = send(
        &mut svm,
        &admin,
        ix_withdraw_treasury(global_state, vault, admin.pubkey(), treasury),
    );
    assert!(res.is_ok(), "{:?}", res.err());

    let treasury_balance_after_withdraw = svm.get_balance(&treasury).unwrap();
    assert_eq!(
        treasury_balance_after_withdraw - treasury_balance_before_withdraw,
        expected_withdraw
    );
    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.treasury_balance, 0);
    assert_vault_invariant(&svm, vault, &gs);
}

// ---------------------------------------------------------------------------
// 2. Double settle
// ---------------------------------------------------------------------------

#[test]
fn test_double_settle_fails() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let bidder = new_funded_keypair(&mut svm, 10_000_000_000);

    let t0 = 1_000;
    set_clock_ts(&mut svm, t0);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();

    let prev_top_bidder_4 = get_global_state(&svm, global_state).top_bidder;
    send(
        &mut svm,
        &bidder,
        ix_challenge(global_state, vault, bidder.pubkey(), prev_top_bidder_4, 1_050_000),
    )
    .unwrap();

    let gs = get_global_state(&svm, global_state);
    set_clock_ts(&mut svm, gs.window_end_ts);
    let res = send(&mut svm, &bidder, ix_settle(global_state, vault, bidder.pubkey(), INCINERATOR, win_record_pda(gs.holder_count)));
    assert!(res.is_ok(), "{:?}", res.err());

    // Second settle: no active window anymore. Must re-derive `win_record`
    // against the NOW-current `holder_count` (incremented by the first
    // settle's flip above) -- the stale ordinal from before that flip would
    // fail `win_record`'s own seeds constraint before ever reaching the
    // `NoActiveWindow` check this test means to exercise.
    let gs_after_first_settle = get_global_state(&svm, global_state);
    let res = send(
        &mut svm,
        &bidder,
        ix_settle(
            global_state,
            vault,
            bidder.pubkey(),
            INCINERATOR,
            win_record_pda(gs_after_first_settle.holder_count),
        ),
    );
    assert_err_contains(&res, "NoActiveWindow");

    let gs = get_global_state(&svm, global_state);
    assert_vault_invariant(&svm, vault, &gs);
}

// ---------------------------------------------------------------------------
// 3. Settle before window ends (boundary)
// ---------------------------------------------------------------------------

#[test]
fn test_settle_before_window_end_boundary() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let bidder = new_funded_keypair(&mut svm, 10_000_000_000);

    let t0 = 1_000;
    set_clock_ts(&mut svm, t0);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();
    let prev_top_bidder_5 = get_global_state(&svm, global_state).top_bidder;
    send(
        &mut svm,
        &bidder,
        ix_challenge(global_state, vault, bidder.pubkey(), prev_top_bidder_5, 1_050_000),
    )
    .unwrap();

    let gs = get_global_state(&svm, global_state);
    let window_end = gs.window_end_ts;

    // One second before the deadline: must fail.
    set_clock_ts(&mut svm, window_end - 1);
    let res = send(&mut svm, &bidder, ix_settle(global_state, vault, bidder.pubkey(), INCINERATOR, win_record_pda(gs.holder_count)));
    assert_err_contains(&res, "WindowNotClosed");

    // Exactly at the deadline: must succeed (closing boundary is inclusive).
    set_clock_ts(&mut svm, window_end);
    let res = send(&mut svm, &bidder, ix_settle(global_state, vault, bidder.pubkey(), INCINERATOR, win_record_pda(gs.holder_count)));
    assert!(res.is_ok(), "{:?}", res.err());

    let gs = get_global_state(&svm, global_state);
    assert_vault_invariant(&svm, vault, &gs);
}

// ---------------------------------------------------------------------------
// 4. Snipe-extension boundary
// ---------------------------------------------------------------------------

#[test]
fn test_snipe_extension_triggers_and_accumulates() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let bidder1 = new_funded_keypair(&mut svm, 10_000_000_000);
    let bidder2 = new_funded_keypair(&mut svm, 10_000_000_000);
    let bidder3 = new_funded_keypair(&mut svm, 10_000_000_000);

    let t0 = 1_000;
    set_clock_ts(&mut svm, t0);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();
    let prev_top_bidder_6 = get_global_state(&svm, global_state).top_bidder;
    send(
        &mut svm,
        &bidder1,
        ix_challenge(global_state, vault, bidder1.pubkey(), prev_top_bidder_6, 1_050_000),
    )
    .unwrap();

    let gs = get_global_state(&svm, global_state);
    let window_end_0 = gs.window_end_ts; // t0 + 30
    let snipe_extend = gs.snipe_extend_secs as i64; // 10

    // Bid exactly at window_end - snipe_extend_secs: must extend.
    set_clock_ts(&mut svm, window_end_0 - snipe_extend);
    let prev_top_bidder_7 = get_global_state(&svm, global_state).top_bidder;
    send(
        &mut svm,
        &bidder2,
        ix_challenge(global_state, vault, bidder2.pubkey(), prev_top_bidder_7, 1_102_500),
    )
    .unwrap();
    let gs = get_global_state(&svm, global_state);
    let window_end_1 = gs.window_end_ts;
    assert_eq!(window_end_1, window_end_0 + snipe_extend, "should extend from the current end");
    assert_vault_invariant(&svm, vault, &gs);

    // A second late bid at the new threshold: must extend again, strictly further out
    // (not reset to a fixed offset from `now`).
    set_clock_ts(&mut svm, window_end_1 - snipe_extend);
    let prev_top_bidder_8 = get_global_state(&svm, global_state).top_bidder;
    send(
        &mut svm,
        &bidder3,
        ix_challenge(global_state, vault, bidder3.pubkey(), prev_top_bidder_8, 1_157_625),
    )
    .unwrap();
    let gs = get_global_state(&svm, global_state);
    let window_end_2 = gs.window_end_ts;
    assert_eq!(window_end_2, window_end_1 + snipe_extend);
    assert!(window_end_2 > window_end_1 && window_end_1 > window_end_0);
    assert_vault_invariant(&svm, vault, &gs);
}

#[test]
fn test_snipe_extension_not_triggered_one_second_early() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let bidder1 = new_funded_keypair(&mut svm, 10_000_000_000);
    let bidder2 = new_funded_keypair(&mut svm, 10_000_000_000);

    let t0 = 1_000;
    set_clock_ts(&mut svm, t0);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();
    let prev_top_bidder_9 = get_global_state(&svm, global_state).top_bidder;
    send(
        &mut svm,
        &bidder1,
        ix_challenge(global_state, vault, bidder1.pubkey(), prev_top_bidder_9, 1_050_000),
    )
    .unwrap();

    let gs = get_global_state(&svm, global_state);
    let window_end_0 = gs.window_end_ts;
    let snipe_extend = gs.snipe_extend_secs as i64;

    // One second earlier than the snipe threshold: must NOT extend.
    set_clock_ts(&mut svm, window_end_0 - snipe_extend - 1);
    let prev_top_bidder_10 = get_global_state(&svm, global_state).top_bidder;
    send(
        &mut svm,
        &bidder2,
        ix_challenge(global_state, vault, bidder2.pubkey(), prev_top_bidder_10, 1_102_500),
    )
    .unwrap();
    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.window_end_ts, window_end_0, "must not extend before the snipe threshold");
    assert_vault_invariant(&svm, vault, &gs);
}

// ---------------------------------------------------------------------------
// 5. Min-raise boundary
// ---------------------------------------------------------------------------

#[test]
fn test_min_raise_boundary() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let bidder1 = new_funded_keypair(&mut svm, 10_000_000_000);
    let bidder2 = new_funded_keypair(&mut svm, 10_000_000_000);

    set_clock_ts(&mut svm, 1_000);
    // genesis_price divisible by 10_000 so the 5% boundary is an exact integer,
    // ruling out any rounding masking a bug.
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();

    // Cold-open bid exactly at the 5% minimum raise from genesis_price: must succeed.
    let prev_top_bidder_11 = get_global_state(&svm, global_state).top_bidder;
    let res = send(
        &mut svm,
        &bidder1,
        ix_challenge(global_state, vault, bidder1.pubkey(), prev_top_bidder_11, 1_050_000),
    );
    assert!(res.is_ok(), "{:?}", res.err());

    // Active-window bid: exactly the 5% minimum raise from the current top bid succeeds,
    // one lamport under fails.
    let prev_top_bidder_12 = get_global_state(&svm, global_state).top_bidder;
    let res = send(
        &mut svm,
        &bidder2,
        ix_challenge(global_state, vault, bidder2.pubkey(), prev_top_bidder_12, 1_102_499),
    );
    assert_err_contains(&res, "BidTooLow");

    let prev_top_bidder_13 = get_global_state(&svm, global_state).top_bidder;
    let res = send(
        &mut svm,
        &bidder2,
        ix_challenge(global_state, vault, bidder2.pubkey(), prev_top_bidder_13, 1_102_500),
    );
    assert!(res.is_ok(), "{:?}", res.err());

    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.top_bid_amount, 1_102_500);
    assert_vault_invariant(&svm, vault, &gs);
}

// ---------------------------------------------------------------------------
// 6. Refund correctness
// ---------------------------------------------------------------------------

/// Passing a `previous_top_bidder` value that does not match the real
/// `global_state.top_bidder` derives the wrong `pending_refund` PDA address,
/// which fails Anchor's own seeds constraint on-chain -- there is no longer
/// any bidder-supplied "refund destination" account for a caller to get
/// wrong or substitute; the only input is a pubkey used purely to derive a
/// PDA address that must match what's actually stored on-chain.
#[test]
fn test_wrong_pending_refund_pda_fails() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let bidder1 = new_funded_keypair(&mut svm, 10_000_000_000);
    let bidder2 = new_funded_keypair(&mut svm, 10_000_000_000);
    let unrelated = Keypair::new();

    set_clock_ts(&mut svm, 1_000);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();
    send(
        &mut svm,
        &bidder1,
        ix_challenge(global_state, vault, bidder1.pubkey(), Pubkey::default(), 1_050_000),
    )
    .unwrap();

    // `unrelated` is not `global_state.top_bidder` (bidder1 is), so the PDA
    // derived from it does not match the seeds constraint.
    let res = send(
        &mut svm,
        &bidder2,
        ix_challenge(global_state, vault, bidder2.pubkey(), unrelated.pubkey(), 1_102_500),
    );
    assert_err_contains(&res, "ConstraintSeeds");

    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.top_bidder, bidder1.pubkey(), "the failed second challenge must not disturb the first bidder's state");
    assert_vault_invariant(&svm, vault, &gs);
}

/// A cold-open challenge (no previous top bidder to refund) must succeed
/// without ever creating the "null-bidder" `PendingRefund` PDA seeded by
/// `Pubkey::default()`. Regression test for the bug where `pending_refund`
/// was a mandatory `init_if_needed` account: every cold open would create
/// and rent-fund that PDA, leaving it with `bidder = Pubkey::default()` /
/// `amount = 0` forever (no signer can ever equal the zero pubkey, so
/// `claim_refund()` could never close it -- permanently stranded rent).
#[test]
fn test_cold_open_omits_pending_refund_account() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let bidder1 = new_funded_keypair(&mut svm, 10_000_000_000);

    set_clock_ts(&mut svm, 1_000);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();

    // Genesis is a cold open (`global_state.top_bidder == Pubkey::default()`).
    // `ix_challenge` mirrors a well-behaved client and omits `pending_refund`
    // entirely for this case (see its doc comment).
    let res = send(
        &mut svm,
        &bidder1,
        ix_challenge(global_state, vault, bidder1.pubkey(), Pubkey::default(), 1_050_000),
    );
    assert!(res.is_ok(), "cold-open challenge without pending_refund must succeed: {:?}", res.err());

    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.top_bidder, bidder1.pubkey());
    assert_vault_invariant(&svm, vault, &gs);

    // The critical assertion: the null-bidder PDA (seeded by the all-zero
    // pubkey) was never created, so no rent was ever stranded there.
    let null_bidder_pda = pending_refund_pda(Pubkey::default());
    assert!(
        svm.get_account(&null_bidder_pda).is_none(),
        "cold open must never create the pending_refund PDA seeded by Pubkey::default()"
    );
}

/// If a client supplies a real (non-`None`) `pending_refund` account on a
/// cold open anyway, the contract must reject the transaction outright
/// rather than silently creating and rent-funding an unclaimable
/// "null-bidder" PDA. Because Solana transactions are atomic, the rejection
/// also guarantees the `init_if_needed` account creation that Anchor's own
/// account-validation performs ahead of the handler is rolled back with
/// everything else -- so no rent is stranded even when a caller gets this
/// wrong.
#[test]
fn test_cold_open_rejects_supplied_pending_refund_account() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let bidder1 = new_funded_keypair(&mut svm, 10_000_000_000);

    set_clock_ts(&mut svm, 1_000);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();

    let null_bidder_pda = pending_refund_pda(Pubkey::default());
    let res = send(
        &mut svm,
        &bidder1,
        ix_challenge_with_explicit_pending_refund(global_state, vault, bidder1.pubkey(), null_bidder_pda, 1_050_000),
    );
    assert_err_contains(&res, "UnexpectedPendingRefundAccount");

    // Rejected atomically: nothing was created, nothing was charged, and the
    // window/global state was never touched.
    assert!(
        svm.get_account(&null_bidder_pda).is_none(),
        "a rejected cold-open challenge must not leave the null-bidder PDA behind"
    );
    let gs = get_global_state(&svm, global_state);
    assert!(!gs.window_active, "a rejected challenge must not open a bidding window");
    assert_eq!(gs.top_bidder, Pubkey::default());
    assert_vault_invariant(&svm, vault, &gs);
}

/// The exact griefing scenario from the bug report: after being outbid, a
/// bidder calls `system_instruction::assign` on their own wallet to reassign
/// its owner away from the System Program. Under the old inline-transfer
/// design this permanently blocked every subsequent challenger. Under the
/// pull-based design, `challenge()` never reads or depends on the previous
/// bidder's account at all -- the refund goes into a program-owned PDA keyed
/// by the bidder's pubkey -- so this self-inflicted reassignment has zero
/// effect on anyone else, and the assigned-away bidder can still claim their
/// refund afterward (a non-System-owned destination is a perfectly valid
/// recipient of a lamport transfer; only the *source* of a system transfer
/// must be System-owned).
#[test]
fn test_self_reassign_ownership_does_not_block_challenge_and_refund_stays_claimable() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let bidder1 = new_funded_keypair(&mut svm, 10_000_000_000);
    let bidder2 = new_funded_keypair(&mut svm, 10_000_000_000);

    set_clock_ts(&mut svm, 1_000);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();
    send(
        &mut svm,
        &bidder1,
        ix_challenge(global_state, vault, bidder1.pubkey(), Pubkey::default(), 1_050_000),
    )
    .unwrap();

    // Outbid bidder1: their refund becomes claimable in their own PDA.
    let res = send(
        &mut svm,
        &bidder2,
        ix_challenge(global_state, vault, bidder2.pubkey(), bidder1.pubkey(), 1_102_500),
    );
    assert!(res.is_ok(), "{:?}", res.err());
    let gs = get_global_state(&svm, global_state);
    assert_vault_invariant(&svm, vault, &gs);
    let refund = get_pending_refund(&svm, pending_refund_pda(bidder1.pubkey())).expect("refund should be pending");
    assert_eq!(refund.bidder, bidder1.pubkey());
    assert_eq!(refund.amount, 1_050_000);

    // The griefing attack: bidder1 reassigns their own wallet's owner away
    // from the System Program (a normal, self-authorized, permissionless
    // action requiring no special privilege).
    let existing = svm.get_account(&bidder1.pubkey()).unwrap();
    svm.set_account(
        bidder1.pubkey(),
        SvmAccount {
            lamports: existing.lamports,
            data: vec![],
            owner: toggld::id(),
            executable: false,
            rent_epoch: existing.rent_epoch,
        },
    )
    .unwrap();

    // A subsequent, independent challenger's outbid must succeed regardless
    // -- this is the core fix: challenge() never touches bidder1's account
    // at all, so bidder1's self-inflicted ownership change cannot block it.
    let bidder3 = new_funded_keypair(&mut svm, 10_000_000_000);
    let gs = get_global_state(&svm, global_state);
    let res = send(
        &mut svm,
        &bidder3,
        ix_challenge(
            global_state,
            vault,
            bidder3.pubkey(),
            bidder2.pubkey(),
            min_raise_amount(gs.top_bid_amount, gs.min_raise_bps),
        ),
    );
    assert!(res.is_ok(), "{:?}", res.err());
    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.top_bidder, bidder3.pubkey());
    assert_vault_invariant(&svm, vault, &gs);

    // bidder1's refund must still be exactly as it was -- untouched by
    // bidder2/bidder3's later activity.
    let refund = get_pending_refund(&svm, pending_refund_pda(bidder1.pubkey())).expect("refund should still be pending");
    assert_eq!(refund.amount, 1_050_000);

    // bidder1 can still claim it, even though their wallet is no longer
    // System-Program-owned (and can therefore no longer pay a transaction
    // fee itself, since a fee payer must be System-owned) -- `payer` covers
    // the fee, while bidder1 still signs as `claimant`, proving the
    // *destination* of the payout need not be System-owned, only the
    // *source* (the vault, earlier, and the pending_refund PDA here).
    let bidder1_balance_before = svm.get_balance(&bidder1.pubkey()).unwrap();
    let res = send_with_signers(&mut svm, &payer, &[&payer, &bidder1], ix_claim_refund(bidder1.pubkey()));
    assert!(res.is_ok(), "{:?}", res.err());

    let bidder1_balance_after = svm.get_balance(&bidder1.pubkey()).unwrap();
    let pending_refund_rent = svm.minimum_balance_for_rent_exemption(PendingRefund::SPACE);
    // bidder1 paid no tx fee (payer did), so the delta is exactly the
    // refunded bid plus the reclaimed rent-exempt reserve -- no more, no less.
    assert_eq!(
        bidder1_balance_after - bidder1_balance_before,
        1_050_000 + pending_refund_rent,
        "must receive exactly the refunded bid plus reclaimed rent"
    );

    assert!(
        get_pending_refund(&svm, pending_refund_pda(bidder1.pubkey())).is_none(),
        "refund account must be closed after claim"
    );
}

// ---------------------------------------------------------------------------
// 7. Fee-split exactness
// ---------------------------------------------------------------------------

#[test]
fn test_fee_split_exactness_across_amounts() {
    // This test deliberately never calls `setup_token()`, so `burn_address`
    // stays `INCINERATOR` and the burn leg is still a raw SOL transfer to the
    // incinerator — the pre-token path. The post-`setup_token()` behaviour
    // (burn leg -> `burn_vault`) is covered by
    // `test_settle_burn_leg_lands_in_burn_vault_after_setup_token`.
    //
    // Amounts deliberately not evenly divisible by 10_000, so the fee-split
    // integer division actually truncates and we still expect exactness.
    for winning_price in [777u64, 123_457u64, 999_999_983u64] {
        let (mut svm, global_state, vault, payer) = new_svm();
        let treasury = Keypair::new().pubkey();
        let admin = Keypair::new().pubkey();
        let bidder = new_funded_keypair(&mut svm, 5_000_000_000);

        set_clock_ts(&mut svm, 1_000);
        // genesis_price = 1 so any bid >= 2 clears the min-raise floor.
        send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1)).unwrap();
        let prev_top_bidder_18 = get_global_state(&svm, global_state).top_bidder;
        send(
            &mut svm,
            &bidder,
            ix_challenge(global_state, vault, bidder.pubkey(), prev_top_bidder_18, winning_price),
        )
        .unwrap();

        let gs = get_global_state(&svm, global_state);
        set_clock_ts(&mut svm, gs.window_end_ts);

        let treasury_balance_before = gs.treasury_balance;
        let burn_balance_before = svm.get_balance(&INCINERATOR).unwrap_or(0);

        let res = send(&mut svm, &bidder, ix_settle(global_state, vault, bidder.pubkey(), INCINERATOR, win_record_pda(gs.holder_count)));
        assert!(res.is_ok(), "{:?}", res.err());

        let gs = get_global_state(&svm, global_state);
        let burn_balance_after = svm.get_balance(&INCINERATOR).unwrap();
        let treasury_cut = gs.treasury_balance - treasury_balance_before;
        let burned_amount = burn_balance_after - burn_balance_before;

        assert_eq!(
            treasury_cut + burned_amount,
            winning_price,
            "fee split must be exact for winning_price={winning_price}"
        );
        assert_vault_invariant(&svm, vault, &gs);
    }
}

// ---------------------------------------------------------------------------
// 8. Authorization checks
// ---------------------------------------------------------------------------

#[test]
fn test_withdraw_treasury_unauthorized_fails() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let attacker = new_funded_keypair(&mut svm, 10_000_000_000);

    set_clock_ts(&mut svm, 1_000);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();

    let res = send(
        &mut svm,
        &attacker,
        ix_withdraw_treasury(global_state, vault, attacker.pubkey(), treasury),
    );
    assert_err_contains(&res, "Unauthorized");
}

// ---------------------------------------------------------------------------
// 10. Burn / treasury account substitution
// ---------------------------------------------------------------------------

#[test]
fn test_settle_wrong_burn_address_fails() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let bidder = new_funded_keypair(&mut svm, 10_000_000_000);
    let attacker_burn = Keypair::new().pubkey();

    set_clock_ts(&mut svm, 1_000);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();
    let prev_top_bidder_20 = get_global_state(&svm, global_state).top_bidder;
    send(
        &mut svm,
        &bidder,
        ix_challenge(global_state, vault, bidder.pubkey(), prev_top_bidder_20, 1_050_000),
    )
    .unwrap();

    let gs = get_global_state(&svm, global_state);
    set_clock_ts(&mut svm, gs.window_end_ts);

    let res = send(&mut svm, &bidder, ix_settle(global_state, vault, bidder.pubkey(), attacker_burn, win_record_pda(gs.holder_count)));
    assert_err_contains(&res, "InvalidBurnAddress");

    let gs = get_global_state(&svm, global_state);
    assert_vault_invariant(&svm, vault, &gs);
}

#[test]
fn test_withdraw_treasury_wrong_treasury_account_fails() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = new_funded_keypair(&mut svm, 10_000_000_000);
    let attacker_treasury = Keypair::new().pubkey();

    set_clock_ts(&mut svm, 1_000);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin.pubkey(), 1_000_000)).unwrap();

    let res = send(
        &mut svm,
        &admin,
        ix_withdraw_treasury(global_state, vault, admin.pubkey(), attacker_treasury),
    );
    assert_err_contains(&res, "InvalidTreasuryAccount");
}

// ---------------------------------------------------------------------------
// 11. Genesis price floor
// ---------------------------------------------------------------------------

#[test]
fn test_initialize_genesis_price_zero_fails() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();

    let res = send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 0));
    assert_err_contains(&res, "InvalidGenesisPrice");
}

// ---------------------------------------------------------------------------
// 11b. Upgrade-authority gating on initialize() (front-running fix)
// ---------------------------------------------------------------------------

/// A signer who is NOT the program's upgrade authority must be rejected -
/// this is the exact front-running attack the constraint exists to close
/// (whoever's `initialize()` transaction lands first would otherwise
/// permanently become admin/treasury).
#[test]
fn test_initialize_wrong_upgrade_authority_fails() {
    let (mut svm, global_state, vault, _authority) = new_svm();
    let attacker = new_funded_keypair(&mut svm, 10_000_000_000);
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();

    let res = send(
        &mut svm,
        &attacker,
        ix_initialize(global_state, vault, attacker.pubkey(), treasury, admin, 1_000_000),
    );
    assert_err_contains(&res, "Unauthorized");

    // The failed call must not have created global_state at all.
    assert!(svm.get_account(&global_state).is_none());
}

/// Explicitly exercises the constraint's *current-state* read, not just a
/// value it happens to already hold: rotate the program's upgrade authority
/// to a second keypair after `new_svm()` sets the first one, then confirm
/// only the new authority - never the old one - can call `initialize()`.
/// This proves the check reads `ProgramData.upgrade_authority_address` live
/// rather than accepting whichever signer first showed up.
#[test]
fn test_initialize_succeeds_for_current_upgrade_authority_only() {
    let (mut svm, global_state, vault, old_authority) = new_svm();
    let new_authority = new_funded_keypair(&mut svm, 10_000_000_000);
    set_upgrade_authority(&mut svm, toggld::id(), new_authority.pubkey());

    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();

    // The now-superseded authority must be rejected.
    let res = send(
        &mut svm,
        &old_authority,
        ix_initialize(global_state, vault, old_authority.pubkey(), treasury, admin, 1_000_000),
    );
    assert_err_contains(&res, "Unauthorized");
    assert!(svm.get_account(&global_state).is_none());

    // The current authority must succeed.
    let res = send(
        &mut svm,
        &new_authority,
        ix_initialize(global_state, vault, new_authority.pubkey(), treasury, admin, 1_000_000),
    );
    assert!(res.is_ok(), "{:?}", res.err());
    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.treasury, treasury);
    assert_eq!(gs.admin, admin);
    assert_vault_invariant(&svm, vault, &gs);
}

// ---------------------------------------------------------------------------
// 11c. initialize() treasury/admin zero-address validation
// ---------------------------------------------------------------------------

#[test]
fn test_initialize_admin_default_fails() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();

    let res = send(
        &mut svm,
        &payer,
        ix_initialize(global_state, vault, payer.pubkey(), treasury, Pubkey::default(), 1_000_000),
    );
    assert_err_contains(&res, "InvalidAdmin");
    assert!(svm.get_account(&global_state).is_none());
}

#[test]
fn test_initialize_treasury_default_fails() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = Keypair::new().pubkey();

    let res = send(
        &mut svm,
        &payer,
        ix_initialize(global_state, vault, payer.pubkey(), Pubkey::default(), admin, 1_000_000),
    );
    assert_err_contains(&res, "InvalidTreasury");
    assert!(svm.get_account(&global_state).is_none());
}

// ---------------------------------------------------------------------------
// 11d. Genesis WinRecord (holder #1 Win NFT eligibility)
// ---------------------------------------------------------------------------

/// A fresh `initialize()` must create the genesis holder's `WinRecord` at the
/// reserved ordinal-`0` PDA, exactly mirroring what a real flip's `WinRecord`
/// looks like except for `price_paid` (no auction happened for the genesis
/// holder -- see `state::WinRecord`'s doc comment).
#[test]
fn test_initialize_creates_genesis_win_record() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury_kp = new_funded_keypair(&mut svm, 10_000_000_000);
    let treasury = treasury_kp.pubkey();
    let admin = Keypair::new().pubkey();

    let t0: i64 = 500_000;
    set_clock_ts(&mut svm, t0);
    let genesis_price = 2_000_000u64;
    let res = send(
        &mut svm,
        &payer,
        ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, genesis_price),
    );
    assert!(res.is_ok(), "{:?}", res.err());

    let genesis_win_record = genesis_win_record_pda();
    let record = get_win_record(&svm, genesis_win_record).expect("genesis WinRecord must exist after initialize()");
    assert_eq!(record.winner, treasury);
    assert_eq!(record.holder_count, 1);
    assert_eq!(
        record.price_paid, 0,
        "genesis holder never won an auction -- price_paid must be 0, not genesis_price"
    );
    assert_eq!(record.won_at, t0);
    assert!(!record.minted);

    let rent_exempt = svm.minimum_balance_for_rent_exemption(WinRecord::SPACE);
    assert_eq!(
        svm.get_balance(&genesis_win_record).unwrap(),
        rent_exempt,
        "genesis WinRecord must be funded to exactly its rent-exempt minimum, no more"
    );
}

/// The genesis holder (the treasury-controlling wallet) must be able to mint
/// their genesis WinRecord through the exact same `mint_win_nft` path as any
/// other win -- no special-casing.
#[test]
fn test_genesis_win_record_mint_win_nft_happy_path() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury_kp = new_funded_keypair(&mut svm, 10_000_000_000);
    let admin = Keypair::new().pubkey();

    set_clock_ts(&mut svm, 1_000);
    send(
        &mut svm,
        &payer,
        ix_initialize(global_state, vault, payer.pubkey(), treasury_kp.pubkey(), admin, 1_000_000),
    )
    .unwrap();

    let genesis_win_record = genesis_win_record_pda();
    let asset = Keypair::new();
    let uri = "https://arweave.net/genesis".to_string();
    let content_hash = [99u8; 32];
    let ed25519_ix = ed25519_attestation_ix(&METADATA_SIGNER_SEED, &content_hash);
    let mint_ix = ix_mint_win_nft(treasury_kp.pubkey(), genesis_win_record, asset.pubkey(), uri.clone(), content_hash);
    let res = send_multi(&mut svm, &treasury_kp, &[&treasury_kp, &asset], &[ed25519_ix, mint_ix]);
    assert!(res.is_ok(), "{:?}", res.err());

    let record = get_win_record(&svm, genesis_win_record).unwrap();
    assert!(record.minted, "genesis WinRecord.minted must flip to true after a successful mint");

    let asset_account = svm.get_account(&asset.pubkey()).expect("asset account must exist after CreateV1");
    assert_eq!(asset_account.owner, mpl_core::ID);
    let parsed =
        mpl_core::accounts::BaseAssetV1::from_bytes(&asset_account.data).expect("asset data must parse as BaseAssetV1");
    assert_eq!(parsed.owner, treasury_kp.pubkey());
    assert_eq!(
        parsed.update_authority,
        mpl_core::types::UpdateAuthority::None,
        "update authority must never be retained, same as any other Win NFT mint"
    );
    assert_eq!(parsed.uri, uri);

    let full_asset = mpl_core::Asset::deserialize(&asset_account.data).expect("asset data must parse with plugins");
    let attrs = full_asset
        .plugin_list
        .attributes
        .as_ref()
        .expect("Attributes plugin must be present")
        .attributes
        .attribute_list
        .clone();
    let find = |key: &str| attrs.iter().find(|a| a.key == key).map(|a| a.value.clone());
    assert_eq!(find("winner"), Some(treasury_kp.pubkey().to_string()));
    assert_eq!(find("holder_count"), Some("1".to_string()));
    assert_eq!(find("price_paid"), Some("0".to_string()));
    assert_eq!(find("won_at"), Some(record.won_at.to_string()));
    let expected_hex: String = content_hash.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(find("metadata_hash"), Some(expected_hex));
}

/// Same `winner == caller` gate as any other `WinRecord` -- a wallet that is
/// not the treasury must never be able to mint the genesis win.
#[test]
fn test_genesis_win_record_rejects_non_treasury_caller() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();

    set_clock_ts(&mut svm, 1_000);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();

    let impostor = new_funded_keypair(&mut svm, 10_000_000_000);
    let asset = Keypair::new();
    let genesis_win_record = genesis_win_record_pda();
    // `NotWinRecordOwner` is checked before the metadata-signature check, so
    // no Ed25519 attestation is needed for this to fail correctly.
    let ix = ix_mint_win_nft(
        impostor.pubkey(),
        genesis_win_record,
        asset.pubkey(),
        "https://arweave.net/x".to_string(),
        [0u8; 32],
    );
    let res = send_with_signers(&mut svm, &impostor, &[&impostor, &asset], ix);
    assert_err_contains(&res, "NotWinRecordOwner");

    let record = get_win_record(&svm, genesis_win_record).unwrap();
    assert!(!record.minted, "a rejected mint attempt must not flip minted");
}

/// Proves the genesis record's ordinal-`0` PDA never collides with the first
/// real flip's ordinal-`1` PDA -- both must exist independently, side by
/// side, after a fresh `initialize()` followed by a real challenge/settle
/// flip.
#[test]
fn test_genesis_win_record_ordinal_never_collides_with_first_flip() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury_kp = new_funded_keypair(&mut svm, 10_000_000_000);
    let admin = Keypair::new().pubkey();

    set_clock_ts(&mut svm, 1_000);
    send(
        &mut svm,
        &payer,
        ix_initialize(global_state, vault, payer.pubkey(), treasury_kp.pubkey(), admin, 1_000_000),
    )
    .unwrap();

    let genesis_win_record = genesis_win_record_pda();
    assert_eq!(genesis_win_record, win_record_pda(0));

    let winner = new_funded_keypair(&mut svm, 10_000_000_000);
    let gs0 = get_global_state(&svm, global_state);
    let bid = min_raise_amount(gs0.current_price, gs0.min_raise_bps);
    send(&mut svm, &winner, ix_challenge(global_state, vault, winner.pubkey(), Pubkey::default(), bid)).unwrap();

    let gs = get_global_state(&svm, global_state);
    set_clock_ts(&mut svm, gs.window_end_ts);
    let flip_win_record = win_record_pda(gs.holder_count);
    assert_eq!(flip_win_record, win_record_pda(1), "first-ever flip must be seeded by ordinal 1");
    assert_ne!(genesis_win_record, flip_win_record, "genesis (0) and first flip (1) PDAs must never collide");

    let res = send(&mut svm, &winner, ix_settle(global_state, vault, winner.pubkey(), INCINERATOR, flip_win_record));
    assert!(res.is_ok(), "{:?}", res.err());

    // Both records must now independently exist, each with their own data.
    let genesis_record = get_win_record(&svm, genesis_win_record).expect("genesis WinRecord must still exist");
    assert_eq!(genesis_record.winner, treasury_kp.pubkey());
    assert_eq!(genesis_record.holder_count, 1);

    let flip_record = get_win_record(&svm, flip_win_record).expect("first flip's WinRecord must exist");
    assert_eq!(flip_record.winner, winner.pubkey());
    assert_eq!(flip_record.holder_count, 2);
}

// ---------------------------------------------------------------------------
// 13. Concurrent bid storms
// ---------------------------------------------------------------------------

#[test]
fn test_bid_storm_sequential_min_raise_chain() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let challengers: Vec<Keypair> = (0..15).map(|_| new_funded_keypair(&mut svm, 10_000_000_000)).collect();

    let t0 = 1_000;
    set_clock_ts(&mut svm, t0);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();

    let gs = get_global_state(&svm, global_state);
    let min_raise_bps = gs.min_raise_bps;
    let mut base = gs.current_price;

    for (i, challenger) in challengers.iter().enumerate() {
        let bid = min_raise_amount(base, min_raise_bps);
        let previous_top_bidder = if i == 0 {
            Pubkey::new_unique()
        } else {
            challengers[i - 1].pubkey()
        };
        let prev_top_bidder_21 = get_global_state(&svm, global_state).top_bidder;
        let res = send(
            &mut svm,
            challenger,
            ix_challenge(global_state, vault, challenger.pubkey(), prev_top_bidder_21, bid),
        );
        assert!(res.is_ok(), "bid {i} failed: {:?}", res.err());

        if i > 0 {
            // Every intermediate refund lands in exactly the previous
            // bidder's own claimable PDA, no more no less.
            let refund = get_pending_refund(&svm, pending_refund_pda(previous_top_bidder))
                .expect("refund should be pending");
            assert_eq!(refund.amount, base);
        }

        let gs = get_global_state(&svm, global_state);
        assert_eq!(gs.top_bidder, challenger.pubkey());
        assert_eq!(gs.top_bid_amount, bid);
        // No drift: escrow always equals exactly the current top bid, never
        // the previous bidder's stale amount plus the new one.
        assert_eq!(gs.escrowed_amount, bid);
        assert_vault_invariant(&svm, vault, &gs);
        base = bid;
    }

    let gs = get_global_state(&svm, global_state);
    set_clock_ts(&mut svm, gs.window_end_ts);
    let last = challengers.last().unwrap();
    let res = send(&mut svm, last, ix_settle(global_state, vault, last.pubkey(), INCINERATOR, win_record_pda(gs.holder_count)));
    assert!(res.is_ok(), "{:?}", res.err());

    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.holder, last.pubkey());
    assert_eq!(gs.current_price, base);
    assert_eq!(gs.escrowed_amount, 0);
    assert_vault_invariant(&svm, vault, &gs);
}

#[test]
fn test_bid_storm_interleaved_late_bidders() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let bidders: Vec<Keypair> = (0..6).map(|_| new_funded_keypair(&mut svm, 10_000_000_000)).collect();

    let t0 = 1_000;
    set_clock_ts(&mut svm, t0);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();
    let prev_top_bidder_22 = get_global_state(&svm, global_state).top_bidder;
    send(
        &mut svm,
        &bidders[0],
        ix_challenge(global_state, vault, bidders[0].pubkey(), prev_top_bidder_22, 1_050_000),
    )
    .unwrap();

    let gs = get_global_state(&svm, global_state);
    let snipe_extend = gs.snipe_extend_secs as i64;
    let min_raise_bps = gs.min_raise_bps;
    let mut window_end = gs.window_end_ts;
    let mut base = gs.top_bid_amount;

    // (offset from t0, expected to extend) - a dense, mixed-timing sequence
    // straddling the snipe threshold on both sides.
    let offsets_and_expect_extend = [(5i64, false), (20, true), (25, false), (30, true), (45, true)];

    for (i, (offset, expect_extend)) in offsets_and_expect_extend.iter().enumerate() {
        let bidder = &bidders[i + 1];
        let bid = min_raise_amount(base, min_raise_bps);

        set_clock_ts(&mut svm, t0 + offset);
        let prev_top_bidder_23 = get_global_state(&svm, global_state).top_bidder;
        let res = send(
            &mut svm,
            bidder,
            ix_challenge(global_state, vault, bidder.pubkey(), prev_top_bidder_23, bid),
        );
        assert!(res.is_ok(), "bid {i} failed: {:?}", res.err());

        let gs = get_global_state(&svm, global_state);
        if *expect_extend {
            assert_eq!(gs.window_end_ts, window_end + snipe_extend, "bid {i} should extend");
        } else {
            assert_eq!(gs.window_end_ts, window_end, "bid {i} should not extend");
        }
        // Monotonic: the window end only ever moves forward, never shortens.
        assert!(gs.window_end_ts >= window_end);
        window_end = gs.window_end_ts;
        base = bid;
        assert_vault_invariant(&svm, vault, &gs);
    }
}

#[test]
fn test_bid_storm_same_bidder_repeated() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let a = new_funded_keypair(&mut svm, 10_000_000_000);
    let b = new_funded_keypair(&mut svm, 10_000_000_000);
    let c = new_funded_keypair(&mut svm, 10_000_000_000);

    set_clock_ts(&mut svm, 1_000);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();

    // a opens, b outbids a (a refunded once), c outbids b (b refunded once),
    // a outbids c again (c refunded once) - a is top bidder again after
    // having already been refunded earlier in the same window.
    let bid_a1 = 1_050_000u64;
    let prev_top_bidder_24 = get_global_state(&svm, global_state).top_bidder;
    send(&mut svm, &a, ix_challenge(global_state, vault, a.pubkey(), prev_top_bidder_24, bid_a1)).unwrap();

    let bid_b = 1_102_500u64;
    let prev_top_bidder_25 = get_global_state(&svm, global_state).top_bidder;
    send(&mut svm, &b, ix_challenge(global_state, vault, b.pubkey(), prev_top_bidder_25, bid_b)).unwrap();
    // a's refund becomes pull-claimable for exactly bid_a1 - not paid to its wallet.
    let a_refund_after_first =
        get_pending_refund(&svm, pending_refund_pda(a.pubkey())).expect("a should have a pending refund");
    assert_eq!(a_refund_after_first.amount, bid_a1);

    let bid_c = 1_157_625u64;
    let prev_top_bidder_26 = get_global_state(&svm, global_state).top_bidder;
    send(&mut svm, &c, ix_challenge(global_state, vault, c.pubkey(), prev_top_bidder_26, bid_c)).unwrap();
    let b_refund =
        get_pending_refund(&svm, pending_refund_pda(b.pubkey())).expect("b should have a pending refund");
    assert_eq!(b_refund.amount, bid_b);

    let bid_a2 = min_raise_amount(bid_c, get_global_state(&svm, global_state).min_raise_bps);
    let prev_top_bidder_27 = get_global_state(&svm, global_state).top_bidder;
    send(&mut svm, &a, ix_challenge(global_state, vault, a.pubkey(), prev_top_bidder_27, bid_a2)).unwrap();

    // a's earlier (still-unclaimed) refund from being outbid the first time
    // must be completely untouched by a becoming top bidder again - no
    // stray double-refund, no funds lost, no accidental reset to zero.
    let a_refund_after_rebid =
        get_pending_refund(&svm, pending_refund_pda(a.pubkey())).expect("a's earlier refund must still exist");
    assert_eq!(a_refund_after_rebid.amount, bid_a1);
    // c is refunded exactly once, for exactly its bid.
    let c_refund =
        get_pending_refund(&svm, pending_refund_pda(c.pubkey())).expect("c should have a pending refund");
    assert_eq!(c_refund.amount, bid_c);

    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.top_bidder, a.pubkey());
    assert_eq!(gs.top_bid_amount, bid_a2);
    assert_eq!(gs.escrowed_amount, bid_a2);
    assert_vault_invariant(&svm, vault, &gs);

    // a is now already top_bidder -- a direct re-raise attempt (raising its
    // own already-winning bid, not being outbid by someone else in between)
    // must be rejected with `AlreadyTopBidder`.
    let bid_a3 = min_raise_amount(bid_a2, gs.min_raise_bps);
    let res = send(&mut svm, &a, ix_challenge(global_state, vault, a.pubkey(), a.pubkey(), bid_a3));
    assert_err_contains(&res, "AlreadyTopBidder");
    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.top_bidder, a.pubkey());
    assert_eq!(gs.top_bid_amount, bid_a2);
    assert_vault_invariant(&svm, vault, &gs);
}

// ---------------------------------------------------------------------------
// 14. Snipe-extension exact boundary
// ---------------------------------------------------------------------------

#[test]
fn test_snipe_extension_exact_threshold_tie() {
    // Side A: bid lands exactly at the `>=` boundary - must extend.
    {
        let (mut svm, global_state, vault, payer) = new_svm();
        let treasury = Keypair::new().pubkey();
        let admin = Keypair::new().pubkey();
        let bidder1 = new_funded_keypair(&mut svm, 10_000_000_000);
        let bidder2 = new_funded_keypair(&mut svm, 10_000_000_000);

        let t0 = 1_000;
        set_clock_ts(&mut svm, t0);
        send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();
        let prev_top_bidder_28 = get_global_state(&svm, global_state).top_bidder;
        send(
            &mut svm,
            &bidder1,
            ix_challenge(global_state, vault, bidder1.pubkey(), prev_top_bidder_28, 1_050_000),
        )
        .unwrap();

        let gs = get_global_state(&svm, global_state);
        let window_end = gs.window_end_ts;
        let snipe_extend = gs.snipe_extend_secs as i64;

        set_clock_ts(&mut svm, window_end - snipe_extend);
        let prev_top_bidder_29 = get_global_state(&svm, global_state).top_bidder;
        send(&mut svm, &bidder2, ix_challenge(global_state, vault, bidder2.pubkey(), prev_top_bidder_29, 1_102_500)).unwrap();

        let gs = get_global_state(&svm, global_state);
        assert_eq!(gs.window_end_ts, window_end + snipe_extend, "exact tie must extend");
        assert_vault_invariant(&svm, vault, &gs);
    }

    // Side B: one second earlier than the tie - must not extend.
    {
        let (mut svm, global_state, vault, payer) = new_svm();
        let treasury = Keypair::new().pubkey();
        let admin = Keypair::new().pubkey();
        let bidder1 = new_funded_keypair(&mut svm, 10_000_000_000);
        let bidder2 = new_funded_keypair(&mut svm, 10_000_000_000);

        let t0 = 1_000;
        set_clock_ts(&mut svm, t0);
        send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();
        let prev_top_bidder_30 = get_global_state(&svm, global_state).top_bidder;
        send(
            &mut svm,
            &bidder1,
            ix_challenge(global_state, vault, bidder1.pubkey(), prev_top_bidder_30, 1_050_000),
        )
        .unwrap();

        let gs = get_global_state(&svm, global_state);
        let window_end = gs.window_end_ts;
        let snipe_extend = gs.snipe_extend_secs as i64;

        set_clock_ts(&mut svm, window_end - snipe_extend - 1);
        let prev_top_bidder_31 = get_global_state(&svm, global_state).top_bidder;
        send(&mut svm, &bidder2, ix_challenge(global_state, vault, bidder2.pubkey(), prev_top_bidder_31, 1_102_500)).unwrap();

        let gs = get_global_state(&svm, global_state);
        assert_eq!(gs.window_end_ts, window_end, "one second early must not extend");
        assert_vault_invariant(&svm, vault, &gs);
    }
}

#[test]
fn test_snipe_extension_extends_from_current_end_not_now() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let bidder1 = new_funded_keypair(&mut svm, 10_000_000_000);
    let bidder2 = new_funded_keypair(&mut svm, 10_000_000_000);
    let bidder3 = new_funded_keypair(&mut svm, 10_000_000_000);

    let t0 = 1_000;
    set_clock_ts(&mut svm, t0);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();
    let prev_top_bidder_32 = get_global_state(&svm, global_state).top_bidder;
    send(
        &mut svm,
        &bidder1,
        ix_challenge(global_state, vault, bidder1.pubkey(), prev_top_bidder_32, 1_050_000),
    )
    .unwrap();

    let gs = get_global_state(&svm, global_state);
    let window_end_0 = gs.window_end_ts; // t0 + 30
    let snipe_extend = gs.snipe_extend_secs as i64; // 10

    // First late bid, 5s past the threshold (not exactly on it).
    set_clock_ts(&mut svm, window_end_0 - snipe_extend + 5);
    let prev_top_bidder_33 = get_global_state(&svm, global_state).top_bidder;
    send(&mut svm, &bidder2, ix_challenge(global_state, vault, bidder2.pubkey(), prev_top_bidder_33, 1_102_500)).unwrap();
    let gs = get_global_state(&svm, global_state);
    let window_end_1 = gs.window_end_ts;
    assert_eq!(window_end_1, window_end_0 + snipe_extend);

    // Second late bid, again 5s past the (new) threshold. If the extension
    // were computed from `now + snipe_extend_secs` instead of the current
    // `window_end_ts + snipe_extend_secs`, this would land 5s short of the
    // correct value - this assertion would catch that regression.
    let now2 = window_end_1 - snipe_extend + 5;
    set_clock_ts(&mut svm, now2);
    let prev_top_bidder_34 = get_global_state(&svm, global_state).top_bidder;
    send(&mut svm, &bidder3, ix_challenge(global_state, vault, bidder3.pubkey(), prev_top_bidder_34, 1_157_625)).unwrap();
    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.window_end_ts, window_end_1 + snipe_extend, "must extend from window_end_ts, not now");
    assert_ne!(gs.window_end_ts, now2 + snipe_extend, "must not extend from now");
    assert_vault_invariant(&svm, vault, &gs);
}

// ---------------------------------------------------------------------------
// 15. Reentrancy-style / escrow-substitution checks
// ---------------------------------------------------------------------------

// `test_challenge_with_vault_as_refund_account_fails` and
// `test_challenge_with_global_state_as_refund_account_fails` (old
// account-substitution tests) no longer apply: there is no bidder-supplied
// "refund destination" account at all any more -- `pending_refund` is
// derived purely from `global_state.top_bidder` via a seeds constraint (see
// `test_wrong_pending_refund_pda_fails` above), so substituting an arbitrary
// account is not even expressible as an attack anymore.

#[test]
fn test_double_challenge_same_slot_only_one_wins() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let bidder1 = new_funded_keypair(&mut svm, 10_000_000_000);
    let bidder2 = new_funded_keypair(&mut svm, 10_000_000_000);

    set_clock_ts(&mut svm, 1_000);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();

    // First challenge: valid cold open.
    let prev_top_bidder_39 = get_global_state(&svm, global_state).top_bidder;
    let res = send(
        &mut svm,
        &bidder1,
        ix_challenge(global_state, vault, bidder1.pubkey(), prev_top_bidder_39, 1_050_000),
    );
    assert!(res.is_ok(), "{:?}", res.err());
    let gs_after_first = get_global_state(&svm, global_state);

    // Second challenge processed immediately after, below the min-raise off the new top bid.
    let prev_top_bidder_40 = get_global_state(&svm, global_state).top_bidder;
    let res = send(&mut svm, &bidder2, ix_challenge(global_state, vault, bidder2.pubkey(), prev_top_bidder_40, 1_050_001));
    assert_err_contains(&res, "BidTooLow");

    // The failed second challenge must leave the first winner's escrow/refund state untouched.
    let gs_after_second = get_global_state(&svm, global_state);
    assert_eq!(gs_after_second.top_bidder, gs_after_first.top_bidder);
    assert_eq!(gs_after_second.top_bid_amount, gs_after_first.top_bid_amount);
    assert_eq!(gs_after_second.escrowed_amount, gs_after_first.escrowed_amount);
    assert_vault_invariant(&svm, vault, &gs_after_second);
}

#[test]
fn test_settle_refund_account_omitted_from_settle_ix_is_impossible() {
    let (_svm, global_state, vault, _payer) = new_svm();
    let caller = Pubkey::new_unique();
    let burn_address = Pubkey::new_unique();
    let win_record = Pubkey::new_unique();

    let metas = toggld::accounts::Settle {
        caller,
        global_state,
        vault,
        burn_address,
        win_record,
        system_program: system_program_id(),
    }
    .to_account_metas(None);

    // Settle's account list is fixed at exactly these six contract-pinned
    // slots - there is no bidder-supplied destination account, so settlement
    // can never be redirected even if a malicious client appended extra accounts.
    assert_eq!(metas.len(), 6, "Settle must not expose any bidder-controlled destination account");
    let keys: Vec<Pubkey> = metas.iter().map(|m| m.pubkey).collect();
    assert_eq!(keys, vec![caller, global_state, vault, burn_address, win_record, system_program_id()]);
}

#[test]
fn test_treasury_withdraw_race_with_pending_settle() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = new_funded_keypair(&mut svm, 10_000_000_000);
    let bidder1 = new_funded_keypair(&mut svm, 10_000_000_000);
    let bidder2 = new_funded_keypair(&mut svm, 10_000_000_000);

    let t0 = 1_000;
    set_clock_ts(&mut svm, t0);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin.pubkey(), 1_000_000)).unwrap();

    // Round 1: full challenge + settle, so treasury_balance is nonzero going in.
    let prev_top_bidder_41 = get_global_state(&svm, global_state).top_bidder;
    send(
        &mut svm,
        &bidder1,
        ix_challenge(global_state, vault, bidder1.pubkey(), prev_top_bidder_41, 1_050_000),
    )
    .unwrap();
    let gs = get_global_state(&svm, global_state);
    set_clock_ts(&mut svm, gs.window_end_ts);
    send(&mut svm, &bidder1, ix_settle(global_state, vault, bidder1.pubkey(), INCINERATOR, win_record_pda(gs.holder_count))).unwrap();

    let gs = get_global_state(&svm, global_state);
    let treasury_balance_after_round_1 = gs.treasury_balance;
    assert!(treasury_balance_after_round_1 > 0);

    // Round 2: open a new challenge (window closes but is NOT settled yet) -
    // this escrow must never be reachable via withdraw_treasury.
    let t1 = gs.window_end_ts + 100;
    set_clock_ts(&mut svm, t1);
    let bid2 = min_raise_amount(gs.current_price, gs.min_raise_bps);
    let prev_top_bidder_42 = get_global_state(&svm, global_state).top_bidder;
    send(&mut svm, &bidder2, ix_challenge(global_state, vault, bidder2.pubkey(), prev_top_bidder_42, bid2)).unwrap();
    let gs = get_global_state(&svm, global_state);
    set_clock_ts(&mut svm, gs.window_end_ts); // window closed, pending settlement

    // withdraw_treasury before settle: must succeed but only move the prior
    // round's treasury_balance, never round 2's in-flight escrow.
    let res = send(&mut svm, &admin, ix_withdraw_treasury(global_state, vault, admin.pubkey(), treasury));
    assert!(res.is_ok(), "{:?}", res.err());

    let treasury_lamports = svm.get_balance(&treasury).unwrap();
    assert_eq!(treasury_lamports, treasury_balance_after_round_1);

    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.treasury_balance, 0);
    assert_eq!(gs.escrowed_amount, bid2, "the pending round's escrow must be untouched by the withdrawal");
    assert_vault_invariant(&svm, vault, &gs);
}

#[test]
fn test_settle_cannot_be_used_to_drain_vault_below_escrow() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = new_funded_keypair(&mut svm, 10_000_000_000);
    let wallets: Vec<Keypair> = (0..4).map(|_| new_funded_keypair(&mut svm, 100_000_000_000)).collect();

    let mut t = 1_000i64;
    set_clock_ts(&mut svm, t);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin.pubkey(), 1_000_000)).unwrap();
    let gs = get_global_state(&svm, global_state);
    assert_vault_invariant(&svm, vault, &gs);

    let mut seed: u64 = 0xDEAD_BEEFu64;

    for round in 0..15 {
        let gs = get_global_state(&svm, global_state);
        let base = gs.current_price;
        // A cold-open self-challenge by the current holder is now rejected
        // at the contract level, so skip past that index rather than risk
        // this always-must-succeed step landing on it.
        let mut opener_idx = (lcg_next(&mut seed) as usize) % wallets.len();
        if wallets[opener_idx].pubkey() == gs.holder {
            opener_idx = (opener_idx + 1) % wallets.len();
        }
        let opener = &wallets[opener_idx];
        let open_bid = min_raise_amount(base, gs.min_raise_bps);
        let prev_top_bidder_43 = get_global_state(&svm, global_state).top_bidder;
        let res = send(&mut svm, opener, ix_challenge(global_state, vault, opener.pubkey(), prev_top_bidder_43, open_bid));
        assert!(res.is_ok(), "round {round} open failed: {:?}", res.err());
        let gs = get_global_state(&svm, global_state);
        assert_vault_invariant(&svm, vault, &gs);

        let mut bidder_idx = opener_idx;
        let mut bid_amount = open_bid;
        let num_outbids = lcg_next(&mut seed) % 2;
        for _ in 0..num_outbids {
            let gs = get_global_state(&svm, global_state);
            let mut next_idx = (lcg_next(&mut seed) as usize) % wallets.len();
            if next_idx == bidder_idx {
                next_idx = (next_idx + 1) % wallets.len();
            }
            let next_bidder = &wallets[next_idx];
            let next_bid = min_raise_amount(bid_amount, gs.min_raise_bps);
            let prev_top_bidder_44 = get_global_state(&svm, global_state).top_bidder;
            let res = send(
                &mut svm,
                next_bidder,
                ix_challenge(global_state, vault, next_bidder.pubkey(), prev_top_bidder_44, next_bid),
            );
            assert!(res.is_ok(), "round {round} outbid failed: {:?}", res.err());
            let gs = get_global_state(&svm, global_state);
            assert_vault_invariant(&svm, vault, &gs);
            bidder_idx = next_idx;
            bid_amount = next_bid;
        }

        let gs = get_global_state(&svm, global_state);
        t = gs.window_end_ts;
        set_clock_ts(&mut svm, t);
        let winner = &wallets[bidder_idx];
        let res = send(&mut svm, winner, ix_settle(global_state, vault, winner.pubkey(), INCINERATOR, win_record_pda(gs.holder_count)));
        assert!(res.is_ok(), "round {round} settle failed: {:?}", res.err());
        let gs = get_global_state(&svm, global_state);
        assert_vault_invariant(&svm, vault, &gs);

        // Every third round, drain the treasury balance and confirm the
        // escrow backing the round that just settled (or the next one's
        // in-flight bids) is never reachable through the withdrawal.
        if round % 3 == 2 {
            let gs_before = get_global_state(&svm, global_state);
            let treasury_before = svm.get_balance(&treasury).unwrap_or(0);
            let res = send(&mut svm, &admin, ix_withdraw_treasury(global_state, vault, admin.pubkey(), treasury));
            assert!(res.is_ok(), "{:?}", res.err());
            let treasury_after = svm.get_balance(&treasury).unwrap();
            assert_eq!(treasury_after - treasury_before, gs_before.treasury_balance);
            let gs_after = get_global_state(&svm, global_state);
            assert_eq!(gs_after.treasury_balance, 0);
            assert_eq!(gs_after.escrowed_amount, gs_before.escrowed_amount);
            assert_vault_invariant(&svm, vault, &gs_after);
        }

        t += 1;
        set_clock_ts(&mut svm, t);
    }
}

// ---------------------------------------------------------------------------
// 16. Adversarial fuzz-lite
// ---------------------------------------------------------------------------

#[test]
fn test_random_bid_sequence_invariant_holds() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let wallets: Vec<Keypair> = (0..5).map(|_| new_funded_keypair(&mut svm, 200_000_000_000)).collect();

    let mut t = 1_000i64;
    set_clock_ts(&mut svm, t);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();

    let mut seed: u64 = 0xC0FFEEu64;
    let mut last_price = 1_000_000u64;

    for round in 0..20 {
        let gs = get_global_state(&svm, global_state);
        let base = gs.current_price;

        // Occasionally attempt an invalid (one-lamport-too-low) cold-open bid
        // first: must fail cleanly and move nothing.
        let r_invalid = lcg_next(&mut seed);
        if r_invalid.is_multiple_of(4) {
            // Must fail with `BidTooLow` specifically, not `CannotChallengeSelf`
            // -- skip past the current holder's index so this stays a clean
            // too-low-bid rejection.
            let mut invalid_bidder_idx = (r_invalid as usize / 4) % wallets.len();
            if wallets[invalid_bidder_idx].pubkey() == gs.holder {
                invalid_bidder_idx = (invalid_bidder_idx + 1) % wallets.len();
            }
            let bidder = &wallets[invalid_bidder_idx];
            let bad_bid = min_raise_amount(base, gs.min_raise_bps) - 1;
            let prev_top_bidder_45 = get_global_state(&svm, global_state).top_bidder;
            let res = send(&mut svm, bidder, ix_challenge(global_state, vault, bidder.pubkey(), prev_top_bidder_45, bad_bid));
            assert_err_contains(&res, "BidTooLow");
            let gs_after = get_global_state(&svm, global_state);
            assert_eq!(gs_after.current_price, base, "rejected bid must not move price");
            assert_vault_invariant(&svm, vault, &gs_after);
        }

        // Valid cold open. A cold-open self-challenge by the current holder
        // is now rejected at the contract level, so skip past that index
        // rather than risk this always-must-succeed step landing on it.
        let mut opener_idx = (lcg_next(&mut seed) as usize) % wallets.len();
        if wallets[opener_idx].pubkey() == gs.holder {
            opener_idx = (opener_idx + 1) % wallets.len();
        }
        let opener = &wallets[opener_idx];
        let open_bid = min_raise_amount(base, gs.min_raise_bps);
        let prev_top_bidder_46 = get_global_state(&svm, global_state).top_bidder;
        let res = send(&mut svm, opener, ix_challenge(global_state, vault, opener.pubkey(), prev_top_bidder_46, open_bid));
        assert!(res.is_ok(), "round {round} open failed: {:?}", res.err());
        let gs = get_global_state(&svm, global_state);
        assert_vault_invariant(&svm, vault, &gs);

        // 0-2 further outbids inside the same window.
        let num_outbids = lcg_next(&mut seed) % 3;
        let mut current_bidder_idx = opener_idx;
        let mut current_bid = open_bid;
        for _ in 0..num_outbids {
            let gs = get_global_state(&svm, global_state);
            let mut next_idx = (lcg_next(&mut seed) as usize) % wallets.len();
            if next_idx == current_bidder_idx {
                next_idx = (next_idx + 1) % wallets.len();
            }
            let next_bidder = &wallets[next_idx];
            let next_bid = min_raise_amount(current_bid, gs.min_raise_bps);
            let prev_top_bidder_47 = get_global_state(&svm, global_state).top_bidder;
            let res = send(
                &mut svm,
                next_bidder,
                ix_challenge(global_state, vault, next_bidder.pubkey(), prev_top_bidder_47, next_bid),
            );
            assert!(res.is_ok(), "round {round} outbid failed: {:?}", res.err());
            let gs = get_global_state(&svm, global_state);
            assert_vault_invariant(&svm, vault, &gs);
            current_bidder_idx = next_idx;
            current_bid = next_bid;
        }

        let gs = get_global_state(&svm, global_state);
        t = gs.window_end_ts;
        set_clock_ts(&mut svm, t);
        let winner = &wallets[current_bidder_idx];
        let res = send(&mut svm, winner, ix_settle(global_state, vault, winner.pubkey(), INCINERATOR, win_record_pda(gs.holder_count)));
        assert!(res.is_ok(), "round {round} settle failed: {:?}", res.err());

        let gs = get_global_state(&svm, global_state);
        assert!(gs.current_price >= last_price, "current_price must never decrease: {last_price} -> {}", gs.current_price);
        last_price = gs.current_price;
        assert_vault_invariant(&svm, vault, &gs);

        t += 1;
        set_clock_ts(&mut svm, t);
    }
}

// ---------------------------------------------------------------------------
// 17. claim_refund() adversarial cases
// ---------------------------------------------------------------------------

#[test]
fn test_claim_refund_happy_path_pays_exact_amount_and_closes_account() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let bidder1 = new_funded_keypair(&mut svm, 10_000_000_000);
    let bidder2 = new_funded_keypair(&mut svm, 10_000_000_000);

    set_clock_ts(&mut svm, 1_000);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();
    send(
        &mut svm,
        &bidder1,
        ix_challenge(global_state, vault, bidder1.pubkey(), Pubkey::default(), 1_050_000),
    )
    .unwrap();
    send(
        &mut svm,
        &bidder2,
        ix_challenge(global_state, vault, bidder2.pubkey(), bidder1.pubkey(), 1_102_500),
    )
    .unwrap();

    let gs_before = get_global_state(&svm, global_state);
    let bidder1_balance_before = svm.get_balance(&bidder1.pubkey()).unwrap();
    let pending_refund_rent = svm.minimum_balance_for_rent_exemption(PendingRefund::SPACE);

    let res = send(&mut svm, &bidder1, ix_claim_refund(bidder1.pubkey()));
    assert!(res.is_ok(), "{:?}", res.err());

    let bidder1_balance_after = svm.get_balance(&bidder1.pubkey()).unwrap();
    // bidder1 itself paid the tx fee here, so allow for that (bounded, unlike
    // a silent short-payment which would be far larger than any fee).
    let received = bidder1_balance_after - bidder1_balance_before;
    assert!(
        received > 1_050_000 && received <= 1_050_000 + pending_refund_rent,
        "expected refund + reclaimed rent minus tx fee, got {received}"
    );

    assert!(
        get_pending_refund(&svm, pending_refund_pda(bidder1.pubkey())).is_none(),
        "refund account must be closed after claim"
    );

    // The vault must have paid out exactly the refund amount (the rent
    // reclaimed on claim came out of the pending_refund PDA itself, not the
    // vault) - global_state's own escrow/treasury bookkeeping is untouched
    // by a claim, since that lamport movement never touched the vault.
    let gs_after = get_global_state(&svm, global_state);
    assert_eq!(gs_after.escrowed_amount, gs_before.escrowed_amount);
    assert_eq!(gs_after.treasury_balance, gs_before.treasury_balance);
    assert_vault_invariant(&svm, vault, &gs_after);
}

#[test]
fn test_claim_refund_twice_fails_second_time() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let bidder1 = new_funded_keypair(&mut svm, 10_000_000_000);
    let bidder2 = new_funded_keypair(&mut svm, 10_000_000_000);

    set_clock_ts(&mut svm, 1_000);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();
    send(
        &mut svm,
        &bidder1,
        ix_challenge(global_state, vault, bidder1.pubkey(), Pubkey::default(), 1_050_000),
    )
    .unwrap();
    send(
        &mut svm,
        &bidder2,
        ix_challenge(global_state, vault, bidder2.pubkey(), bidder1.pubkey(), 1_102_500),
    )
    .unwrap();

    let res = send(&mut svm, &bidder1, ix_claim_refund(bidder1.pubkey()));
    assert!(res.is_ok(), "{:?}", res.err());

    let balance_after_first_claim = svm.get_balance(&bidder1.pubkey()).unwrap();

    // Second claim attempt on the now-closed account: must fail cleanly
    // (Anchor's own account-deserialization safety - a closed account's
    // discriminator no longer matches `PendingRefund`), not pay out
    // anything, and not panic.
    let res = send(&mut svm, &bidder1, ix_claim_refund(bidder1.pubkey()));
    assert!(res.is_err(), "second claim must fail");

    // No stray lamports moved on the failed attempt (aside from the tx fee
    // bidder1 paid trying).
    let balance_after_second_attempt = svm.get_balance(&bidder1.pubkey()).unwrap();
    assert!(
        balance_after_second_attempt <= balance_after_first_claim,
        "a failed double-claim must never increase the claimant's balance"
    );

    let gs = get_global_state(&svm, global_state);
    assert_vault_invariant(&svm, vault, &gs);
}

#[test]
fn test_claim_refund_with_nothing_pending_fails_cleanly() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let never_outbid_anyone = new_funded_keypair(&mut svm, 10_000_000_000);

    set_clock_ts(&mut svm, 1_000);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();

    let balance_before = svm.get_balance(&never_outbid_anyone.pubkey()).unwrap();

    // This account's `PendingRefund` PDA was never created - there is
    // nothing to deserialize. Must fail cleanly (an ordinary Anchor account
    // error, not a panic) and pay out nothing.
    let res = send(&mut svm, &never_outbid_anyone, ix_claim_refund(never_outbid_anyone.pubkey()));
    assert!(res.is_err(), "claiming with nothing pending must fail");

    let balance_after = svm.get_balance(&never_outbid_anyone.pubkey()).unwrap();
    assert!(balance_after <= balance_before, "a failed claim must never increase the claimant's balance");

    let gs = get_global_state(&svm, global_state);
    assert_vault_invariant(&svm, vault, &gs);
}

#[test]
fn test_claim_refund_by_someone_else_fails() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let bidder1 = new_funded_keypair(&mut svm, 10_000_000_000);
    let bidder2 = new_funded_keypair(&mut svm, 10_000_000_000);
    let attacker = new_funded_keypair(&mut svm, 10_000_000_000);

    set_clock_ts(&mut svm, 1_000);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();
    send(
        &mut svm,
        &bidder1,
        ix_challenge(global_state, vault, bidder1.pubkey(), Pubkey::default(), 1_050_000),
    )
    .unwrap();
    send(
        &mut svm,
        &bidder2,
        ix_challenge(global_state, vault, bidder2.pubkey(), bidder1.pubkey(), 1_102_500),
    )
    .unwrap();

    // `attacker` signs the transaction, but the instruction is built with
    // `pending_refund` pointed at bidder1's PDA while `claimant` is rewritten
    // to the attacker's own key. The on-chain `constraint = pending_refund.bidder
    // == claimant.key()` check must reject this since `attacker.key() !=
    // bidder1.pubkey()`.
    let mut ix = ix_claim_refund(bidder1.pubkey());
    ix.accounts[0].pubkey = attacker.pubkey();
    let res = send(&mut svm, &attacker, ix);
    assert_err_contains(&res, "NothingToRefund");

    // bidder1's refund must be completely untouched.
    let refund = get_pending_refund(&svm, pending_refund_pda(bidder1.pubkey())).expect("refund should still be pending");
    assert_eq!(refund.amount, 1_050_000);
    let gs = get_global_state(&svm, global_state);
    assert_vault_invariant(&svm, vault, &gs);
}

#[test]
fn test_two_distinct_unclaimed_refunds_tracked_independently() {
    // The concurrency case that motivates the per-bidder-PDA design over a
    // single embedded field: under the old inline-refund design there was
    // never more than one outstanding refund at a time (each challenge
    // always fully resolved the previous one before returning). Pull-based
    // refunds break that: bidder A can go unclaimed across many subsequent
    // outbids by *other* bidders. This proves two distinct bidders' refunds
    // coexist correctly, with no cross-contamination, and can be claimed
    // independently in either order.
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let a = new_funded_keypair(&mut svm, 10_000_000_000);
    let b = new_funded_keypair(&mut svm, 10_000_000_000);
    let c = new_funded_keypair(&mut svm, 10_000_000_000);

    set_clock_ts(&mut svm, 1_000);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();

    // a opens, b outbids a (a now pending, unclaimed), c outbids b (b now
    // pending too) - a's refund is still sitting there, unclaimed, the
    // whole time. Two distinct pending refunds coexist.
    let bid_a = 1_050_000u64;
    send(&mut svm, &a, ix_challenge(global_state, vault, a.pubkey(), Pubkey::default(), bid_a)).unwrap();
    let bid_b = 1_102_500u64;
    send(&mut svm, &b, ix_challenge(global_state, vault, b.pubkey(), a.pubkey(), bid_b)).unwrap();
    let bid_c = 1_157_625u64;
    send(&mut svm, &c, ix_challenge(global_state, vault, c.pubkey(), b.pubkey(), bid_c)).unwrap();

    let refund_a = get_pending_refund(&svm, pending_refund_pda(a.pubkey())).expect("a's refund must still be pending");
    let refund_b = get_pending_refund(&svm, pending_refund_pda(b.pubkey())).expect("b's refund must be pending");
    assert_eq!(refund_a.amount, bid_a);
    assert_eq!(refund_b.amount, bid_b);

    let gs = get_global_state(&svm, global_state);
    assert_vault_invariant(&svm, vault, &gs);

    // Claim b's refund first (out of order relative to when it became
    // pending) - must not disturb a's still-pending refund at all.
    let b_balance_before = svm.get_balance(&b.pubkey()).unwrap();
    let res = send(&mut svm, &b, ix_claim_refund(b.pubkey()));
    assert!(res.is_ok(), "{:?}", res.err());
    let b_balance_after = svm.get_balance(&b.pubkey()).unwrap();
    assert!(b_balance_after > b_balance_before, "b must have received its refund");
    assert!(
        get_pending_refund(&svm, pending_refund_pda(b.pubkey())).is_none(),
        "b's refund account must be closed"
    );

    let refund_a_after_b_claims = get_pending_refund(&svm, pending_refund_pda(a.pubkey()))
        .expect("a's refund must be completely unaffected by b's claim");
    assert_eq!(refund_a_after_b_claims.amount, bid_a, "a's refund amount must be untouched");

    let gs = get_global_state(&svm, global_state);
    assert_vault_invariant(&svm, vault, &gs);

    // a can still claim afterward, for exactly its own original amount.
    let a_balance_before = svm.get_balance(&a.pubkey()).unwrap();
    let res = send(&mut svm, &a, ix_claim_refund(a.pubkey()));
    assert!(res.is_ok(), "{:?}", res.err());
    let a_balance_after = svm.get_balance(&a.pubkey()).unwrap();
    assert!(a_balance_after > a_balance_before, "a must have received its own refund");
    assert!(get_pending_refund(&svm, pending_refund_pda(a.pubkey())).is_none());

    let gs = get_global_state(&svm, global_state);
    assert_vault_invariant(&svm, vault, &gs);
}

#[test]
fn test_pending_refund_rent_exemption_maintained_and_reclaimed_on_claim() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    let bidder1 = new_funded_keypair(&mut svm, 10_000_000_000);
    let bidder2 = new_funded_keypair(&mut svm, 10_000_000_000);

    set_clock_ts(&mut svm, 1_000);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();
    send(
        &mut svm,
        &bidder1,
        ix_challenge(global_state, vault, bidder1.pubkey(), Pubkey::default(), 1_050_000),
    )
    .unwrap();
    send(
        &mut svm,
        &bidder2,
        ix_challenge(global_state, vault, bidder2.pubkey(), bidder1.pubkey(), 1_102_500),
    )
    .unwrap();

    let pda = pending_refund_pda(bidder1.pubkey());
    let rent = svm.minimum_balance_for_rent_exemption(PendingRefund::SPACE);
    let pda_lamports = svm.get_balance(&pda).unwrap();
    assert!(pda_lamports >= rent, "pending_refund PDA must be rent-exempt");
    assert_eq!(pda_lamports, rent + 1_050_000, "PDA balance must be exactly rent + owed amount");

    let bidder1_balance_before = svm.get_balance(&bidder1.pubkey()).unwrap();
    let res = send(&mut svm, &bidder1, ix_claim_refund(bidder1.pubkey()));
    assert!(res.is_ok(), "{:?}", res.err());
    let bidder1_balance_after = svm.get_balance(&bidder1.pubkey()).unwrap();

    // bidder1 must have actually received the reclaimed rent, not just the
    // bid amount (minus the tx fee it itself paid to submit the claim).
    let received = bidder1_balance_after - bidder1_balance_before;
    assert!(
        received > 1_050_000,
        "claimant must receive more than the bare refund amount (the reclaimed rent), got {received}"
    );
    let pda_after = svm.get_account(&pda);
    assert!(
        pda_after.is_none() || pda_after.unwrap().lamports == 0,
        "pending_refund PDA must be fully drained on close"
    );
}

// ===========================================================================
// Phase 8 — $TOGGLD token launch
// ===========================================================================
//
// LiteSVM ships the classic SPL Token + Associated Token programs (see
// `litesvm::programs::load_default_programs`) but no mints or token accounts,
// and the Phase 8 instructions take real `Account<Mint>` / `Account<TokenAccount>`
// args — so the helpers below hand-pack the SPL byte layouts (`Mint` = 82 bytes,
// `Account` = 165 bytes) directly rather than pulling `spl-token` in as a
// dev-dependency just to call `pack`/`unpack`.
//
// The `swap2` CPI happy path is deliberately NOT exercised here — LiteSVM has
// no DBC program loaded — so `burn_tokens()` coverage is revert-paths only, all
// of which trip before the swap CPI is ever reached (see PHASE_8_PLAN §7).

const SPL_TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SPL_ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

/// Offset of `TokenConfig.max_slippage_bps` in the account's raw bytes:
/// 8 (discriminator) + 32 toggld_mint + 1 burn_vault_bump + 1 burn_vault_ata_bump
/// + 1 venue + 32 pool_address + 32 venue_config = 107.
const TOKEN_CONFIG_MAX_SLIPPAGE_OFFSET: usize = 107;

/// Offset of `TokenConfig.venue` in the account's raw bytes:
/// 8 (discriminator) + 32 toggld_mint + 1 burn_vault_bump + 1 burn_vault_ata_bump = 42.
const TOKEN_CONFIG_VENUE_OFFSET: usize = 42;

fn spl_token_id() -> Pubkey {
    SPL_TOKEN_PROGRAM.parse().unwrap()
}
fn ata_program_id() -> Pubkey {
    SPL_ATA_PROGRAM.parse().unwrap()
}

fn token_config_pda() -> Pubkey {
    Pubkey::find_program_address(&[TOKEN_CONFIG_SEED], &toggld::id()).0
}
fn burn_vault_pda() -> Pubkey {
    Pubkey::find_program_address(&[BURN_VAULT_SEED], &toggld::id()).0
}
fn team_vesting_pda() -> Pubkey {
    Pubkey::find_program_address(&[TEAM_VESTING_SEED], &toggld::id()).0
}

/// Canonical associated-token-account address for `owner`/`mint` under the
/// classic SPL Token program — the address every `anchor_spl` `associated_token`
/// constraint in the Phase 8 instructions derives and checks against.
fn ata_for(owner: Pubkey, mint: Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), spl_token_id().as_ref(), mint.as_ref()],
        &ata_program_id(),
    )
    .0
}

/// Injects a fully-initialized classic SPL `Mint` (82-byte layout) with no mint
/// or freeze authority.
fn create_mint(svm: &mut LiteSVM, mint: Pubkey, decimals: u8, supply: u64) {
    let mut data = vec![0u8; 82];
    // mint_authority: COption::None  -> tag bytes [0..4] already zero
    data[36..44].copy_from_slice(&supply.to_le_bytes());
    data[44] = decimals;
    data[45] = 1; // is_initialized
                  // freeze_authority: COption::None -> tag bytes [46..50] already zero
    svm.set_account(
        mint,
        SvmAccount {
            lamports: svm.minimum_balance_for_rent_exemption(82),
            data,
            owner: spl_token_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

/// Injects an initialized classic SPL token account (165-byte layout) holding
/// `amount` of `mint`, owned by `authority`. Used for the pre-existing
/// `admin_toggld_ata` that `init_team_vesting()` moves the team allocation out
/// of — Anchor won't `init` that one, it must already exist and hold a balance.
fn create_token_account(
    svm: &mut LiteSVM,
    addr: Pubkey,
    mint: Pubkey,
    authority: Pubkey,
    amount: u64,
) {
    let mut data = vec![0u8; 165];
    data[0..32].copy_from_slice(mint.as_ref());
    data[32..64].copy_from_slice(authority.as_ref());
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    // delegate: COption::None (72..76)
    data[108] = 1; // AccountState::Initialized
                   // is_native: COption::None (109..113); delegated_amount 0; close_authority None
    svm.set_account(
        addr,
        SvmAccount {
            lamports: svm.minimum_balance_for_rent_exemption(165),
            data,
            owner: spl_token_id(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

/// Minimal stand-in for a Meteora DBC `VirtualPool` (or DAMM v2 `Pool`) account:
/// a byte blob large enough to hold the `sqrt_price` `u128` at the venue's
/// offset, which is all `burn_tokens()`'s on-chain expected-out floor reads
/// (PHASE_8_PLAN §4A.8). `sqrt_price` is Meteora Q64.64.
fn create_fake_pool(svm: &mut LiteSVM, addr: Pubkey, sqrt_price: u128, sqrt_price_offset: usize) {
    let len = sqrt_price_offset + 16;
    let mut data = vec![0u8; len];
    data[sqrt_price_offset..sqrt_price_offset + 16].copy_from_slice(&sqrt_price.to_le_bytes());
    svm.set_account(
        addr,
        SvmAccount {
            lamports: svm.minimum_balance_for_rent_exemption(len),
            data,
            owner: DBC_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

/// DBC `VirtualPool.sqrt_price` byte offset (matches `burn_tokens.rs`).
const DBC_POOL_SQRT_PRICE_OFFSET: usize = 280;

/// Reads the `amount` field (offset 64, `u64` LE) straight out of a classic SPL
/// token account's raw bytes.
fn token_account_amount(svm: &LiteSVM, addr: Pubkey) -> u64 {
    let acct = svm.get_account(&addr).expect("token account should exist");
    let mut b = [0u8; 8];
    b.copy_from_slice(&acct.data[64..72]);
    u64::from_le_bytes(b)
}

fn set_lamports(svm: &mut LiteSVM, key: Pubkey, lamports: u64) {
    let mut acct = svm.get_account(&key).expect("account should exist");
    acct.lamports = lamports;
    svm.set_account(key, acct).unwrap();
}

fn patch_account_data(svm: &mut LiteSVM, key: Pubkey, offset: usize, bytes: &[u8]) {
    let mut acct = svm.get_account(&key).expect("account should exist");
    acct.data[offset..offset + bytes.len()].copy_from_slice(bytes);
    svm.set_account(key, acct).unwrap();
}

fn get_token_config(svm: &LiteSVM) -> TokenConfig {
    let a = svm
        .get_account(&token_config_pda())
        .expect("token_config should exist");
    TokenConfig::try_deserialize(&mut a.data.as_slice()).expect("TokenConfig should deserialize")
}

fn get_team_vesting(svm: &LiteSVM) -> TeamVesting {
    let a = svm
        .get_account(&team_vesting_pda())
        .expect("team_vesting should exist");
    TeamVesting::try_deserialize(&mut a.data.as_slice()).expect("TeamVesting should deserialize")
}

/// `new_svm()` + a funded `admin` keypair + `initialize()` already run, clock
/// parked at t0 = 1_000. Returns the admin keypair — the only signer the Phase 8
/// admin-gated instructions accept.
fn init_with_admin(
    svm: &mut LiteSVM,
    global_state: Pubkey,
    vault: Pubkey,
    payer: &Keypair,
) -> Keypair {
    let admin = new_funded_keypair(svm, 100_000_000_000);
    let treasury = Keypair::new().pubkey();
    set_clock_ts(svm, 1_000);
    send(
        svm,
        payer,
        ix_initialize(
            global_state,
            vault,
            payer.pubkey(),
            treasury,
            admin.pubkey(),
            1_000_000,
        ),
    )
    .unwrap();
    admin
}

fn fund_admin_toggld_ata(svm: &mut LiteSVM, admin: Pubkey, mint: Pubkey, amount: u64) {
    create_token_account(svm, ata_for(admin, mint), mint, admin, amount);
}

// ---------------------------------------------------------------------------
// Phase 8 instruction builders
// ---------------------------------------------------------------------------

fn ix_setup_token(
    admin: Pubkey,
    global_state: Pubkey,
    mint: Pubkey,
    venue: u8,
    pool_address: Pubkey,
    venue_config: Pubkey,
    max_slippage_bps: u16,
) -> Instruction {
    let burn_vault = burn_vault_pda();
    Instruction::new_with_bytes(
        toggld::id(),
        &toggld::instruction::SetupToken {
            toggld_mint: mint,
            venue,
            pool_address,
            venue_config,
            max_slippage_bps,
        }
        .data(),
        toggld::accounts::SetupToken {
            admin,
            global_state,
            token_config: token_config_pda(),
            burn_vault,
            mint,
            burn_vault_toggld_ata: ata_for(burn_vault, mint),
            token_program: spl_token_id(),
            associated_token_program: ata_program_id(),
            system_program: system_program_id(),
        }
        .to_account_metas(None),
    )
}

fn ix_promote_burn_venue(
    admin: Pubkey,
    global_state: Pubkey,
    new_venue: u8,
    new_pool_address: Pubkey,
    new_venue_config: Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        toggld::id(),
        &toggld::instruction::PromoteBurnVenue {
            new_venue,
            new_pool_address,
            new_venue_config,
        }
        .data(),
        toggld::accounts::PromoteBurnVenue {
            admin,
            global_state,
            token_config: token_config_pda(),
        }
        .to_account_metas(None),
    )
}

fn ix_init_team_vesting(
    admin: Pubkey,
    global_state: Pubkey,
    mint: Pubkey,
    total_amount: u64,
    start_ts: i64,
    duration_secs: i64,
) -> Instruction {
    let team_vesting = team_vesting_pda();
    Instruction::new_with_bytes(
        toggld::id(),
        &toggld::instruction::InitTeamVesting {
            total_amount,
            start_ts,
            duration_secs,
        }
        .data(),
        toggld::accounts::InitTeamVesting {
            admin,
            global_state,
            team_vesting,
            mint,
            team_vesting_ata: ata_for(team_vesting, mint),
            admin_toggld_ata: ata_for(admin, mint),
            token_program: spl_token_id(),
            associated_token_program: ata_program_id(),
            system_program: system_program_id(),
        }
        .to_account_metas(None),
    )
}

fn ix_claim_vested(admin: Pubkey, global_state: Pubkey, mint: Pubkey) -> Instruction {
    let team_vesting = team_vesting_pda();
    Instruction::new_with_bytes(
        toggld::id(),
        &toggld::instruction::ClaimVested {}.data(),
        toggld::accounts::ClaimVested {
            admin,
            global_state,
            team_vesting,
            mint,
            team_vesting_ata: ata_for(team_vesting, mint),
            admin_toggld_ata: ata_for(admin, mint),
            token_program: spl_token_id(),
            associated_token_program: ata_program_id(),
        }
        .to_account_metas(None),
    )
}

/// Full `burn_tokens` instruction builder. `venue_config` is `Some` for DBC
/// (address-checked) / `None` for DAMM v2; `dbc_program` selects the venue
/// program; `base_vault`/`quote_vault` are the pool token vaults the on-chain
/// expected-out floor reads (PHASE_8_PLAN §4A.7/§4A.8).
#[allow(clippy::too_many_arguments)]
fn ix_burn_tokens_full(
    caller: Pubkey,
    mint: Pubkey,
    pool_address: Pubkey,
    venue_config: Option<Pubkey>,
    dbc_program: Pubkey,
    base_vault: Pubkey,
    quote_vault: Pubkey,
    min_out: u64,
) -> Instruction {
    let burn_vault = burn_vault_pda();
    Instruction::new_with_bytes(
        toggld::id(),
        &toggld::instruction::BurnTokens { min_out }.data(),
        toggld::accounts::BurnTokens {
            caller,
            token_config: token_config_pda(),
            burn_vault,
            mint,
            wsol_mint: WSOL_MINT,
            burn_vault_toggld_ata: ata_for(burn_vault, mint),
            burn_vault_wsol_ata: ata_for(burn_vault, WSOL_MINT),
            dbc_pool_authority: Pubkey::new_unique(),
            dbc_config: venue_config,
            dbc_pool: pool_address,
            dbc_base_vault: base_vault,
            dbc_quote_vault: quote_vault,
            dbc_event_authority: Pubkey::new_unique(),
            dbc_program,
            token_program: spl_token_id(),
            associated_token_program: ata_program_id(),
            system_program: system_program_id(),
        }
        .to_account_metas(None),
    )
}

/// Convenience wrapper for the common DBC-venue case with throwaway pool vaults
/// (fine for revert-path tests that trip before the expected-out floor reads).
fn ix_burn_tokens(
    caller: Pubkey,
    mint: Pubkey,
    pool_address: Pubkey,
    venue_config: Pubkey,
    min_out: u64,
) -> Instruction {
    ix_burn_tokens_full(
        caller,
        mint,
        pool_address,
        Some(venue_config),
        DBC_PROGRAM_ID,
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        min_out,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_setup_token(
    svm: &mut LiteSVM,
    global_state: Pubkey,
    admin: &Keypair,
    mint: Pubkey,
    venue: u8,
    pool_address: Pubkey,
    venue_config: Pubkey,
    max_slippage_bps: u16,
) {
    send(
        svm,
        admin,
        ix_setup_token(
            admin.pubkey(),
            global_state,
            mint,
            venue,
            pool_address,
            venue_config,
            max_slippage_bps,
        ),
    )
    .unwrap();
}

fn setup_vesting(
    svm: &mut LiteSVM,
    global_state: Pubkey,
    admin: &Keypair,
    mint: Pubkey,
    total: u64,
    start_ts: i64,
    duration_secs: i64,
) {
    fund_admin_toggld_ata(svm, admin.pubkey(), mint, total);
    send(
        svm,
        admin,
        ix_init_team_vesting(admin.pubkey(), global_state, mint, total, start_ts, duration_secs),
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// 18. setup_token()
// ---------------------------------------------------------------------------

#[test]
fn test_setup_token_happy_path_wires_burn_vault_and_config() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = init_with_admin(&mut svm, global_state, vault, &payer);

    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);
    let pool_address = Pubkey::new_unique();
    let venue_config = Pubkey::new_unique();

    let res = send(
        &mut svm,
        &admin,
        ix_setup_token(
            admin.pubkey(),
            global_state,
            mint,
            TokenConfig::VENUE_DBC_CURVE,
            pool_address,
            venue_config,
            300,
        ),
    );
    assert!(res.is_ok(), "{:?}", res.err());

    let tc = get_token_config(&svm);
    assert_eq!(tc.toggld_mint, mint);
    assert_eq!(tc.venue, TokenConfig::VENUE_DBC_CURVE);
    assert_eq!(tc.pool_address, pool_address);
    assert_eq!(tc.venue_config, venue_config);
    assert_eq!(tc.max_slippage_bps, 300);
    assert_eq!(tc.total_tokens_burned, 0);
    assert_eq!(
        tc.burn_vault_bump,
        Pubkey::find_program_address(&[BURN_VAULT_SEED], &toggld::id()).1
    );

    // burn_vault must be a plain, 0-byte, System-Program-owned lamport account
    // holding exactly its rent reserve — same shape as `vault`.
    let bv = svm
        .get_account(&burn_vault_pda())
        .expect("burn_vault should be created");
    assert_eq!(
        bv.owner,
        system_program_id(),
        "burn_vault must stay System-owned like `vault`"
    );
    assert!(
        bv.data.is_empty(),
        "burn_vault must carry no account data"
    );
    assert_eq!(bv.lamports, svm.minimum_balance_for_rent_exemption(0));

    // settle()'s burn leg is repointed with no settle.rs change.
    let gs = get_global_state(&svm, global_state);
    assert_eq!(
        gs.burn_address,
        burn_vault_pda(),
        "setup_token must repoint global_state.burn_address to burn_vault"
    );

    // burn_vault's $TOGGLD ATA exists, owned by the burn_vault PDA, empty.
    let ata = ata_for(burn_vault_pda(), mint);
    let ata_acct = svm.get_account(&ata).expect("burn_vault $TOGGLD ATA created");
    assert_eq!(ata_acct.owner, spl_token_id());
    assert_eq!(token_account_amount(&svm, ata), 0);

    assert_vault_invariant(&svm, vault, &gs);
}

#[test]
fn test_setup_token_unauthorized_fails() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let _admin = init_with_admin(&mut svm, global_state, vault, &payer);
    let attacker = new_funded_keypair(&mut svm, 100_000_000_000);

    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);

    let res = send(
        &mut svm,
        &attacker,
        ix_setup_token(
            attacker.pubkey(),
            global_state,
            mint,
            TokenConfig::VENUE_DBC_CURVE,
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            100,
        ),
    );
    assert_err_contains(&res, "Unauthorized");
    assert!(
        svm.get_account(&token_config_pda()).is_none(),
        "a rejected setup_token must not create token_config"
    );
    // burn_address untouched — still the incinerator.
    assert_eq!(get_global_state(&svm, global_state).burn_address, INCINERATOR);
}

#[test]
fn test_setup_token_double_call_rejected() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = init_with_admin(&mut svm, global_state, vault, &payer);
    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);

    run_setup_token(
        &mut svm,
        global_state,
        &admin,
        mint,
        TokenConfig::VENUE_DBC_CURVE,
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        300,
    );
    let tc_before = get_token_config(&svm);

    // Second call: `init` on token_config fails because the PDA already exists.
    let res = send(
        &mut svm,
        &admin,
        ix_setup_token(
            admin.pubkey(),
            global_state,
            mint,
            TokenConfig::VENUE_DBC_CURVE,
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            111,
        ),
    );
    assert!(
        res.is_err(),
        "a second setup_token must be rejected (token_config already initialized)"
    );

    let tc_after = get_token_config(&svm);
    assert_eq!(tc_after.pool_address, tc_before.pool_address);
    assert_eq!(tc_after.venue_config, tc_before.venue_config);
    assert_eq!(tc_after.max_slippage_bps, tc_before.max_slippage_bps);
}

#[test]
fn test_setup_token_rejects_unknown_venue() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = init_with_admin(&mut svm, global_state, vault, &payer);
    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);

    let res = send(
        &mut svm,
        &admin,
        ix_setup_token(
            admin.pubkey(),
            global_state,
            mint,
            3, // only 0/1/2 are valid
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            100,
        ),
    );
    assert_err_contains(&res, "InvalidVenue");
    assert!(svm.get_account(&token_config_pda()).is_none());
}

#[test]
fn test_setup_token_slippage_ceiling_enforced() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = init_with_admin(&mut svm, global_state, vault, &payer);
    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);
    let pool = Pubkey::new_unique();
    let cfg = Pubkey::new_unique();

    // One bp over the hard ceiling: rejected, nothing created.
    let res = send(
        &mut svm,
        &admin,
        ix_setup_token(
            admin.pubkey(),
            global_state,
            mint,
            TokenConfig::VENUE_DBC_CURVE,
            pool,
            cfg,
            MAX_SLIPPAGE_BPS_CEILING + 1,
        ),
    );
    assert_err_contains(&res, "SlippageToleranceTooWide");
    assert!(svm.get_account(&token_config_pda()).is_none());

    // Exactly at the ceiling: accepted.
    let res = send(
        &mut svm,
        &admin,
        ix_setup_token(
            admin.pubkey(),
            global_state,
            mint,
            TokenConfig::VENUE_DBC_CURVE,
            pool,
            cfg,
            MAX_SLIPPAGE_BPS_CEILING,
        ),
    );
    assert!(res.is_ok(), "{:?}", res.err());
    assert_eq!(get_token_config(&svm).max_slippage_bps, MAX_SLIPPAGE_BPS_CEILING);
}

// ---------------------------------------------------------------------------
// 19. init_team_vesting()
// ---------------------------------------------------------------------------

#[test]
fn test_init_team_vesting_happy_path_locks_allocation() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = init_with_admin(&mut svm, global_state, vault, &payer);
    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);

    let total = 50_000_000_000_000_000u64;
    let start_ts = 2_000_000i64;
    let duration = 31_536_000i64;
    fund_admin_toggld_ata(&mut svm, admin.pubkey(), mint, total);

    let res = send(
        &mut svm,
        &admin,
        ix_init_team_vesting(admin.pubkey(), global_state, mint, total, start_ts, duration),
    );
    assert!(res.is_ok(), "{:?}", res.err());

    let v = get_team_vesting(&svm);
    assert_eq!(v.total_amount, total);
    assert_eq!(v.start_ts, start_ts);
    assert_eq!(v.duration_secs, duration);
    assert_eq!(v.claimed_amount, 0);
    assert_eq!(
        v.bump,
        Pubkey::find_program_address(&[TEAM_VESTING_SEED], &toggld::id()).1
    );

    // The whole allocation moved from the admin's ATA into the PDA-owned ATA.
    assert_eq!(
        token_account_amount(&svm, ata_for(team_vesting_pda(), mint)),
        total
    );
    assert_eq!(token_account_amount(&svm, ata_for(admin.pubkey(), mint)), 0);
}

#[test]
fn test_init_team_vesting_unauthorized_fails() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let _admin = init_with_admin(&mut svm, global_state, vault, &payer);
    let attacker = new_funded_keypair(&mut svm, 100_000_000_000);
    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);
    fund_admin_toggld_ata(&mut svm, attacker.pubkey(), mint, 1_000);

    let res = send(
        &mut svm,
        &attacker,
        ix_init_team_vesting(attacker.pubkey(), global_state, mint, 1_000, 1, 1),
    );
    assert_err_contains(&res, "Unauthorized");
    assert!(svm.get_account(&team_vesting_pda()).is_none());
}

#[test]
fn test_init_team_vesting_double_call_rejected() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = init_with_admin(&mut svm, global_state, vault, &payer);
    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);

    let total = 10_000_000u64;
    setup_vesting(
        &mut svm,
        global_state,
        &admin,
        mint,
        total,
        5_000,
        TeamVesting::MIN_DURATION_SECS,
    );
    let v_before = get_team_vesting(&svm);

    // Re-fund so it isn't a lack of tokens that stops the second call.
    fund_admin_toggld_ata(&mut svm, admin.pubkey(), mint, total);
    let res = send(
        &mut svm,
        &admin,
        ix_init_team_vesting(admin.pubkey(), global_state, mint, 123, 999, 999),
    );
    assert!(
        res.is_err(),
        "a second init_team_vesting must be rejected (team_vesting already initialized)"
    );

    let v_after = get_team_vesting(&svm);
    assert_eq!(v_after.total_amount, v_before.total_amount);
    assert_eq!(v_after.start_ts, v_before.start_ts);
    assert_eq!(v_after.duration_secs, v_before.duration_secs);
}

#[test]
fn test_init_team_vesting_rejects_zero_amount_and_bad_schedule() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = init_with_admin(&mut svm, global_state, vault, &payer);
    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);
    fund_admin_toggld_ata(&mut svm, admin.pubkey(), mint, 1_000_000);

    // clock is parked at t0 = 1_000 by init_with_admin.
    let good_start = 1_000i64;
    let good_dur = TeamVesting::MIN_DURATION_SECS;

    // Zero amount -> InvalidVestingAmount.
    let res = send(
        &mut svm,
        &admin,
        ix_init_team_vesting(admin.pubkey(), global_state, mint, 0, good_start, good_dur),
    );
    assert_err_contains(&res, "InvalidVestingAmount");

    // start_ts far in the past (beyond the allowed backdate) -> InvalidVestingSchedule.
    let res = send(
        &mut svm,
        &admin,
        ix_init_team_vesting(
            admin.pubkey(),
            global_state,
            mint,
            1_000,
            good_start - TeamVesting::MAX_START_BACKDATE_SECS - 10_000,
            good_dur,
        ),
    );
    assert_err_contains(&res, "InvalidVestingSchedule");

    // Duration far below the minimum release window -> InvalidVestingSchedule.
    let res = send(
        &mut svm,
        &admin,
        ix_init_team_vesting(
            admin.pubkey(),
            global_state,
            mint,
            1_000,
            good_start,
            TeamVesting::MIN_DURATION_SECS - 1,
        ),
    );
    assert_err_contains(&res, "InvalidVestingSchedule");

    assert!(svm.get_account(&team_vesting_pda()).is_none());
}

// ---------------------------------------------------------------------------
// 20. claim_vested()
// ---------------------------------------------------------------------------

#[test]
fn test_claim_vested_before_start_reverts() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = init_with_admin(&mut svm, global_state, vault, &payer);
    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);

    let start_ts = 5_000_000i64;
    setup_vesting(
        &mut svm,
        global_state,
        &admin,
        mint,
        1_000_000_000,
        start_ts,
        TeamVesting::MIN_DURATION_SECS,
    );

    set_clock_ts(&mut svm, start_ts - 1);
    let res = send(&mut svm, &admin, ix_claim_vested(admin.pubkey(), global_state, mint));
    assert_err_contains(&res, "VestingNotStarted");
    assert_eq!(token_account_amount(&svm, ata_for(admin.pubkey(), mint)), 0);
}

#[test]
fn test_claim_vested_nothing_new_unlocked_reverts() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = init_with_admin(&mut svm, global_state, vault, &payer);
    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);

    let start_ts = 5_000_000i64;
    let duration = TeamVesting::MIN_DURATION_SECS;
    let total = 999_999_937u64;
    setup_vesting(&mut svm, global_state, &admin, mint, total, start_ts, duration);

    // Fully vested, first claim drains everything.
    set_clock_ts(&mut svm, start_ts + duration);
    send(&mut svm, &admin, ix_claim_vested(admin.pubkey(), global_state, mint)).unwrap();
    assert_eq!(token_account_amount(&svm, ata_for(admin.pubkey(), mint)), total);

    // Nothing new has unlocked — a second claim right away must revert.
    let res = send(&mut svm, &admin, ix_claim_vested(admin.pubkey(), global_state, mint));
    assert_err_contains(&res, "NothingVestedToClaim");
    // No stray movement.
    assert_eq!(token_account_amount(&svm, ata_for(admin.pubkey(), mint)), total);
    assert_eq!(get_team_vesting(&svm).claimed_amount, total);
}

#[test]
fn test_claim_vested_full_unlock_at_and_after_end() {
    let total = 123_456_789_000u64;
    let start_ts = 4_000_000i64;
    let duration = TeamVesting::MIN_DURATION_SECS;

    // Exactly at start_ts + duration.
    {
        let (mut svm, global_state, vault, payer) = new_svm();
        let admin = init_with_admin(&mut svm, global_state, vault, &payer);
        let mint = Pubkey::new_unique();
        create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);
        setup_vesting(&mut svm, global_state, &admin, mint, total, start_ts, duration);

        set_clock_ts(&mut svm, start_ts + duration);
        send(&mut svm, &admin, ix_claim_vested(admin.pubkey(), global_state, mint)).unwrap();

        assert_eq!(token_account_amount(&svm, ata_for(admin.pubkey(), mint)), total);
        assert_eq!(token_account_amount(&svm, ata_for(team_vesting_pda(), mint)), 0);
        assert_eq!(get_team_vesting(&svm).claimed_amount, total);
    }

    // Well past the end.
    {
        let (mut svm, global_state, vault, payer) = new_svm();
        let admin = init_with_admin(&mut svm, global_state, vault, &payer);
        let mint = Pubkey::new_unique();
        create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);
        setup_vesting(&mut svm, global_state, &admin, mint, total, start_ts, duration);

        set_clock_ts(&mut svm, start_ts + duration + 10_000_000);
        send(&mut svm, &admin, ix_claim_vested(admin.pubkey(), global_state, mint)).unwrap();
        assert_eq!(token_account_amount(&svm, ata_for(admin.pubkey(), mint)), total);
    }
}

#[test]
fn test_claim_vested_linear_release_exactness_across_schedules() {
    // (total, duration_secs, elapsed_secs) — total deliberately not divisible
    // by duration so the linear-release integer division truncates, and the
    // on-chain claim must still match `compute_vested_unlocked` to the token.
    for (total, duration, elapsed) in [
        (50_000_000_000_000_000u64, 31_536_000i64, 7_000_123i64),
        (999_999_937u64, 12_345_000i64, 6_789_000i64),
        (123_456_789_012u64, 3_000_000i64, 1i64),
        (u64::MAX / 2, 2_592_000i64, 2_591_999i64),
    ] {
        let (mut svm, global_state, vault, payer) = new_svm();
        let admin = init_with_admin(&mut svm, global_state, vault, &payer);
        let mint = Pubkey::new_unique();
        create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);

        let start_ts = 1_000_000i64;
        setup_vesting(&mut svm, global_state, &admin, mint, total, start_ts, duration);

        set_clock_ts(&mut svm, start_ts + elapsed);
        let res = send(&mut svm, &admin, ix_claim_vested(admin.pubkey(), global_state, mint));
        assert!(
            res.is_ok(),
            "total={total} dur={duration} elapsed={elapsed}: {:?}",
            res.err()
        );

        let expected = ((total as u128) * (elapsed as u128) / (duration as u128)) as u64;
        assert_eq!(
            token_account_amount(&svm, ata_for(admin.pubkey(), mint)),
            expected,
            "linear-release claim must be exact (total={total}, dur={duration}, elapsed={elapsed})"
        );
        assert_eq!(get_team_vesting(&svm).claimed_amount, expected);
        assert_eq!(
            token_account_amount(&svm, ata_for(team_vesting_pda(), mint)),
            total - expected
        );
    }
}

#[test]
fn test_claim_vested_rejects_wrong_mint() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = init_with_admin(&mut svm, global_state, vault, &payer);
    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);

    let start_ts = 5_000_000i64;
    setup_vesting(
        &mut svm,
        global_state,
        &admin,
        mint,
        1_000_000_000,
        start_ts,
        TeamVesting::MIN_DURATION_SECS,
    );
    set_clock_ts(&mut svm, start_ts + 1_000);

    // A different, unrelated mint — `claim_vested` pins `mint` to
    // `team_vesting.mint`, so this must be rejected before any transfer. Its
    // ATAs are pre-created so resolution reaches the `mint` address check
    // rather than tripping on an uninitialized derived ATA first.
    let wrong_mint = Pubkey::new_unique();
    create_mint(&mut svm, wrong_mint, 9, 0);
    create_token_account(
        &mut svm,
        ata_for(team_vesting_pda(), wrong_mint),
        wrong_mint,
        team_vesting_pda(),
        0,
    );
    create_token_account(
        &mut svm,
        ata_for(admin.pubkey(), wrong_mint),
        wrong_mint,
        admin.pubkey(),
        0,
    );

    let res = send(
        &mut svm,
        &admin,
        ix_claim_vested(admin.pubkey(), global_state, wrong_mint),
    );
    assert_err_contains(&res, "TokenNotConfigured");
    assert_eq!(get_team_vesting(&svm).claimed_amount, 0);
}

// ---------------------------------------------------------------------------
// 21. promote_burn_venue()
// ---------------------------------------------------------------------------

#[test]
fn test_promote_burn_venue_happy_path_repoints_routing_only() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = init_with_admin(&mut svm, global_state, vault, &payer);
    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);
    run_setup_token(
        &mut svm,
        global_state,
        &admin,
        mint,
        TokenConfig::VENUE_DBC_CURVE,
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        200,
    );

    let new_pool = Pubkey::new_unique();
    let new_config = Pubkey::new_unique();
    let res = send(
        &mut svm,
        &admin,
        ix_promote_burn_venue(
            admin.pubkey(),
            global_state,
            TokenConfig::VENUE_DAMM_V2,
            new_pool,
            new_config,
        ),
    );
    assert!(res.is_ok(), "{:?}", res.err());

    let tc = get_token_config(&svm);
    assert_eq!(tc.venue, TokenConfig::VENUE_DAMM_V2);
    assert_eq!(tc.pool_address, new_pool);
    assert_eq!(tc.venue_config, new_config);
    // Routing only — mint, slippage ceiling, burn counter, burn wiring untouched.
    assert_eq!(tc.toggld_mint, mint);
    assert_eq!(tc.max_slippage_bps, 200);
    assert_eq!(tc.total_tokens_burned, 0);
    assert_eq!(
        get_global_state(&svm, global_state).burn_address,
        burn_vault_pda()
    );
    assert_vault_invariant(&svm, vault, &get_global_state(&svm, global_state));
}

#[test]
fn test_promote_burn_venue_unauthorized_fails() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = init_with_admin(&mut svm, global_state, vault, &payer);
    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);
    run_setup_token(
        &mut svm,
        global_state,
        &admin,
        mint,
        TokenConfig::VENUE_DBC_CURVE,
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        200,
    );
    let attacker = new_funded_keypair(&mut svm, 100_000_000_000);

    let res = send(
        &mut svm,
        &attacker,
        ix_promote_burn_venue(
            attacker.pubkey(),
            global_state,
            TokenConfig::VENUE_DAMM_V2,
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        ),
    );
    assert_err_contains(&res, "Unauthorized");
    assert_eq!(get_token_config(&svm).venue, TokenConfig::VENUE_DBC_CURVE);
}

#[test]
fn test_promote_burn_venue_before_setup_token_fails() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = init_with_admin(&mut svm, global_state, vault, &payer);

    let res = send(
        &mut svm,
        &admin,
        ix_promote_burn_venue(
            admin.pubkey(),
            global_state,
            TokenConfig::VENUE_DAMM_V1,
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        ),
    );
    assert_err_contains(&res, "AccountNotInitialized");
}

#[test]
fn test_promote_burn_venue_rejects_unknown_venue() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = init_with_admin(&mut svm, global_state, vault, &payer);
    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);
    run_setup_token(
        &mut svm,
        global_state,
        &admin,
        mint,
        TokenConfig::VENUE_DBC_CURVE,
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        200,
    );

    let res = send(
        &mut svm,
        &admin,
        ix_promote_burn_venue(
            admin.pubkey(),
            global_state,
            7,
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        ),
    );
    assert_err_contains(&res, "InvalidVenue");
    assert_eq!(get_token_config(&svm).venue, TokenConfig::VENUE_DBC_CURVE);
}

/// Documents current behaviour: unlike `setup_token` / `init_team_vesting`,
/// `promote_burn_venue` has no `init`/one-shot guard — it only ever repoints
/// swap routing, so calling it more than once is allowed and simply applies the
/// latest values. (See the followups note — this deviates from the task's
/// "double-call rejection" wording but appears intentional.)
#[test]
fn test_promote_burn_venue_has_no_one_time_guard() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = init_with_admin(&mut svm, global_state, vault, &payer);
    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);
    run_setup_token(
        &mut svm,
        global_state,
        &admin,
        mint,
        TokenConfig::VENUE_DBC_CURVE,
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        200,
    );

    let (p1, c1) = (Pubkey::new_unique(), Pubkey::new_unique());
    send(
        &mut svm,
        &admin,
        ix_promote_burn_venue(admin.pubkey(), global_state, TokenConfig::VENUE_DAMM_V2, p1, c1),
    )
    .unwrap();

    let (p2, c2) = (Pubkey::new_unique(), Pubkey::new_unique());
    let res = send(
        &mut svm,
        &admin,
        ix_promote_burn_venue(admin.pubkey(), global_state, TokenConfig::VENUE_DAMM_V2, p2, c2),
    );
    assert!(res.is_ok(), "a second promote must also be accepted: {:?}", res.err());

    let tc = get_token_config(&svm);
    assert_eq!(tc.venue, TokenConfig::VENUE_DAMM_V2);
    assert_eq!(tc.pool_address, p2);
    assert_eq!(tc.venue_config, c2);
}

#[test]
fn test_promote_burn_venue_rejects_dbc_curve_target() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = init_with_admin(&mut svm, global_state, vault, &payer);
    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);
    run_setup_token(
        &mut svm,
        global_state,
        &admin,
        mint,
        TokenConfig::VENUE_DBC_CURVE,
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        200,
    );

    // The DBC curve is dead once the migrator graduates it — promotion may only
    // ever target a DAMM pool, never revert to the curve.
    let res = send(
        &mut svm,
        &admin,
        ix_promote_burn_venue(
            admin.pubkey(),
            global_state,
            TokenConfig::VENUE_DBC_CURVE,
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        ),
    );
    assert_err_contains(&res, "InvalidVenue");
    assert_eq!(get_token_config(&svm).venue, TokenConfig::VENUE_DBC_CURVE);
}

#[test]
fn test_promote_burn_venue_rejects_noop_repeat() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = init_with_admin(&mut svm, global_state, vault, &payer);
    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);
    run_setup_token(
        &mut svm,
        global_state,
        &admin,
        mint,
        TokenConfig::VENUE_DBC_CURVE,
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        200,
    );

    let (pool, cfg) = (Pubkey::new_unique(), Pubkey::new_unique());
    send(
        &mut svm,
        &admin,
        ix_promote_burn_venue(admin.pubkey(), global_state, TokenConfig::VENUE_DAMM_V2, pool, cfg),
    )
    .unwrap();

    // Exact same venue + pool + config again — nothing changes, so it is
    // rejected rather than emitting a misleading no-op event.
    let res = send(
        &mut svm,
        &admin,
        ix_promote_burn_venue(admin.pubkey(), global_state, TokenConfig::VENUE_DAMM_V2, pool, cfg),
    );
    assert_err_contains(&res, "VenueCannotRevert");
}

// ---------------------------------------------------------------------------
// 22. burn_tokens() — revert paths only (no DBC program loaded in LiteSVM)
// ---------------------------------------------------------------------------

struct BurnFixture {
    svm: LiteSVM,
    global_state: Pubkey,
    vault: Pubkey,
    caller: Keypair,
    mint: Pubkey,
    pool_address: Pubkey,
    venue_config: Pubkey,
}

/// `new_svm()` + `initialize()` + `setup_token(venue = DbcCurve)` already run,
/// with the $TOGGLD and WSOL mints injected and a funded permissionless caller.
fn burn_tokens_fixture() -> BurnFixture {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = init_with_admin(&mut svm, global_state, vault, &payer);
    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);
    create_mint(&mut svm, WSOL_MINT, 9, 0);
    let pool_address = Pubkey::new_unique();
    let venue_config = Pubkey::new_unique();
    run_setup_token(
        &mut svm,
        global_state,
        &admin,
        mint,
        TokenConfig::VENUE_DBC_CURVE,
        pool_address,
        venue_config,
        300,
    );
    let caller = new_funded_keypair(&mut svm, 100_000_000_000);
    BurnFixture {
        svm,
        global_state,
        vault,
        caller,
        mint,
        pool_address,
        venue_config,
    }
}

#[test]
fn test_burn_tokens_rejects_dust_sweep_below_min() {
    let mut f = burn_tokens_fixture();
    // burn_vault holds exactly its rent reserve after setup_token; add just
    // under MIN_SWEEP so the post-reserve sweep is below the dust floor.
    f.svm
        .airdrop(&burn_vault_pda(), MIN_SWEEP_LAMPORTS - 1)
        .unwrap();

    let res = send(
        &mut f.svm,
        &f.caller,
        ix_burn_tokens(f.caller.pubkey(), f.mint, f.pool_address, f.venue_config, 1),
    );
    assert_err_contains(&res, "NothingToSweep");
    assert_vault_invariant(
        &f.svm,
        f.vault,
        &get_global_state(&f.svm, f.global_state),
    );
}

#[test]
fn test_burn_tokens_never_sweeps_below_rent_exempt_minimum() {
    let mut f = burn_tokens_fixture();
    let reserve = f.svm.minimum_balance_for_rent_exemption(0);
    // Force the vault below its own rent reserve: the sweep computation's
    // checked_sub underflows and must revert rather than wrap around.
    set_lamports(&mut f.svm, burn_vault_pda(), reserve - 1);

    let res = send(
        &mut f.svm,
        &f.caller,
        ix_burn_tokens(f.caller.pubkey(), f.mint, f.pool_address, f.venue_config, 1),
    );
    assert_err_contains(&res, "SweepBelowRentExempt");
}

#[test]
fn test_burn_tokens_rejects_zero_min_out() {
    let mut f = burn_tokens_fixture();
    f.svm
        .airdrop(&burn_vault_pda(), MIN_SWEEP_LAMPORTS + 5_000_000)
        .unwrap();

    let res = send(
        &mut f.svm,
        &f.caller,
        ix_burn_tokens(f.caller.pubkey(), f.mint, f.pool_address, f.venue_config, 0),
    );
    assert_err_contains(&res, "MinOutZero");
}

#[test]
fn test_burn_tokens_rejects_slippage_ceiling_breach() {
    let mut f = burn_tokens_fixture();
    f.svm
        .airdrop(&burn_vault_pda(), MIN_SWEEP_LAMPORTS + 5_000_000)
        .unwrap();

    // Tamper the stored ceiling above MAX_SLIPPAGE_BPS_CEILING; burn_tokens
    // re-checks it and must refuse to proceed before any swap CPI.
    patch_account_data(
        &mut f.svm,
        token_config_pda(),
        TOKEN_CONFIG_MAX_SLIPPAGE_OFFSET,
        &(MAX_SLIPPAGE_BPS_CEILING + 1).to_le_bytes(),
    );

    let res = send(
        &mut f.svm,
        &f.caller,
        ix_burn_tokens(f.caller.pubkey(), f.mint, f.pool_address, f.venue_config, 1),
    );
    assert_err_contains(&res, "SlippageToleranceTooWide");
}

#[test]
fn test_burn_tokens_rejects_non_dbc_venue() {
    let mut f = burn_tokens_fixture();
    let new_pool = Pubkey::new_unique();
    let new_config = Pubkey::new_unique();

    // `promote_burn_venue()` can no longer land `TokenConfig.venue` on
    // `VENUE_DAMM_V1` at all (SEC-3 fix) -- reaching this state now requires
    // directly tampering the account, which is exactly the point: this test
    // asserts `burn_tokens()`'s own venue guard is defense-in-depth,
    // independent of `promote_burn_venue()`'s input validation.
    patch_account_data(
        &mut f.svm,
        token_config_pda(),
        TOKEN_CONFIG_VENUE_OFFSET,
        &[TokenConfig::VENUE_DAMM_V1],
    );
    patch_account_data(
        &mut f.svm,
        token_config_pda(),
        TOKEN_CONFIG_VENUE_OFFSET + 1,
        new_pool.as_ref(),
    );
    patch_account_data(
        &mut f.svm,
        token_config_pda(),
        TOKEN_CONFIG_VENUE_OFFSET + 1 + 32,
        new_config.as_ref(),
    );
    f.svm
        .airdrop(&burn_vault_pda(), MIN_SWEEP_LAMPORTS + 5_000_000)
        .unwrap();

    // DAMM swap path isn't wired yet — the DBC-only guard must trip.
    let res = send(
        &mut f.svm,
        &f.caller,
        ix_burn_tokens(f.caller.pubkey(), f.mint, new_pool, new_config, 1),
    );
    assert_err_contains(&res, "InvalidVenue");
}

#[test]
fn test_burn_tokens_rejects_slippage_floor_not_met() {
    let mut f = burn_tokens_fixture();
    f.svm.airdrop(&burn_vault_pda(), 50_000_000).unwrap();

    // Give `dbc_pool` a real sqrt_price (Q64.64 for price == 1: sqrt_price ==
    // 2^64), so the on-chain expected-out floor for the ~0.049 SOL sweep is
    // ~49e6 base units — a `min_out = 1` keeper arg is far below it.
    create_fake_pool(&mut f.svm, f.pool_address, 1u128 << 64, DBC_POOL_SQRT_PRICE_OFFSET);

    let res = send(
        &mut f.svm,
        &f.caller,
        ix_burn_tokens_full(
            f.caller.pubkey(),
            f.mint,
            f.pool_address,
            Some(f.venue_config),
            DBC_PROGRAM_ID,
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            1,
        ),
    );
    assert_err_contains(&res, "SlippageFloorNotMet");
    assert_eq!(get_token_config(&f.svm).total_tokens_burned, 0);
}

#[test]
fn test_burn_tokens_rejects_malformed_pool_account() {
    let mut f = burn_tokens_fixture();
    f.svm.airdrop(&burn_vault_pda(), 50_000_000).unwrap();

    // `dbc_pool` (== token_config.pool_address, so it clears the `address`
    // constraint) is only 165 bytes — far too small to hold a `sqrt_price` at
    // the venue's byte offset. The expected-out floor read must reject it
    // rather than reading garbage.
    create_token_account(&mut f.svm, f.pool_address, f.mint, Pubkey::new_unique(), 0);
    let res = send(
        &mut f.svm,
        &f.caller,
        ix_burn_tokens_full(
            f.caller.pubkey(),
            f.mint,
            f.pool_address,
            Some(f.venue_config),
            DBC_PROGRAM_ID,
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            1,
        ),
    );
    assert_err_contains(&res, "MalformedPoolAccount");
}

// ---------------------------------------------------------------------------
// 23. settle()'s burn leg after setup_token() repoints it to burn_vault
// ---------------------------------------------------------------------------

#[test]
fn test_settle_burn_leg_lands_in_burn_vault_after_setup_token() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let admin = init_with_admin(&mut svm, global_state, vault, &payer);
    let mint = Pubkey::new_unique();
    create_mint(&mut svm, mint, 9, TOTAL_TOKEN_SUPPLY);
    run_setup_token(
        &mut svm,
        global_state,
        &admin,
        mint,
        TokenConfig::VENUE_DBC_CURVE,
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        300,
    );

    let burn_vault = burn_vault_pda();
    assert_eq!(
        get_global_state(&svm, global_state).burn_address,
        burn_vault,
        "precondition: setup_token repointed burn_address"
    );

    // One full challenge -> settle cycle.
    let user = new_funded_keypair(&mut svm, 10_000_000_000);
    let bid = 1_050_000u64; // 5% over genesis 1_000_000
    send(
        &mut svm,
        &user,
        ix_challenge(global_state, vault, user.pubkey(), Pubkey::default(), bid),
    )
    .unwrap();

    let gs = get_global_state(&svm, global_state);
    set_clock_ts(&mut svm, gs.window_end_ts);

    let burn_vault_before = svm.get_balance(&burn_vault).unwrap();
    let incinerator_before = svm.get_balance(&INCINERATOR).unwrap_or(0);

    let res = send(
        &mut svm,
        &user,
        ix_settle(global_state, vault, user.pubkey(), burn_vault, win_record_pda(gs.holder_count)),
    );
    assert!(res.is_ok(), "{:?}", res.err());

    let expected_fee = (bid as u128 * FEE_BPS as u128 / 10_000u128) as u64;
    let expected_burn = bid - expected_fee;

    assert_eq!(
        svm.get_balance(&burn_vault).unwrap() - burn_vault_before,
        expected_burn,
        "settle()'s 85% burn leg must land in burn_vault, not the incinerator"
    );
    assert_eq!(
        svm.get_balance(&INCINERATOR).unwrap_or(0),
        incinerator_before,
        "no lamports may reach the old incinerator once the token burn path is wired"
    );

    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.treasury_balance, expected_fee);
    assert_eq!(gs.current_price, bid);
    assert_eq!(gs.escrowed_amount, 0);
    assert_vault_invariant(&svm, vault, &gs);
}

// ---------------------------------------------------------------------------
// Phase R3 -- Win NFT
// ---------------------------------------------------------------------------

/// Runs `initialize()` then a single cold-open challenge/settle cycle that
/// flips the holder -- the minimal setup nearly every Phase R3 test needs.
/// Returns the funded winner keypair and the resulting `WinRecord` PDA
/// (seeded by genesis's pre-increment `holder_count` of 1, i.e.
/// `win_record_pda(1)`).
fn settle_one_flip(svm: &mut LiteSVM, global_state: Pubkey, vault: Pubkey, payer: &Keypair) -> (Keypair, Pubkey) {
    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    set_clock_ts(svm, 1_000);
    send(svm, payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();

    let winner = new_funded_keypair(svm, 10_000_000_000);
    let gs0 = get_global_state(svm, global_state);
    let bid = min_raise_amount(gs0.current_price, gs0.min_raise_bps);
    send(svm, &winner, ix_challenge(global_state, vault, winner.pubkey(), Pubkey::default(), bid)).unwrap();

    let gs = get_global_state(svm, global_state);
    set_clock_ts(svm, gs.window_end_ts);
    let win_record = win_record_pda(gs.holder_count);
    let res = send(svm, &winner, ix_settle(global_state, vault, winner.pubkey(), INCINERATOR, win_record));
    assert!(res.is_ok(), "settle_one_flip: {:?}", res.err());

    (winner, win_record)
}

#[test]
fn test_settle_creates_win_record_only_on_flip_at_pre_increment_pda() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let (winner, win_record) = settle_one_flip(&mut svm, global_state, vault, &payer);

    // --- the flip must have created exactly WinRecord PDA #1 ---------------
    let gs = get_global_state(&svm, global_state);
    assert_eq!(gs.holder_count, 2, "a flip must increment holder_count exactly once");
    assert_eq!(
        win_record,
        win_record_pda(1),
        "the flip's WinRecord must be seeded by the PRE-increment ordinal (1), not the post-increment one (2)"
    );

    let record = get_win_record(&svm, win_record).expect("WinRecord must exist after a flip");
    assert_eq!(record.winner, winner.pubkey());
    assert_eq!(
        record.holder_count, 2,
        "WinRecord.holder_count records the POST-increment ordinal -- 'you are holder #2'"
    );
    assert_eq!(record.price_paid, gs.current_price);
    assert_eq!(record.won_at, gs.holder_since);
    assert!(!record.minted);

    let rent_exempt = svm.minimum_balance_for_rent_exemption(WinRecord::SPACE);
    assert_eq!(
        svm.get_balance(&win_record).unwrap(),
        rent_exempt,
        "WinRecord must be funded to exactly its rent-exempt minimum, no more"
    );

    // --- now a DEFEND: the holder outbids a different mid-window bidder ----
    // Must NOT create a second WinRecord and must NOT touch holder_count.
    let challenger = new_funded_keypair(&mut svm, 10_000_000_000);
    let bid_c = min_raise_amount(gs.current_price, gs.min_raise_bps);
    send(
        &mut svm,
        &challenger,
        ix_challenge(global_state, vault, challenger.pubkey(), Pubkey::default(), bid_c),
    )
    .unwrap();
    let bid_defend = min_raise_amount(bid_c, gs.min_raise_bps);
    send(
        &mut svm,
        &winner,
        ix_challenge(global_state, vault, winner.pubkey(), challenger.pubkey(), bid_defend),
    )
    .unwrap();

    let gs2 = get_global_state(&svm, global_state);
    set_clock_ts(&mut svm, gs2.window_end_ts);
    // Pre-increment ordinal at defend time is still 2 (holder_count is
    // untouched by challenges) -- this PDA must never be created.
    let defend_win_record = win_record_pda(gs2.holder_count);
    let caller_lamports_before = svm.get_balance(&winner.pubkey()).unwrap();
    let res = send(
        &mut svm,
        &winner,
        ix_settle(global_state, vault, winner.pubkey(), INCINERATOR, defend_win_record),
    );
    assert!(res.is_ok(), "{:?}", res.err());

    let gs3 = get_global_state(&svm, global_state);
    assert_eq!(gs3.holder_count, 2, "a defend must never increment holder_count");
    assert!(
        svm.get_account(&defend_win_record).is_none(),
        "no WinRecord may be created for a defend -- no rent spent"
    );
    // The only lamports leaving `caller` on a defend are the transaction fee
    // -- a small, fixed per-signature cost, nowhere near a WinRecord's
    // rent-exempt reserve. This is a loose bound, not an exact-fee assertion,
    // deliberately: it's enough to prove no rent-sized debit happened.
    let caller_lamports_after = svm.get_balance(&winner.pubkey()).unwrap();
    assert!(
        caller_lamports_before - caller_lamports_after < rent_exempt,
        "caller must not be debited anything rent-sized on a defend"
    );
}

#[test]
fn test_mint_win_nft_happy_path_creates_immutable_core_asset() {
    // Sanity check on the test fixture itself: the seed's derived public key
    // really is the same `METADATA_SIGNER` baked into the program constant,
    // so a passing test here actually proves something about the real
    // Ed25519Program path, not a self-consistent mock.
    let derived_signer = Pubkey::new_from_array(SigningKey::from_bytes(&METADATA_SIGNER_SEED).verifying_key().to_bytes());
    assert_eq!(derived_signer, METADATA_SIGNER);

    let (mut svm, global_state, vault, payer) = new_svm();
    let (winner, win_record) = settle_one_flip(&mut svm, global_state, vault, &payer);

    let asset = Keypair::new();
    let uri = "https://arweave.net/abc123".to_string();
    let content_hash = [42u8; 32];
    let ed25519_ix = ed25519_attestation_ix(&METADATA_SIGNER_SEED, &content_hash);
    let mint_ix = ix_mint_win_nft(winner.pubkey(), win_record, asset.pubkey(), uri.clone(), content_hash);
    let res = send_multi(&mut svm, &winner, &[&winner, &asset], &[ed25519_ix, mint_ix]);
    assert!(res.is_ok(), "{:?}", res.err());

    let record = get_win_record(&svm, win_record).unwrap();
    assert!(record.minted, "WinRecord.minted must flip to true after a successful mint");

    // The asset account must now be a real, owned-by-mpl-core Core asset --
    // owned by the winner, permanently immutable (no update authority), and
    // carrying the exact uri supplied.
    let asset_account = svm.get_account(&asset.pubkey()).expect("asset account must exist after CreateV1");
    assert_eq!(asset_account.owner, mpl_core::ID);
    let parsed =
        mpl_core::accounts::BaseAssetV1::from_bytes(&asset_account.data).expect("asset data must parse as BaseAssetV1");
    assert_eq!(parsed.owner, winner.pubkey());
    assert_eq!(
        parsed.update_authority,
        mpl_core::types::UpdateAuthority::None,
        "update authority must never be retained -- snapshot-once, immutable, matches the locked decision"
    );
    assert_eq!(parsed.uri, uri);

    // Mechanism 1 -- the Attributes plugin must carry the exact WinRecord
    // ground truth, unforgeable and independent of anything the client
    // uploaded off-chain, plus the metadata_hash attestation from Mechanism 2.
    let full_asset = mpl_core::Asset::deserialize(&asset_account.data).expect("asset data must parse with plugins");
    let attrs = full_asset
        .plugin_list
        .attributes
        .as_ref()
        .expect("Attributes plugin must be present")
        .attributes
        .attribute_list
        .clone();
    let find = |key: &str| attrs.iter().find(|a| a.key == key).map(|a| a.value.clone());
    assert_eq!(find("winner"), Some(record.winner.to_string()));
    assert_eq!(find("holder_count"), Some(record.holder_count.to_string()));
    assert_eq!(find("price_paid"), Some(record.price_paid.to_string()));
    assert_eq!(find("won_at"), Some(record.won_at.to_string()));
    let expected_hex: String = content_hash.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(find("metadata_hash"), Some(expected_hex));
}

#[test]
fn test_mint_win_nft_rejects_non_owner_caller() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let (_winner, win_record) = settle_one_flip(&mut svm, global_state, vault, &payer);

    let impostor = new_funded_keypair(&mut svm, 10_000_000_000);
    let asset = Keypair::new();
    // No Ed25519 attestation needed: `NotWinRecordOwner` is checked before
    // the metadata-signature check, so this must fail on that first, never
    // reaching Mechanism 2 at all.
    let ix = ix_mint_win_nft(impostor.pubkey(), win_record, asset.pubkey(), "https://arweave.net/x".to_string(), [0u8; 32]);
    let res = send_with_signers(&mut svm, &impostor, &[&impostor, &asset], ix);
    assert_err_contains(&res, "NotWinRecordOwner");

    let record = get_win_record(&svm, win_record).unwrap();
    assert!(!record.minted, "a rejected mint attempt must not flip minted");
}

#[test]
fn test_mint_win_nft_rejects_double_mint() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let (winner, win_record) = settle_one_flip(&mut svm, global_state, vault, &payer);

    let asset1 = Keypair::new();
    let content_hash1 = [11u8; 32];
    let ed25519_ix1 = ed25519_attestation_ix(&METADATA_SIGNER_SEED, &content_hash1);
    let ix1 = ix_mint_win_nft(
        winner.pubkey(),
        win_record,
        asset1.pubkey(),
        "https://arweave.net/first".to_string(),
        content_hash1,
    );
    let res1 = send_multi(&mut svm, &winner, &[&winner, &asset1], &[ed25519_ix1, ix1]);
    assert!(res1.is_ok(), "first mint should succeed: {:?}", res1.err());

    // No Ed25519 attestation needed for the second attempt:
    // `WinNftAlreadyMinted` is checked before the metadata-signature check.
    let asset2 = Keypair::new();
    let ix2 = ix_mint_win_nft(
        winner.pubkey(),
        win_record,
        asset2.pubkey(),
        "https://arweave.net/second".to_string(),
        [0u8; 32],
    );
    let res2 = send_with_signers(&mut svm, &winner, &[&winner, &asset2], ix2);
    assert_err_contains(&res2, "WinNftAlreadyMinted");

    // The first mint's asset must be untouched by the rejected second attempt.
    assert!(svm.get_account(&asset2.pubkey()).is_none(), "the second attempt's asset must never be created");
}

/// The key eligibility fix from Phase R3's review pass: a winner's ability to
/// mint their `WinRecord` must survive being outbid and flipped past -- it is
/// NOT gated on still being the current holder.
#[test]
fn test_mint_win_nft_winner_can_mint_after_being_outbid_and_flipped_past() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let (winner_a, win_record_a) = settle_one_flip(&mut svm, global_state, vault, &payer);

    // A second flip happens BEFORE winner_a ever mints -- someone else
    // outbids and takes the toggle.
    let winner_b = new_funded_keypair(&mut svm, 10_000_000_000);
    let gs = get_global_state(&svm, global_state);
    let bid = min_raise_amount(gs.current_price, gs.min_raise_bps);
    send(
        &mut svm,
        &winner_b,
        ix_challenge(global_state, vault, winner_b.pubkey(), Pubkey::default(), bid),
    )
    .unwrap();
    let gs2 = get_global_state(&svm, global_state);
    set_clock_ts(&mut svm, gs2.window_end_ts);
    let win_record_b = win_record_pda(gs2.holder_count);
    send(
        &mut svm,
        &winner_b,
        ix_settle(global_state, vault, winner_b.pubkey(), INCINERATOR, win_record_b),
    )
    .unwrap();

    let gs3 = get_global_state(&svm, global_state);
    assert_eq!(gs3.holder, winner_b.pubkey(), "precondition: the toggle has moved on");
    assert_ne!(gs3.holder, winner_a.pubkey(), "precondition: winner_a is no longer the holder");

    // winner_a, no longer the holder and outbid long ago, must still be able
    // to mint their (now-past) win.
    let asset = Keypair::new();
    let content_hash = [7u8; 32];
    let ed25519_ix = ed25519_attestation_ix(&METADATA_SIGNER_SEED, &content_hash);
    let ix = ix_mint_win_nft(
        winner_a.pubkey(),
        win_record_a,
        asset.pubkey(),
        "https://arweave.net/past-win".to_string(),
        content_hash,
    );
    let res = send_multi(&mut svm, &winner_a, &[&winner_a, &asset], &[ed25519_ix, ix]);
    assert!(
        res.is_ok(),
        "a winner must be able to mint a past win after being outbid and flipped past: {:?}",
        res.err()
    );

    let record = get_win_record(&svm, win_record_a).unwrap();
    assert!(record.minted);
}

#[test]
fn test_mint_win_nft_rejects_empty_and_oversized_uri() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let (winner, win_record) = settle_one_flip(&mut svm, global_state, vault, &payer);

    // No Ed25519 attestation needed: `InvalidNftUri` is checked before the
    // metadata-signature check.
    let asset1 = Keypair::new();
    let ix_empty = ix_mint_win_nft(winner.pubkey(), win_record, asset1.pubkey(), String::new(), [0u8; 32]);
    let res_empty = send_with_signers(&mut svm, &winner, &[&winner, &asset1], ix_empty);
    assert_err_contains(&res_empty, "InvalidNftUri");

    let asset2 = Keypair::new();
    let oversized_uri = "a".repeat(MAX_NFT_URI_LEN + 1);
    let ix_oversized = ix_mint_win_nft(winner.pubkey(), win_record, asset2.pubkey(), oversized_uri, [0u8; 32]);
    let res_oversized = send_with_signers(&mut svm, &winner, &[&winner, &asset2], ix_oversized);
    assert_err_contains(&res_oversized, "InvalidNftUri");

    let record = get_win_record(&svm, win_record).unwrap();
    assert!(!record.minted, "rejected uri attempts must not flip minted");
}

// ---------------------------------------------------------------------------
// Mechanism 2 -- InvalidMetadataSignature cases (plan §6/§7)
// ---------------------------------------------------------------------------

#[test]
fn test_mint_win_nft_rejects_wrong_signer() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let (winner, win_record) = settle_one_flip(&mut svm, global_state, vault, &payer);

    let asset = Keypair::new();
    let content_hash = [3u8; 32];
    // Valid signature, valid message -- but signed by a keypair that is NOT
    // `METADATA_SIGNER`.
    let ed25519_ix = ed25519_attestation_ix(&WRONG_SIGNER_SEED, &content_hash);
    let mint_ix = ix_mint_win_nft(winner.pubkey(), win_record, asset.pubkey(), "https://arweave.net/x".to_string(), content_hash);
    let res = send_multi(&mut svm, &winner, &[&winner, &asset], &[ed25519_ix, mint_ix]);
    assert_err_contains(&res, "InvalidMetadataSignature");

    let record = get_win_record(&svm, win_record).unwrap();
    assert!(!record.minted, "a rejected mint attempt must not flip minted");
}

#[test]
fn test_mint_win_nft_rejects_wrong_message() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let (winner, win_record) = settle_one_flip(&mut svm, global_state, vault, &payer);

    let asset = Keypair::new();
    let signed_hash = [5u8; 32];
    let submitted_hash = [6u8; 32]; // different from what was actually signed
    let ed25519_ix = ed25519_attestation_ix(&METADATA_SIGNER_SEED, &signed_hash);
    let mint_ix = ix_mint_win_nft(
        winner.pubkey(),
        win_record,
        asset.pubkey(),
        "https://arweave.net/x".to_string(),
        submitted_hash,
    );
    let res = send_multi(&mut svm, &winner, &[&winner, &asset], &[ed25519_ix, mint_ix]);
    assert_err_contains(&res, "InvalidMetadataSignature");

    let record = get_win_record(&svm, win_record).unwrap();
    assert!(!record.minted);
}

#[test]
fn test_mint_win_nft_rejects_missing_ed25519_instruction() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let (winner, win_record) = settle_one_flip(&mut svm, global_state, vault, &payer);

    let asset = Keypair::new();
    let content_hash = [9u8; 32];
    // `mint_win_nft` sent as the transaction's only/first instruction --
    // `current_index == 0`, so there is no preceding instruction at all.
    let mint_ix = ix_mint_win_nft(winner.pubkey(), win_record, asset.pubkey(), "https://arweave.net/x".to_string(), content_hash);
    let res = send_with_signers(&mut svm, &winner, &[&winner, &asset], mint_ix);
    assert_err_contains(&res, "InvalidMetadataSignature");

    let record = get_win_record(&svm, win_record).unwrap();
    assert!(!record.minted);
}

#[test]
fn test_mint_win_nft_rejects_non_adjacent_ed25519_instruction() {
    let (mut svm, global_state, vault, payer) = new_svm();
    let (winner, win_record) = settle_one_flip(&mut svm, global_state, vault, &payer);

    let asset = Keypair::new();
    let content_hash = [13u8; 32];
    // A genuinely valid Ed25519 attestation over the exact content_hash --
    // but with an unrelated instruction (a second, harmless Ed25519
    // instruction acting as filler) placed between it and `mint_win_nft`, so
    // it is no longer the IMMEDIATELY preceding instruction. Must still be
    // rejected: the positional-adjacency check (plan §7) is what's being
    // exercised here, independent of whether the signature itself is valid.
    let ed25519_ix = ed25519_attestation_ix(&METADATA_SIGNER_SEED, &content_hash);
    let filler_ix = ed25519_attestation_ix(&WRONG_SIGNER_SEED, b"filler, unrelated attestation");
    let mint_ix = ix_mint_win_nft(winner.pubkey(), win_record, asset.pubkey(), "https://arweave.net/x".to_string(), content_hash);
    let res = send_multi(&mut svm, &winner, &[&winner, &asset], &[ed25519_ix, filler_ix, mint_ix]);
    assert_err_contains(&res, "InvalidMetadataSignature");

    let record = get_win_record(&svm, win_record).unwrap();
    assert!(!record.minted);
}

// ---------------------------------------------------------------------------
// Atomic settle() + ed25519 + mint_win_nft() happy path (plan §6)
// ---------------------------------------------------------------------------

/// Proves the whole point of the redesign's atomicity goal (plan §1/§4.4):
/// a single transaction, one signer, carrying `settle()` (which flips the
/// holder and creates the `WinRecord`), the Ed25519 metadata-signer
/// attestation, and `mint_win_nft()` -- all three succeed or fail together,
/// with no window where a flip has happened but minting hasn't (or can't)
/// yet occur.
#[test]
fn test_atomic_settle_ed25519_mint_win_nft_happy_path() {
    let (mut svm, global_state, vault, payer) = new_svm();

    let treasury = Keypair::new().pubkey();
    let admin = Keypair::new().pubkey();
    set_clock_ts(&mut svm, 1_000);
    send(&mut svm, &payer, ix_initialize(global_state, vault, payer.pubkey(), treasury, admin, 1_000_000)).unwrap();

    let winner = new_funded_keypair(&mut svm, 10_000_000_000);
    let gs0 = get_global_state(&svm, global_state);
    let bid = min_raise_amount(gs0.current_price, gs0.min_raise_bps);
    send(&mut svm, &winner, ix_challenge(global_state, vault, winner.pubkey(), Pubkey::default(), bid)).unwrap();

    let gs = get_global_state(&svm, global_state);
    set_clock_ts(&mut svm, gs.window_end_ts);
    let win_record = win_record_pda(gs.holder_count);
    let asset = Keypair::new();
    let content_hash = [21u8; 32];

    let settle_ix = ix_settle(global_state, vault, winner.pubkey(), INCINERATOR, win_record);
    let ed25519_ix = ed25519_attestation_ix(&METADATA_SIGNER_SEED, &content_hash);
    let mint_ix = ix_mint_win_nft(
        winner.pubkey(),
        win_record,
        asset.pubkey(),
        "https://arweave.net/atomic".to_string(),
        content_hash,
    );

    let res = send_multi(&mut svm, &winner, &[&winner, &asset], &[settle_ix, ed25519_ix, mint_ix]);
    assert!(res.is_ok(), "atomic settle+ed25519+mint transaction should succeed: {:?}", res.err());

    let record = get_win_record(&svm, win_record).unwrap();
    assert!(record.minted, "the same atomic transaction that created WinRecord must also have minted it");
    assert_eq!(record.winner, winner.pubkey());

    let asset_account = svm.get_account(&asset.pubkey()).expect("asset account must exist");
    assert_eq!(asset_account.owner, mpl_core::ID);
    let full_asset = mpl_core::Asset::deserialize(&asset_account.data).expect("asset data must parse with plugins");
    let attrs = full_asset
        .plugin_list
        .attributes
        .as_ref()
        .expect("Attributes plugin must be present")
        .attributes
        .attribute_list
        .clone();
    let find = |key: &str| attrs.iter().find(|a| a.key == key).map(|a| a.value.clone());
    assert_eq!(find("winner"), Some(record.winner.to_string()));
    assert_eq!(find("holder_count"), Some(record.holder_count.to_string()));
    assert_eq!(find("price_paid"), Some(record.price_paid.to_string()));
    assert_eq!(find("won_at"), Some(record.won_at.to_string()));

    let gs_final = get_global_state(&svm, global_state);
    assert_vault_invariant(&svm, vault, &gs_final);
}
