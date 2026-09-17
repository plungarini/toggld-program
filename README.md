# toggld-program

The on-chain Solana program behind [toggld.win](https://toggld.win): a single toggle with exactly
one holder at a time. Anyone can open a 30-second bidding window to challenge the holder; the
winner either flips the toggle (new holder) or, if already holder, pays to defend it. Every
winning payment splits 15% to the treasury and 85% burned, on-chain, unconditionally.

This is a synced source extract from toggld.win's application monorepo, published so the deployed
program can be independently verified against its source. It is not the primary development
repository; issues and pull requests here are out of scope for anything outside the Anchor
program itself.

## Building

```
anchor build
```

## Verifying against the deployed program

```
solana-verify build --library-name toggld --base-image solanafoundation/solana-verifiable-build:3.1.11
solana-verify get-executable-hash target/deploy/toggld.so
```

The default `solana-verify` image ships an older cargo that predates Rust's `edition2024`
stabilization and fails to resolve this crate's dependency tree; pin `--base-image` as above.

Compare the resulting hash against the live program:

```
solana-verify get-program-hash -u mainnet-beta <PROGRAM_ADDRESS>
```

## Testing

Integration tests run against [LiteSVM](https://github.com/LiteSVM/litesvm), no local validator
required:

```
cargo test
```

## Security

See the `security.txt` embedded in the deployed program binary (readable with any
[security.txt](https://github.com/neodyme-labs/solana-security-txt) reader), or the contact and
disclosure policy linked from [toggld.win/legal/risk-disclosure](https://toggld.win/legal/risk-disclosure).

## License

MIT, see [LICENSE](./LICENSE).
