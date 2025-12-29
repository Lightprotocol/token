# p-token

A `pinocchio`-based Token program with library support for external program integration.

## Overview

`p-token` is a reimplementation of the SPL Token program using [`pinocchio`](https://github.com/anza-xyz/pinocchio). Optimizes compute units while maintaining full compatibility with SPL Token instruction and account layouts.

## Features

- Same instruction and account layout as SPL Token
- Minimal CU usage
- Library mode for external program integration
- Token-2022 extension account compatibility

## Changes (jorrit/refactor branch)

### 1. Transfer Authority Pre-validation Parameter

**path:** `src/processor/shared/transfer.rs:14-17, 127-152`

Added `signer_is_validated: bool` parameter to transfer functions.

**behavior:**
- `false` (default): Full authority validation via `validate_owner()` - checks owner/delegate and signer status
- `true`: Authority validation skipped - caller has already validated authority externally

**affected functions:**
- `shared::transfer::process_transfer(accounts, amount, expected_decimals, signer_is_validated)`
- `transfer::process_transfer(accounts, instruction_data, signer_is_validated)`
- `transfer_checked::process_transfer_checked(accounts, instruction_data, signer_is_validated)`

**usage:** External programs (e.g., compressed-token) validate permanent delegate authority before calling p-token, then pass `signer_is_validated=true` to avoid redundant validation.

**security requirement:** Caller MUST verify `authority.is_signer()` before setting `signer_is_validated=true`. Failure to do so enables unauthorized transfers.

### 2. Account Size Validation with AccountType Check

**path:** `../p-interface/src/state/mod.rs:58-81, 102-124`

`load_unchecked` and `load_mut_unchecked` now accept accounts larger than `T::LEN` and validate AccountType.

**before:**
```rust
if bytes.len() != T::LEN {
    return Err(ProgramError::InvalidAccountData);
}
Ok(&*(bytes.as_ptr() as *const T))
```

**after:**
```rust
if bytes.len() < T::LEN {
    return Err(ProgramError::InvalidAccountData);
}
// For extended accounts (>165 bytes), validate AccountType at byte 165
if bytes.len() > ACCOUNT_TYPE_OFFSET && bytes[ACCOUNT_TYPE_OFFSET] != T::ACCOUNT_TYPE {
    return Err(ProgramError::InvalidAccountData);
}
Ok(&*(bytes[..T::LEN].as_ptr() as *const T))
```

**purpose:** Enables processing of Token-2022 extension accounts (165+ bytes) while preventing type confusion.

**security:**
- Minimum size validated to prevent buffer underflow
- AccountType discriminator at byte 165 validated for extended accounts:
  - `ACCOUNT_TYPE_MINT = 1` for Mint accounts
  - `ACCOUNT_TYPE_TOKEN_ACCOUNT = 2` for Token accounts
- Prevents loading a Mint as Account or vice versa when extensions present

### 3. Library Conversion

**path:** `Cargo.toml`, `src/lib.rs`

**changes:**
- `crate-type = ["cdylib", "lib"]` - enables both program deployment and library import
- `pub mod processor` - exports processor functions for external use
- Removed `#![no_std]` from lib.rs root (processor module retains no_std behavior)

**purpose:** Allows external programs to import and call p-token functions directly instead of via CPI.

### 4. Public API Addition

**path:** `src/processor/mod.rs:206`

`unpack_amount_and_decimals` made public:
```rust
pub const fn unpack_amount_and_decimals(instruction_data: &[u8]) -> Result<(u64, u8), TokenError>
```

**purpose:** Enables external programs to parse transfer_checked instruction data.

### 5. Program ID Change

**path:** `../p-interface/src/lib.rs:9`

Program ID updated from `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` to `cTokenmWW8bLPjZEBAUgYy3zKxQZW6VKi7bqNFEVv3m`.

**purpose:** Distinguishes p-token/ctoken deployments from standard SPL Token program.

## Integration Pattern

External programs using p-token as a library:

1. Validate authority externally (e.g., permanent delegate check with `is_signer()`)
2. Call p-token transfer with appropriate `signer_is_validated` flag:

```rust
use pinocchio_token_program::processor::shared::transfer::process_transfer;

// After validating permanent delegate is signer
let signer_is_validated = validate_permanent_delegate(mint_checks, authority)?;

// Call p-token - authority validation skipped if signer_is_validated=true
process_transfer(accounts, amount, expected_decimals, signer_is_validated)?;
```

## Unsupported Features

**Multisig:** Multisig accounts are not supported. The AccountType validation at byte 165 does not handle Multisig accounts (355 bytes), which have no discriminator at that offset. Token-2022 handles this via size exclusion (`!= 355`), but this implementation assumes no multisig usage.

**Batch module:** Commented out in mod.rs. Batch instruction processing (discriminator 255) currently disabled.

## License

The code is licensed under the [Apache License Version 2.0](LICENSE)
