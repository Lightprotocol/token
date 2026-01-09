//! Tests for load_unchecked and load_mut_unchecked AccountType validation.
//!
//! These tests verify that the account loading functions properly validate
//! account types to prevent type confusion vulnerabilities (e.g., loading
//! a Token account as a Mint).

use pinocchio_token_interface::state::{
    account::Account, load_mut_unchecked, load_unchecked, mint::Mint, Transmutable,
    ACCOUNT_TYPE_MINT, ACCOUNT_TYPE_OFFSET, ACCOUNT_TYPE_TOKEN_ACCOUNT,
};

// ============================================================================
// load_unchecked tests
// ============================================================================

#[test]
fn test_load_unchecked_exact_length_mint() {
    // Standard Mint (82 bytes) should load as Mint
    let data = vec![0u8; Mint::LEN];
    let result = unsafe { load_unchecked::<Mint>(&data) };
    assert!(result.is_ok());
}

#[test]
fn test_load_unchecked_exact_length_account() {
    // Standard Account (165 bytes) should load as Account
    let data = vec![0u8; Account::LEN];
    let result = unsafe { load_unchecked::<Account>(&data) };
    assert!(result.is_ok());
}

#[test]
fn test_load_unchecked_rejects_token_as_mint() {
    // CRITICAL: 165-byte Token account data should NOT load as Mint
    // This is the main vulnerability being fixed
    let data = vec![0u8; Account::LEN]; // 165 bytes
    let result = unsafe { load_unchecked::<Mint>(&data) };
    assert!(
        result.is_err(),
        "Should reject Token account loaded as Mint"
    );
}

#[test]
fn test_load_unchecked_rejects_ambiguous_size_as_mint() {
    // Data between Mint::LEN (82) and ACCOUNT_TYPE_OFFSET (165) should be rejected
    // because we can't verify the type without a discriminator
    let data = vec![0u8; 100]; // 82 < 100 < 165
    let result = unsafe { load_unchecked::<Mint>(&data) };
    assert!(
        result.is_err(),
        "Should reject ambiguous size without discriminator"
    );
}

#[test]
fn test_load_unchecked_rejects_extended_token_as_mint() {
    // Extended Token account (>165 bytes, type=2) should NOT load as Mint
    let mut data = vec![0u8; 200];
    data[ACCOUNT_TYPE_OFFSET] = ACCOUNT_TYPE_TOKEN_ACCOUNT; // type = 2
    let result = unsafe { load_unchecked::<Mint>(&data) };
    assert!(
        result.is_err(),
        "Should reject extended Token loaded as Mint"
    );
}

#[test]
fn test_load_unchecked_rejects_extended_mint_as_account() {
    // Extended Mint (>165 bytes, type=1) should NOT load as Account
    let mut data = vec![0u8; 200];
    data[ACCOUNT_TYPE_OFFSET] = ACCOUNT_TYPE_MINT; // type = 1
    let result = unsafe { load_unchecked::<Account>(&data) };
    assert!(
        result.is_err(),
        "Should reject extended Mint loaded as Account"
    );
}

#[test]
fn test_load_unchecked_accepts_extended_mint() {
    // Extended Mint (>165 bytes, type=1) should load as Mint
    let mut data = vec![0u8; 200];
    data[ACCOUNT_TYPE_OFFSET] = ACCOUNT_TYPE_MINT; // type = 1
    let result = unsafe { load_unchecked::<Mint>(&data) };
    assert!(
        result.is_ok(),
        "Should accept extended Mint with correct type"
    );
}

#[test]
fn test_load_unchecked_accepts_extended_account() {
    // Extended Account (>165 bytes, type=2) should load as Account
    let mut data = vec![0u8; 200];
    data[ACCOUNT_TYPE_OFFSET] = ACCOUNT_TYPE_TOKEN_ACCOUNT; // type = 2
    let result = unsafe { load_unchecked::<Account>(&data) };
    assert!(
        result.is_ok(),
        "Should accept extended Account with correct type"
    );
}

#[test]
fn test_load_unchecked_rejects_too_short_for_mint() {
    let data = vec![0u8; 50]; // Too short for Mint (82 bytes)
    let result = unsafe { load_unchecked::<Mint>(&data) };
    assert!(result.is_err(), "Should reject data shorter than Mint::LEN");
}

#[test]
fn test_load_unchecked_rejects_too_short_for_account() {
    let data = vec![0u8; 100]; // Too short for Account (165 bytes)
    let result = unsafe { load_unchecked::<Account>(&data) };
    assert!(
        result.is_err(),
        "Should reject data shorter than Account::LEN"
    );
}

// ============================================================================
// load_mut_unchecked tests
// ============================================================================

#[test]
fn test_load_mut_unchecked_exact_length_mint() {
    let mut data = vec![0u8; Mint::LEN];
    let result = unsafe { load_mut_unchecked::<Mint>(&mut data) };
    assert!(result.is_ok());
}

#[test]
fn test_load_mut_unchecked_exact_length_account() {
    let mut data = vec![0u8; Account::LEN];
    let result = unsafe { load_mut_unchecked::<Account>(&mut data) };
    assert!(result.is_ok());
}

#[test]
fn test_load_mut_unchecked_rejects_token_as_mint() {
    // CRITICAL: Same vulnerability check for mutable reference
    let mut data = vec![0u8; Account::LEN];
    let result = unsafe { load_mut_unchecked::<Mint>(&mut data) };
    assert!(
        result.is_err(),
        "Should reject Token account loaded as mutable Mint"
    );
}

#[test]
fn test_load_mut_unchecked_rejects_ambiguous_size_as_mint() {
    let mut data = vec![0u8; 100];
    let result = unsafe { load_mut_unchecked::<Mint>(&mut data) };
    assert!(
        result.is_err(),
        "Should reject ambiguous size without discriminator"
    );
}

#[test]
fn test_load_mut_unchecked_accepts_extended_mint() {
    let mut data = vec![0u8; 200];
    data[ACCOUNT_TYPE_OFFSET] = ACCOUNT_TYPE_MINT;
    let result = unsafe { load_mut_unchecked::<Mint>(&mut data) };
    assert!(
        result.is_ok(),
        "Should accept extended Mint with correct type"
    );
}

#[test]
fn test_load_mut_unchecked_accepts_extended_account() {
    let mut data = vec![0u8; 200];
    data[ACCOUNT_TYPE_OFFSET] = ACCOUNT_TYPE_TOKEN_ACCOUNT;
    let result = unsafe { load_mut_unchecked::<Account>(&mut data) };
    assert!(
        result.is_ok(),
        "Should accept extended Account with correct type"
    );
}

#[test]
fn test_load_mut_unchecked_rejects_extended_token_as_mint() {
    let mut data = vec![0u8; 200];
    data[ACCOUNT_TYPE_OFFSET] = ACCOUNT_TYPE_TOKEN_ACCOUNT;
    let result = unsafe { load_mut_unchecked::<Mint>(&mut data) };
    assert!(
        result.is_err(),
        "Should reject extended Token loaded as mutable Mint"
    );
}

#[test]
fn test_load_mut_unchecked_rejects_extended_mint_as_account() {
    let mut data = vec![0u8; 200];
    data[ACCOUNT_TYPE_OFFSET] = ACCOUNT_TYPE_MINT;
    let result = unsafe { load_mut_unchecked::<Account>(&mut data) };
    assert!(
        result.is_err(),
        "Should reject extended Mint loaded as mutable Account"
    );
}
