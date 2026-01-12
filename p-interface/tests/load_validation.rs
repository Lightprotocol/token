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

#[test]
fn test_load_unchecked_rejects_size_83_as_mint() {
    // Boundary test: size 83 (just above Mint::LEN of 82)
    let data = vec![0u8; 83];
    let result = unsafe { load_unchecked::<Mint>(&data) };
    assert!(
        result.is_err(),
        "Should reject size just above Mint::LEN without discriminator"
    );
}

#[test]
fn test_load_unchecked_rejects_size_164_as_mint() {
    // Boundary test: size 164 (one below ACCOUNT_TYPE_OFFSET of 165)
    let data = vec![0u8; 164];
    let result = unsafe { load_unchecked::<Mint>(&data) };
    assert!(
        result.is_err(),
        "Should reject size just below ACCOUNT_TYPE_OFFSET"
    );
}

#[test]
fn test_load_unchecked_rejects_mint_as_account() {
    // Boundary test: 82-byte Mint data should NOT load as Account (165 bytes)
    let data = vec![0u8; Mint::LEN]; // 82 bytes
    let result = unsafe { load_unchecked::<Account>(&data) };
    assert!(
        result.is_err(),
        "Should reject Mint-sized data loaded as Account"
    );
}

#[test]
fn test_load_unchecked_rejects_empty_data() {
    let data = vec![0u8; 0];
    let result = unsafe { load_unchecked::<Mint>(&data) };
    assert!(result.is_err(), "Should reject empty data");
}

#[test]
fn test_load_unchecked_rejects_size_81_as_mint() {
    // Boundary test: size 81 (just below Mint::LEN of 82)
    let data = vec![0u8; 81];
    let result = unsafe { load_unchecked::<Mint>(&data) };
    assert!(result.is_err(), "Should reject size just below Mint::LEN");
}

#[test]
fn test_load_unchecked_rejects_size_164_as_account() {
    // Boundary test: size 164 (just below Account::LEN of 165)
    let data = vec![0u8; 164];
    let result = unsafe { load_unchecked::<Account>(&data) };
    assert!(
        result.is_err(),
        "Should reject size just below Account::LEN"
    );
}

#[test]
fn test_load_unchecked_accepts_size_166_as_mint() {
    // Boundary test: minimal extended account (166 bytes, just above ACCOUNT_TYPE_OFFSET)
    let mut data = vec![0u8; 166];
    data[ACCOUNT_TYPE_OFFSET] = ACCOUNT_TYPE_MINT;
    let result = unsafe { load_unchecked::<Mint>(&data) };
    assert!(
        result.is_ok(),
        "Should accept minimal extended Mint (166 bytes)"
    );
}

#[test]
fn test_load_unchecked_accepts_size_166_as_account() {
    // Boundary test: minimal extended account (166 bytes, just above ACCOUNT_TYPE_OFFSET)
    let mut data = vec![0u8; 166];
    data[ACCOUNT_TYPE_OFFSET] = ACCOUNT_TYPE_TOKEN_ACCOUNT;
    let result = unsafe { load_unchecked::<Account>(&data) };
    assert!(
        result.is_ok(),
        "Should accept minimal extended Account (166 bytes)"
    );
}

#[test]
fn test_load_unchecked_rejects_size_166_with_type_0() {
    // Size 166 with type=0 should be rejected for both Mint and Account
    let mut data = vec![0u8; 166];
    data[ACCOUNT_TYPE_OFFSET] = 0;
    let result_mint = unsafe { load_unchecked::<Mint>(&data) };
    let result_account = unsafe { load_unchecked::<Account>(&data) };
    assert!(result_mint.is_err(), "Should reject type=0 as Mint");
    assert!(result_account.is_err(), "Should reject type=0 as Account");
}

#[test]
fn test_load_unchecked_rejects_size_166_with_invalid_type() {
    // Size 166 with invalid type values should be rejected
    let mut data = vec![0u8; 166];
    data[ACCOUNT_TYPE_OFFSET] = 255; // Invalid type
    let result_mint = unsafe { load_unchecked::<Mint>(&data) };
    let result_account = unsafe { load_unchecked::<Account>(&data) };
    assert!(result_mint.is_err(), "Should reject invalid type as Mint");
    assert!(
        result_account.is_err(),
        "Should reject invalid type as Account"
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

#[test]
fn test_load_mut_unchecked_rejects_size_83_as_mint() {
    // Boundary test: size 83 (just above Mint::LEN of 82)
    let mut data = vec![0u8; 83];
    let result = unsafe { load_mut_unchecked::<Mint>(&mut data) };
    assert!(
        result.is_err(),
        "Should reject size just above Mint::LEN without discriminator"
    );
}

#[test]
fn test_load_mut_unchecked_rejects_size_164_as_mint() {
    // Boundary test: size 164 (one below ACCOUNT_TYPE_OFFSET of 165)
    let mut data = vec![0u8; 164];
    let result = unsafe { load_mut_unchecked::<Mint>(&mut data) };
    assert!(
        result.is_err(),
        "Should reject size just below ACCOUNT_TYPE_OFFSET"
    );
}

#[test]
fn test_load_mut_unchecked_rejects_mint_as_account() {
    // Boundary test: 82-byte Mint data should NOT load as Account (165 bytes)
    let mut data = vec![0u8; Mint::LEN]; // 82 bytes
    let result = unsafe { load_mut_unchecked::<Account>(&mut data) };
    assert!(
        result.is_err(),
        "Should reject Mint-sized data loaded as mutable Account"
    );
}

#[test]
fn test_load_mut_unchecked_rejects_empty_data() {
    let mut data = vec![0u8; 0];
    let result = unsafe { load_mut_unchecked::<Mint>(&mut data) };
    assert!(result.is_err(), "Should reject empty data");
}

#[test]
fn test_load_mut_unchecked_rejects_size_81_as_mint() {
    let mut data = vec![0u8; 81];
    let result = unsafe { load_mut_unchecked::<Mint>(&mut data) };
    assert!(result.is_err(), "Should reject size just below Mint::LEN");
}

#[test]
fn test_load_mut_unchecked_rejects_size_164_as_account() {
    let mut data = vec![0u8; 164];
    let result = unsafe { load_mut_unchecked::<Account>(&mut data) };
    assert!(
        result.is_err(),
        "Should reject size just below Account::LEN"
    );
}

#[test]
fn test_load_mut_unchecked_accepts_size_166_as_mint() {
    let mut data = vec![0u8; 166];
    data[ACCOUNT_TYPE_OFFSET] = ACCOUNT_TYPE_MINT;
    let result = unsafe { load_mut_unchecked::<Mint>(&mut data) };
    assert!(
        result.is_ok(),
        "Should accept minimal extended Mint (166 bytes)"
    );
}

#[test]
fn test_load_mut_unchecked_accepts_size_166_as_account() {
    let mut data = vec![0u8; 166];
    data[ACCOUNT_TYPE_OFFSET] = ACCOUNT_TYPE_TOKEN_ACCOUNT;
    let result = unsafe { load_mut_unchecked::<Account>(&mut data) };
    assert!(
        result.is_ok(),
        "Should accept minimal extended Account (166 bytes)"
    );
}

#[test]
fn test_load_mut_unchecked_rejects_size_166_with_type_0() {
    let mut data = vec![0u8; 166];
    data[ACCOUNT_TYPE_OFFSET] = 0;
    let result_mint = unsafe { load_mut_unchecked::<Mint>(&mut data) };
    let mut data2 = vec![0u8; 166];
    data2[ACCOUNT_TYPE_OFFSET] = 0;
    let result_account = unsafe { load_mut_unchecked::<Account>(&mut data2) };
    assert!(result_mint.is_err(), "Should reject type=0 as Mint");
    assert!(result_account.is_err(), "Should reject type=0 as Account");
}

#[test]
fn test_load_mut_unchecked_rejects_size_166_with_invalid_type() {
    let mut data = vec![0u8; 166];
    data[ACCOUNT_TYPE_OFFSET] = 255;
    let result_mint = unsafe { load_mut_unchecked::<Mint>(&mut data) };
    let mut data2 = vec![0u8; 166];
    data2[ACCOUNT_TYPE_OFFSET] = 255;
    let result_account = unsafe { load_mut_unchecked::<Account>(&mut data2) };
    assert!(result_mint.is_err(), "Should reject invalid type as Mint");
    assert!(
        result_account.is_err(),
        "Should reject invalid type as Account"
    );
}

// ============================================================================
// Randomized fuzz tests
// ============================================================================

#[test]
fn test_load_unchecked_fuzz_rejects_invalid_random_data() {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    for i in 0..1_000_000 {
        // Random size between 0 and 500
        let size = rng.gen_range(0..500);
        let mut data: Vec<u8> = (0..size).map(|_| rng.gen()).collect();

        // If size > ACCOUNT_TYPE_OFFSET, ensure byte[165] is never 1 or 2
        if size > ACCOUNT_TYPE_OFFSET {
            while data[ACCOUNT_TYPE_OFFSET] == ACCOUNT_TYPE_MINT
                || data[ACCOUNT_TYPE_OFFSET] == ACCOUNT_TYPE_TOKEN_ACCOUNT
            {
                data[ACCOUNT_TYPE_OFFSET] = rng.gen();
            }
        }

        // Skip exact length matches (these are valid cases)
        if size == Mint::LEN || size == Account::LEN {
            continue;
        }

        let result_mint = unsafe { load_unchecked::<Mint>(&data) };
        let result_account = unsafe { load_unchecked::<Account>(&data) };

        assert!(
            result_mint.is_err(),
            "Iteration {}: Should reject random data (size={}) as Mint",
            i,
            size
        );
        assert!(
            result_account.is_err(),
            "Iteration {}: Should reject random data (size={}) as Account",
            i,
            size
        );
    }
}
