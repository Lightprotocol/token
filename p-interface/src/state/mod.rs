use pinocchio::program_error::ProgramError;

pub mod account;
pub mod account_state;
pub mod mint;
pub mod multisig;

/// Type alias for fields represented as `COption`.
pub type COption<T> = ([u8; 4], T);

/// AccountType discriminator for Mint accounts (at byte 82 for extended mints).
pub const ACCOUNT_TYPE_MINT: u8 = 1;

/// AccountType discriminator for Token accounts (at byte 165 for extended accounts).
pub const ACCOUNT_TYPE_TOKEN_ACCOUNT: u8 = 2;

/// Marker trait for types that can be cast from a raw pointer.
///
/// # Safety
///
/// It is up to the type implementing this trait to guarantee that the cast is
/// safe, i.e., the fields of the type are well aligned and there are no padding
/// bytes.
pub unsafe trait Transmutable {
    /// The length of the type.
    ///
    /// This must be equal to the size of each individual field in the type.
    const LEN: usize;

    /// The expected AccountType discriminator value at byte offset `LEN` for extended accounts.
    /// Used to validate account type when `bytes.len() > LEN`.
    const ACCOUNT_TYPE: u8;
}

/// Trait to represent a type that can be initialized.
pub trait Initializable {
    /// Return `true` if the object is initialized.
    fn is_initialized(&self) -> Result<bool, ProgramError>;
}

/// Return a reference for an initialized `T` from the given bytes.
///
/// # Safety
///
/// The caller must ensure that `bytes` contains a valid representation of `T`.
#[inline(always)]
pub unsafe fn load<T: Initializable + Transmutable>(bytes: &[u8]) -> Result<&T, ProgramError> {
    load_unchecked(&bytes).and_then(|t: &T| {
        // checks if the data is initialized
        if t.is_initialized()? {
            Ok(t)
        } else {
            Err(ProgramError::UninitializedAccount)
        }
    })
}

/// Byte offset of AccountType discriminator in extended accounts.
pub const ACCOUNT_TYPE_OFFSET: usize = 165;

/// Return a `T` reference from the given bytes.
///
/// This function does not check if the data is initialized.
///
/// Accepts:
/// - Exact length match: `bytes.len() == T::LEN` (standard account)
/// - Extended account: `bytes.len() > ACCOUNT_TYPE_OFFSET` with matching AccountType at byte 165
///
/// Rejects everything else (too short, ambiguous size, wrong AccountType).
///
/// # Safety
///
/// The caller must ensure that `bytes` contains a valid representation of `T`.
#[inline(always)]
pub unsafe fn load_unchecked<T: Transmutable>(bytes: &[u8]) -> Result<&T, ProgramError> {
    if bytes.len() == T::LEN {
        return Ok(&*(bytes[..T::LEN].as_ptr() as *const T));
    }
    if bytes.len() > ACCOUNT_TYPE_OFFSET && bytes[ACCOUNT_TYPE_OFFSET] == T::ACCOUNT_TYPE {
        return Ok(&*(bytes[..T::LEN].as_ptr() as *const T));
    }
    Err(ProgramError::InvalidAccountData)
}

/// Return a mutable reference for an initialized `T` from the given bytes.
///
/// # Safety
///
/// The caller must ensure that `bytes` contains a valid representation of `T`.
#[inline(always)]
pub unsafe fn load_mut<T: Initializable + Transmutable>(
    bytes: &mut [u8],
) -> Result<&mut T, ProgramError> {
    load_mut_unchecked(bytes).and_then(|t: &mut T| {
        // checks if the data is initialized
        if t.is_initialized()? {
            Ok(t)
        } else {
            Err(ProgramError::UninitializedAccount)
        }
    })
}

/// Return a mutable `T` reference from the given bytes.
///
/// This function does not check if the data is initialized.
///
/// Accepts:
/// - Exact length match: `bytes.len() == T::LEN` (standard account)
/// - Extended account: `bytes.len() > ACCOUNT_TYPE_OFFSET` with matching AccountType at byte 165
///
/// Rejects everything else (too short, ambiguous size, wrong AccountType).
///
/// # Safety
///
/// The caller must ensure that `bytes` contains a valid representation of `T`.
#[inline(always)]
pub unsafe fn load_mut_unchecked<T: Transmutable>(
    bytes: &mut [u8],
) -> Result<&mut T, ProgramError> {
    if bytes.len() == T::LEN {
        return Ok(&mut *(bytes[..T::LEN].as_mut_ptr() as *mut T));
    }
    if bytes.len() > ACCOUNT_TYPE_OFFSET && bytes[ACCOUNT_TYPE_OFFSET] == T::ACCOUNT_TYPE {
        return Ok(&mut *(bytes[..T::LEN].as_mut_ptr() as *mut T));
    }
    Err(ProgramError::InvalidAccountData)
}
