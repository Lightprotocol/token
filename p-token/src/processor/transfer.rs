use {
    super::{shared, unpack_amount},
    pinocchio::{account_info::AccountInfo, ProgramResult},
};

#[inline(always)]
pub fn process_transfer(
    accounts: &[AccountInfo],
    instruction_data: &[u8],
    signer_is_validated: bool,
) -> ProgramResult {
    let amount = unpack_amount(instruction_data)?;

    shared::transfer::process_transfer(accounts, amount, None, signer_is_validated)
}
