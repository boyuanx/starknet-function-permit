use starknet::ContractAddress;
use starknet_function_permit::permit_struct::{Permit, PermitSignature};

#[starknet::interface]
pub trait IFunctionPermit<TContractState> {
    fn get_permit_hash(self: @TContractState, permit: Permit) -> felt252;

    fn is_valid_permit(
        self: @TContractState,
        src5_selector: felt252,
        params: Span<felt252>,
        operator: ContractAddress,
        permit_data_index: u32,
        permit: Permit,
        permit_signature: PermitSignature,
    ) -> felt252;
}

#[starknet::interface]
pub trait ISRC6<TState> {
    fn is_valid_signature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;
}

pub mod FunctionPermitConstants {
    pub const SRC_PERMIT_MAGIC_VALUE: felt252 = selector!("SRC_PERMIT_MAGIC_VALUE");
    pub const SRC_PERMIT_DELEGATE_ALL_FUNCTIONS: felt252 = selector!("SRC_PERMIT_DELEGATE_ALL_FUNCTIONS");
    pub const SRC_PERMIT_DELEGATE_ALL_PARAMS: felt252 = selector!("SRC_PERMIT_DELEGATE_ALL_PARAMS");
    pub const PERMIT_VALIDATION_ERROR: felt252 = 'PERMIT_VALIDATION_ERROR';
    pub const PERMIT_SIGNATURE_ERROR: felt252 = 'PERMIT_SIGNATURE_ERROR';
}
