use starknet::ContractAddress;
use starknet_function_permit::permit_struct::{Permit, PermitSignature};

#[starknet::interface]
pub trait IFunctionPermit<TContractState> {
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
