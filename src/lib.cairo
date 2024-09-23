use starknet::{ContractAddress};
use core::poseidon::{poseidon_hash_span};
use core::hash::{Hash, HashStateTrait, HashStateExTrait};

#[derive(Drop, Serde, Copy, Hash)]
pub struct Permit {
    pub src_permit_magic_value: felt252,
    pub nonce: felt252,
    pub data: Span<PermitData>,
}

#[derive(Drop, Serde, Copy, Hash)]
pub struct PermitData {
    pub src5_selector: felt252,
    pub params: Span<felt252>,
    pub operator: ContractAddress,
    pub valid_from: u64,
    pub valid_until: u64,
}

#[derive(Drop, Serde)]
pub struct PermitSignature {
    pub from: ContractAddress,
    pub signature: Array<felt252>,
}

impl HashFelt252Span<S, +HashStateTrait<S>, +Drop<S>> of Hash<Span<felt252>, S> {
    fn update_state(state: S, value: Span<felt252>) -> S {
        state.update_with(poseidon_hash_span(value))
    }
}

impl HashPermitDataSpan<S, +HashStateTrait<S>, +Drop<S>> of Hash<Span<PermitData>, S> {
    fn update_state(state: S, value: Span<PermitData>) -> S {
        let value_len = value.len();
        if value_len == 0 {
            return state;
        }
        let mut i = 1;
        let mut state_new = state.update_with(*value.at(0));
        loop {
            if i == value_len {
                break;
            }
            state_new = state_new.update_with(*value.at(i));
        };
        state_new
    }
}

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

#[starknet::contract]
mod FunctionPermit {
    use starknet::{ContractAddress, get_block_timestamp};
    use core::poseidon::{PoseidonTrait};
    use super::{HashFelt252Span, HashPermitDataSpan, ISRC6Dispatcher, ISRC6DispatcherTrait};
    use super::{HashStateTrait, HashStateExTrait};

    #[storage]
    struct Storage {}

    const SRC_PERMIT_MAGIC_VALUE: felt252 = selector!("SRC_PERMIT_MAGIC_VALUE");
    const PERMIT_VALIDATION_ERROR: felt252 = 'PERMIT_VALIDATION_ERROR';
    const PERMIT_SIGNATURE_ERROR: felt252 = 'PERMIT_SIGNATURE_ERROR';

    #[abi(embed_v0)]
    impl FunctionPermitImpl of super::IFunctionPermit<ContractState> {
        fn is_valid_permit(
            self: @ContractState,
            src5_selector: felt252,
            params: Span<felt252>,
            operator: ContractAddress,
            permit_data_index: u32,
            permit: super::Permit,
            permit_signature: super::PermitSignature,
        ) -> felt252 {
            let current_timestamp = get_block_timestamp();
            let data = *permit.data.at(permit_data_index);
            assert(
                SRC_PERMIT_MAGIC_VALUE == permit.src_permit_magic_value
                    && src5_selector == data.src5_selector
                    && params == data.params
                    && operator == data.operator
                    && current_timestamp >= data.valid_from
                    && current_timestamp < data.valid_until,
                PERMIT_VALIDATION_ERROR
            );
            let permit_hash = PoseidonTrait::new().update_with(permit).finalize();
            let from_account = ISRC6Dispatcher { contract_address: permit_signature.from };
            assert(
                from_account.is_valid_signature(permit_hash, permit_signature.signature) == 'VALID',
                PERMIT_SIGNATURE_ERROR
            );
            SRC_PERMIT_MAGIC_VALUE
        }
    }
}
