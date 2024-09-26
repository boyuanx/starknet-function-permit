use starknet::{ContractAddress};
use core::{hash::{Hash, HashStateTrait, HashStateExTrait}, poseidon::{poseidon_hash_span}};

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

pub impl HashFelt252Span<S, +HashStateTrait<S>, +Drop<S>> of Hash<Span<felt252>, S> {
    fn update_state(state: S, value: Span<felt252>) -> S {
        state.update_with(poseidon_hash_span(value))
    }
}

pub impl HashPermitDataSpan<S, +HashStateTrait<S>, +Drop<S>> of Hash<Span<PermitData>, S> {
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
