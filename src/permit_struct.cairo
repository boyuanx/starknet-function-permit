use starknet::{ContractAddress};
use starknet_function_permit::permit_sample_impl::{HashFelt252Span, HashPermitDataSpan};

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
