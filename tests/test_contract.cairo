use starknet::{ContractAddress, get_block_timestamp};
use snforge_std::{
    declare, ContractClassTrait, DeclareResultTrait,
    signature::{KeyPairTrait, stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl}}
};
use openzeppelin::account::interface::{AccountABISafeDispatcher};
use starknet_function_permit::{
    permit_interface::{
        FunctionPermitConstants, IFunctionPermitSafeDispatcher, IFunctionPermitSafeDispatcherTrait
    },
    permit_struct::{Permit, PermitData, PermitSignature}
};

fn deploy_contract(name: ByteArray, constructor_calldata: Array<felt252>) -> ContractAddress {
    let contract = declare(name).unwrap().contract_class();
    let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
    contract_address
}

#[test]
#[feature("safe_dispatcher")]
/// This is by no means an exhaustive test case
/// It merely demonstrates the most basic case
fn test_permit() {
    /// Initializing MockAccount and Permit sample implementation
    let key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let account_contract_address = deploy_contract("MockAccount", array![key_pair.public_key]);
    let account_dispatcher = AccountABISafeDispatcher {
        contract_address: account_contract_address
    };
    let permit_contract_address = deploy_contract("FunctionPermit", array![]);
    let permit_dispatcher = IFunctionPermitSafeDispatcher {
        contract_address: permit_contract_address
    };
    /// Setting up PermitData
    let src5_selector = selector!("Test");
    let params = array!['123', '456'].span();
    let operator = '123456'.try_into().unwrap();
    let mut valid_from = get_block_timestamp();
    let mut valid_until = get_block_timestamp() + 100;
    let permit_data = PermitData { src5_selector, params, operator, valid_from, valid_until };
    /// Setting up Permit
    let src_permit_magic_value = FunctionPermitConstants::SRC_PERMIT_MAGIC_VALUE;
    let mut nonce = 1;
    let permit = Permit { src_permit_magic_value, nonce, data: array![permit_data].span() };
    let permit_hash = permit_dispatcher.get_permit_hash(permit).unwrap();
    /// Setting up PermitSignature
    let mut from = account_contract_address;
    let (r, s): (felt252, felt252) = key_pair.sign(permit_hash).unwrap();
    let permit_signature = PermitSignature { from, signature: array![r, s] };
    /// Trying to validate the permit
    match permit_dispatcher
        .is_valid_permit(src5_selector, params, operator, 0, permit, permit_signature) {
        Result::Ok(v) => assert(v == FunctionPermitConstants::SRC_PERMIT_MAGIC_VALUE, 'Failed'),
        Result::Err(panic_data) => { panic(panic_data); }
    };
}

