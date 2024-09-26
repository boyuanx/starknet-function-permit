#[starknet::contract]
mod FunctionPermit {
    use starknet::{ContractAddress, get_block_timestamp};
    use core::{hash::{HashStateTrait, HashStateExTrait}, poseidon::{PoseidonTrait}};
    use starknet_function_permit::{
        permit_interface::{IFunctionPermit, ISRC6Dispatcher, ISRC6DispatcherTrait},
        permit_struct::{Permit, PermitSignature, HashFelt252Span, HashPermitDataSpan}
    };

    #[storage]
    struct Storage {}

    const SRC_PERMIT_MAGIC_VALUE: felt252 = selector!("SRC_PERMIT_MAGIC_VALUE");
    const PERMIT_VALIDATION_ERROR: felt252 = 'PERMIT_VALIDATION_ERROR';
    const PERMIT_SIGNATURE_ERROR: felt252 = 'PERMIT_SIGNATURE_ERROR';

    #[abi(embed_v0)]
    impl FunctionPermitImpl of IFunctionPermit<ContractState> {
        fn is_valid_permit(
            self: @ContractState,
            src5_selector: felt252,
            params: Span<felt252>,
            operator: ContractAddress,
            permit_data_index: u32,
            permit: Permit,
            permit_signature: PermitSignature,
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
