#[starknet::contract]
mod FunctionPermit {
    use starknet::{ContractAddress, get_block_timestamp};
    use core::{hash::{HashStateTrait, HashStateExTrait}, poseidon::{PoseidonTrait}};
    use starknet_function_permit::{
        permit_interface::{
            FunctionPermitConstants, IFunctionPermit, ISRC6Dispatcher, ISRC6DispatcherTrait
        },
        permit_struct::{Permit, PermitSignature, HashFelt252Span, HashPermitDataSpan}
    };

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl FunctionPermitImpl of IFunctionPermit<ContractState> {
        fn get_permit_hash(self: @ContractState, permit: Permit) -> felt252 {
            PoseidonTrait::new().update_with(permit).finalize()
        }

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
                FunctionPermitConstants::SRC_PERMIT_MAGIC_VALUE == permit.src_permit_magic_value
                    && (data.src5_selector == src5_selector
                        || data
                            .src5_selector == FunctionPermitConstants::SRC_PERMIT_DELEGATE_ALL_FUNCTIONS)
                    && (data.params == params
                        || (data.params.len() == 1
                            && *data
                                .params
                                .at(0) == FunctionPermitConstants::SRC_PERMIT_DELEGATE_ALL_PARAMS))
                    && data.operator == operator
                    && data.valid_from <= current_timestamp
                    && data.valid_until > current_timestamp,
                FunctionPermitConstants::PERMIT_VALIDATION_ERROR
            );
            let permit_hash = self.get_permit_hash(permit);
            let from_account = ISRC6Dispatcher { contract_address: permit_signature.from };
            assert(
                from_account.is_valid_signature(permit_hash, permit_signature.signature) == 'VALID',
                FunctionPermitConstants::PERMIT_SIGNATURE_ERROR
            );
            FunctionPermitConstants::SRC_PERMIT_MAGIC_VALUE
        }
    }
}
