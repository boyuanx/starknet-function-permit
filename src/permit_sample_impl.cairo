use core::{hash::{Hash, HashStateTrait, HashStateExTrait}, poseidon::{poseidon_hash_span}};
use starknet_function_permit::{permit_struct::{Permit, PermitData}};

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

#[starknet::contract]
mod FunctionPermit {
    use starknet::{ContractAddress, get_block_timestamp};
    use core::{poseidon::{PoseidonTrait}};
    use starknet_function_permit::{
        permit_interface::{
            FunctionPermitConstants, IFunctionPermit, ISRC6Dispatcher, ISRC6DispatcherTrait
        },
        permit_struct::{PermitSignature}
    };
    use super::{HashStateTrait, HashStateExTrait, Permit};

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
