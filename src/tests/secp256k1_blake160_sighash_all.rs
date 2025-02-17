use super::{blake160, sign_tx, DummyDataLoader, MAX_CYCLES, SECP256K1_DATA_BIN, SIGHASH_ALL_BIN};
use ckb_crypto::secp::{Generator, Privkey};
use ckb_script::{ScriptConfig, ScriptError, TransactionScriptsVerifier};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMetaBuilder, ResolvedTransaction},
        Capacity, ScriptHashType, TransactionBuilder, TransactionView,
    },
    packed::{CellDep, CellInput, CellOutput, OutPoint, Script},
    prelude::*,
    H256,
};
use rand::{thread_rng, Rng};

const ERROR_PUBKEY_BLAKE160_HASH: i8 = -3;
const ERROR_WITNESS_TOO_LONG: i8 = -12;

fn gen_tx(
    dummy: &mut DummyDataLoader,
    script_data: Bytes,
    lock_args: Vec<Bytes>,
) -> TransactionView {
    let previous_tx_hash = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        H256::from(&buf)
    };
    let previous_index = 0;
    let capacity = Capacity::shannons(42);
    let previous_out_point = OutPoint::new(previous_tx_hash, previous_index);
    let contract_tx_hash = {
        let mut rng = thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        H256::from(&buf)
    };
    let contract_index = 0;
    let contract_out_point = OutPoint::new(contract_tx_hash.clone(), contract_index);
    // dep contract code
    let dep_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(script_data.len())
                .expect("script capacity")
                .pack(),
        )
        .build();
    let dep_cell_data_hash = CellOutput::calc_data_hash(&script_data).pack();
    dummy
        .cells
        .insert(contract_out_point.clone(), (dep_cell, script_data));
    // secp256k1 data
    let secp256k1_data_out_point = {
        let tx_hash = {
            let mut rng = thread_rng();
            let mut buf = [0u8; 32];
            rng.fill(&mut buf);
            H256::from(&buf)
        };
        OutPoint::new(tx_hash, 0)
    };
    let secp256k1_data_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(SECP256K1_DATA_BIN.len())
                .expect("data capacity")
                .pack(),
        )
        .build();
    dummy.cells.insert(
        secp256k1_data_out_point.clone(),
        (secp256k1_data_cell, SECP256K1_DATA_BIN.clone()),
    );
    // input unlock script
    let script = Script::new_builder()
        .args(lock_args.pack())
        .code_hash(dep_cell_data_hash)
        .hash_type(ScriptHashType::Data.pack())
        .build();
    let previous_output_cell = CellOutput::new_builder()
        .capacity(capacity.pack())
        .lock(script)
        .build();
    dummy.cells.insert(
        previous_out_point.clone(),
        (previous_output_cell, Bytes::new()),
    );
    TransactionBuilder::default()
        .input(CellInput::new(previous_out_point.clone(), 0))
        .cell_dep(CellDep::new(contract_out_point, false))
        .cell_dep(CellDep::new(secp256k1_data_out_point, false))
        .output(CellOutput::new_builder().capacity(capacity.pack()).build())
        .output_data(Bytes::new().pack())
        .build()
}

fn sign_tx_hash(tx: TransactionView, key: &Privkey, tx_hash: &[u8]) -> TransactionView {
    // calculate message
    let mut blake2b = ckb_hash::new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(tx_hash);
    blake2b.finalize(&mut message);
    let message = H256::from(message);
    let sig = key.sign_recoverable(&message).expect("sign");
    tx.as_advanced_builder()
        .witness(vec![Bytes::from(sig.serialize()).pack()].pack())
        .build()
}

fn build_resolved_tx<'a>(
    data_loader: &DummyDataLoader,
    tx: &'a TransactionView,
) -> ResolvedTransaction<'a> {
    let previous_out_point = tx
        .inputs()
        .get(0)
        .expect("should have at least one input")
        .previous_output();
    let resolved_cell_deps = tx
        .cell_deps()
        .into_iter()
        .map(|dep| {
            let deps_out_point = dep.clone();
            let (dep_output, dep_data) =
                data_loader.cells.get(&deps_out_point.out_point()).unwrap();
            CellMetaBuilder::from_cell_output(dep_output.to_owned(), dep_data.to_owned())
                .out_point(deps_out_point.out_point().clone())
                .build()
        })
        .collect();
    let (input_output, input_data) = data_loader.cells.get(&previous_out_point).unwrap();
    let input_cell =
        CellMetaBuilder::from_cell_output(input_output.to_owned(), input_data.to_owned())
            .out_point(previous_out_point)
            .build();
    ResolvedTransaction {
        transaction: tx,
        resolved_cell_deps,
        resolved_inputs: vec![input_cell],
        resolved_dep_groups: vec![],
    }
}

#[test]
fn test_sighash_all_unlock() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());
    let tx = gen_tx(&mut data_loader, SIGHASH_ALL_BIN.clone(), vec![pubkey_hash]);
    let tx = sign_tx(tx, &privkey);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let script_config = ScriptConfig::default();
    let verify_result = TransactionScriptsVerifier::new(&resolved_tx, &data_loader, &script_config)
        .verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_signing_with_wrong_key() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let wrong_privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());
    let tx = gen_tx(&mut data_loader, SIGHASH_ALL_BIN.clone(), vec![pubkey_hash]);
    let tx = sign_tx(tx, &wrong_privkey);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let script_config = ScriptConfig::default();
    let verify_result = TransactionScriptsVerifier::new(&resolved_tx, &data_loader, &script_config)
        .verify(MAX_CYCLES);
    assert_eq!(
        verify_result,
        Err(ScriptError::ValidationFailure(ERROR_PUBKEY_BLAKE160_HASH))
    );
}

#[test]
fn test_signing_wrong_tx_hash() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());
    let tx = gen_tx(&mut data_loader, SIGHASH_ALL_BIN.clone(), vec![pubkey_hash]);
    let tx = {
        let mut rand_tx_hash = [0u8; 32];
        let mut rng = thread_rng();
        rng.fill(&mut rand_tx_hash);
        sign_tx_hash(tx, &privkey, &rand_tx_hash[..])
    };
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let script_config = ScriptConfig::default();
    let verify_result = TransactionScriptsVerifier::new(&resolved_tx, &data_loader, &script_config)
        .verify(MAX_CYCLES);
    assert_eq!(
        verify_result,
        Err(ScriptError::ValidationFailure(ERROR_PUBKEY_BLAKE160_HASH))
    );
}

#[test]
fn test_super_long_witness() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");
    let pubkey_hash = blake160(&pubkey.serialize());
    let tx = gen_tx(&mut data_loader, SIGHASH_ALL_BIN.clone(), vec![pubkey_hash]);
    let tx_hash: H256 = tx.hash().unpack();

    let mut buffer: Vec<u8> = vec![];
    buffer.resize(40000, 1);
    let super_long_message = Bytes::from(&buffer[..]);

    let mut blake2b = ckb_hash::new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(&tx_hash[..]);
    blake2b.update(&super_long_message[..]);
    blake2b.finalize(&mut message);
    let message = H256::from(message);
    let sig = privkey.sign_recoverable(&message).expect("sign");
    let tx = tx
        .as_advanced_builder()
        .witness(
            vec![
                Bytes::from(sig.serialize()).pack(),
                super_long_message.pack(),
            ]
            .pack(),
        )
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let script_config = ScriptConfig::default();
    let verify_result = TransactionScriptsVerifier::new(&resolved_tx, &data_loader, &script_config)
        .verify(MAX_CYCLES);
    assert_eq!(
        verify_result,
        Err(ScriptError::ValidationFailure(ERROR_WITNESS_TOO_LONG))
    );
}

#[cfg(test)]
mod multisig_tests {
    const ERROR_WRONG_NUMBER_OF_ARGUMENTS: i8 = -2;

    // script args: [pkh_1, pkh_2, ..., pkh_n, m ]
    // - pkh_i: public key blake160 hash as bytes
    // - m: u8 as byte
    //
    // witness: [ sig_1, sig_2, ..., sig_m ]
    // - sig_1: recoverable signature
    use super::super::multi_sign_tx;
    use super::*;

    fn generate_keys(n: usize) -> Vec<Privkey> {
        let mut keys = Vec::with_capacity(n);
        for _ in 0..n {
            keys.push(Generator::random_privkey());
        }

        keys
    }

    fn pkh(key: &Privkey) -> Bytes {
        blake160(&key.pubkey().unwrap().serialize())
    }

    fn verify(data_loader: &DummyDataLoader, tx: &TransactionView) -> Result<u64, ScriptError> {
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let script_config = ScriptConfig::default();
        TransactionScriptsVerifier::new(&resolved_tx, data_loader, &script_config)
            .verify(MAX_CYCLES)
    }

    #[test]
    fn test_sighash_1_2_unlock() {
        let mut data_loader = DummyDataLoader::new();
        let keys = generate_keys(3);

        let raw_tx = gen_tx(
            &mut data_loader,
            SIGHASH_ALL_BIN.clone(),
            vec![pkh(&keys[0]), pkh(&keys[1]), vec![1].into()],
        );

        {
            let tx = sign_tx(raw_tx.clone(), &keys[0]);
            verify(&data_loader, &tx).expect("pass verification");
        }
        {
            let tx = sign_tx(raw_tx.clone(), &keys[1]);
            verify(&data_loader, &tx).expect("pass verification");
        }
        {
            let tx = sign_tx(raw_tx.clone(), &keys[2]);
            assert_eq!(
                verify(&data_loader, &tx),
                Err(ScriptError::ValidationFailure(ERROR_PUBKEY_BLAKE160_HASH))
            );
        }
    }

    #[test]
    fn test_sighash_2_3_unlock() {
        let mut data_loader = DummyDataLoader::new();
        let keys = generate_keys(4);

        let raw_tx = gen_tx(
            &mut data_loader,
            SIGHASH_ALL_BIN.clone(),
            vec![pkh(&keys[0]), pkh(&keys[1]), pkh(&keys[2]), vec![2].into()],
        );

        {
            let tx = multi_sign_tx(raw_tx.clone(), &[&keys[0], &keys[1]]);
            verify(&data_loader, &tx).expect("pass verification");
        }
        {
            let tx = multi_sign_tx(raw_tx.clone(), &[&keys[1], &keys[0]]);
            verify(&data_loader, &tx).expect("pass verification");
        }
        {
            let tx = multi_sign_tx(raw_tx.clone(), &[&keys[0], &keys[2]]);
            verify(&data_loader, &tx).expect("pass verification");
        }
        {
            let tx = multi_sign_tx(raw_tx.clone(), &[&keys[1], &keys[2]]);
            verify(&data_loader, &tx).expect("pass verification");
        }

        {
            // add extra arg
            let raw_tx = raw_tx
                .as_advanced_builder()
                .set_witnesses(vec![])
                .witness(vec![Bytes::from("x").pack()].pack())
                .build();
            let tx = multi_sign_tx(raw_tx, &[&keys[0], &keys[1]]);
            assert_eq!(3, tx.witnesses().get(0).expect("get 0").len());
            verify(&data_loader, &tx).expect("pass verification");
        }

        {
            let tx = sign_tx(raw_tx.clone(), &keys[1]);
            assert_eq!(
                verify(&data_loader, &tx),
                Err(ScriptError::ValidationFailure(
                    ERROR_WRONG_NUMBER_OF_ARGUMENTS
                ))
            );
        }

        {
            let tx = multi_sign_tx(raw_tx.clone(), &[&keys[0], &keys[0]]);
            assert_eq!(
                verify(&data_loader, &tx),
                Err(ScriptError::ValidationFailure(ERROR_PUBKEY_BLAKE160_HASH))
            );
        }

        {
            let tx = multi_sign_tx(raw_tx.clone(), &[&keys[0], &keys[3]]);
            assert_eq!(
                verify(&data_loader, &tx),
                Err(ScriptError::ValidationFailure(ERROR_PUBKEY_BLAKE160_HASH))
            );
        }
    }
}
