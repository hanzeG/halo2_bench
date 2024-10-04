use ark_std::{end_timer, start_timer};
use mimc_halo2::mimc::{
    mimc_hash::{MiMC5HashChip, MiMC5HashConfig, MiMC5HashPallasChip},
    primitives::mimc5_hash_pallas,
};
use pasta_curves::{pallas, vesta};
use rand::rngs::OsRng;

use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, SingleVerifier,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};

#[derive(Debug, Clone)]
struct MiMC5HashCircuitConfig {
    input: Column<Advice>,
    mimc_config: MiMC5HashConfig,
}

#[derive(Default, Clone, Copy)]
struct MiMC5HashPallasCircuit {
    pub message: Fp,
    pub message_hash: Fp,
}

impl Circuit<Fp> for MiMC5HashPallasCircuit {
    type Config = MiMC5HashCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let circuit_input = meta.advice_column();
        meta.enable_equality(circuit_input);
        let state = meta.advice_column();
        let round_constants = meta.fixed_column();

        Self::Config {
            input: circuit_input,
            mimc_config: MiMC5HashPallasChip::configure(meta, state, round_constants),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = MiMC5HashPallasChip::construct(config.mimc_config);

        let message = layouter.assign_region(
            || "load message",
            |mut region| {
                region.assign_advice(
                    || "load input message",
                    config.input,
                    0,
                    || Value::known(self.message),
                )
            },
        )?;

        let msg_hash = chip.hash_message(layouter.namespace(|| "hash message"), &message)?;

        layouter.assign_region(
            || "constrain output",
            |mut region| {
                let expected_output = region.assign_advice(
                    || "load expected output",
                    config.input,
                    0,
                    || Value::known(self.message_hash),
                )?;
                region.constrain_equal(msg_hash.cell(), expected_output.cell())
            },
        )?;

        Ok(())
    }
}

fn main() {
    let log2_num_rows = 7;
    // Initialize the polynomial commitment parameters
    let timer_get_param = start_timer!(|| "get param");
    let params: Params<vesta::Affine> = Params::new(log2_num_rows);
    end_timer!(timer_get_param);

    let empty_circuit = MiMC5HashPallasCircuit::default();

    // Initialize the proving key
    let timer_get_pk_vk = start_timer!(|| "get pk vk");
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
    end_timer!(timer_get_pk_vk);

    let mut rng = OsRng;
    let pallas_message = pallas::Base::random(&mut rng);
    let mut state = pallas_message;
    mimc5_hash_pallas(&mut state);
    let pallas_message_hash = state;

    let circuit = MiMC5HashPallasCircuit {
        message: pallas_message,
        message_hash: pallas_message_hash,
    };

    // Create a proof
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    let timer_create_proof = start_timer!(|| "create proof");
    create_proof(
        &params,
        &pk,
        &[circuit.clone()],
        &[&[]],
        &mut rng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    end_timer!(timer_create_proof);

    let proof = transcript.finalize();

    // Verify the proof
    let timer_verify = start_timer!(|| "verify");
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    assert!(
        verify_proof(&params, pk.get_vk(), strategy, &[&[]], &mut transcript).is_ok(),
        "proof verification failed"
    );
    end_timer!(timer_verify);

    println!("Proof verification successful for MiMC hash on Pallas curve!");
}
