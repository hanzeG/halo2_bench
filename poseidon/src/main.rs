use ark_std::{end_timer, start_timer};

use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Instance,
    },
    poly::{
        commitment::ParamsProver,
        ipa::{
            commitment::{IPACommitmentScheme, ParamsIPA},
            multiopen::ProverIPA,
            strategy::SingleStrategy,
        },
        VerificationStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use halo2curves::pasta::{pallas, vesta, EqAffine, Fp};

use halo2_poseidon::poseidon::{
    primitives::{self as poseidon, generate_constants, ConstantLength, Mds, Spec},
    Hash, Pow5Chip, Pow5Config,
};
use std::convert::TryInto;
use std::marker::PhantomData;

use rand::rngs::OsRng;

#[derive(Clone, Copy)]
struct HashCircuit<S, const WIDTH: usize, const RATE: usize, const L: usize>
where
    S: Spec<Fp, WIDTH, RATE> + Clone + Copy,
{
    message: Value<[Fp; L]>,
    _spec: PhantomData<S>,
}

#[derive(Debug, Clone)]
struct MyConfig<const WIDTH: usize, const RATE: usize, const L: usize> {
    input: [Column<Advice>; L],
    expected: Column<Instance>,
    poseidon_config: Pow5Config<Fp, WIDTH, RATE>,
}

impl<S, const WIDTH: usize, const RATE: usize, const L: usize> Circuit<Fp>
    for HashCircuit<S, WIDTH, RATE, L>
where
    S: Spec<Fp, WIDTH, RATE> + Copy + Clone,
{
    type Config = MyConfig<WIDTH, RATE, L>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            message: Value::unknown(),
            _spec: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let expected = meta.instance_column();
        meta.enable_equality(expected);
        let partial_sbox = meta.advice_column();

        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

        meta.enable_constant(rc_b[0]);

        Self::Config {
            input: state[..RATE].try_into().unwrap(),
            expected,
            poseidon_config: Pow5Chip::configure::<S>(
                meta,
                state.try_into().unwrap(),
                partial_sbox,
                rc_a.try_into().unwrap(),
                rc_b.try_into().unwrap(),
            ),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = Pow5Chip::construct(config.poseidon_config.clone());

        let message = layouter.assign_region(
            || "load message",
            |mut region| {
                let message_word = |i: usize| {
                    let value = self.message.map(|message_vals| message_vals[i]);
                    region.assign_advice(
                        || format!("load message_{}", i),
                        config.input[i],
                        0,
                        || value,
                    )
                };

                let message: Result<Vec<_>, Error> = (0..L).map(message_word).collect();
                Ok(message?.try_into().unwrap())
            },
        )?;

        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;
        let output = hasher.hash(layouter.namespace(|| "hash"), message)?;

        layouter.constrain_instance(output.cell(), config.expected, 0)
    }
}

#[derive(Debug, Clone, Copy)]
struct MySpec<const WIDTH: usize, const RATE: usize>;

impl<const WIDTH: usize, const RATE: usize> Spec<Fp, WIDTH, RATE> for MySpec<WIDTH, RATE> {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fp) -> Fp {
        val.pow_vartime([5])
    }

    fn secure_mds() -> usize {
        0
    }

    fn constants() -> (Vec<[Fp; WIDTH]>, Mds<Fp, WIDTH>, Mds<Fp, WIDTH>) {
        generate_constants::<_, Self, WIDTH, RATE>()
    }
}

const K: u32 = 7;

fn main() {
    // 选择参数
    const WIDTH: usize = 3;
    const RATE: usize = 2;
    const L: usize = 2;

    // 初始化多项式承诺参数
    let timer_get_param = start_timer!(|| "get param");
    let params: ParamsIPA<vesta::Affine> = ParamsIPA::new(K);
    end_timer!(timer_get_param);

    // 创建空电路用于生成密钥
    let empty_circuit = HashCircuit::<MySpec<WIDTH, RATE>, WIDTH, RATE, L> {
        message: Value::unknown(),
        _spec: PhantomData,
    };

    // 生成验证密钥和证明密钥
    let timer_get_pk_vk = start_timer!(|| "get pk vk");
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
    end_timer!(timer_get_pk_vk);

    // 生成随机消息并计算其哈希值
    let mut rng = OsRng;
    let message: [Fp; L] = (0..L)
        .map(|_| pallas::Base::random(&mut rng))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let output = poseidon::Hash::<_, MySpec<WIDTH, RATE>, ConstantLength<L>, WIDTH, RATE>::init()
        .hash(message);

    println!("Message: {:?}", message);
    println!("Expected Poseidon Hash Output: {:?}", output);

    // 构造电路实例
    let circuit = HashCircuit::<MySpec<WIDTH, RATE>, WIDTH, RATE, L> {
        message: Value::known(message),
        _spec: PhantomData,
    };

    // 创建证明
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    let timer_create_proof = start_timer!(|| "create proof");
    create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&[output]]],
        &mut rng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    end_timer!(timer_create_proof);
    let proof = transcript.finalize();

    println!("Proof generated successfully.");

    // 验证证明
    let timer_verify = start_timer!(|| "verify");
    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    assert!(verify_proof(
        &params,
        pk.get_vk(),
        strategy,
        &[&[&[output]]],
        &mut transcript
    )
    .is_ok());
    end_timer!(timer_verify);

    println!("Proof verified successfully.");
}
