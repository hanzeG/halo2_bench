use ark_std::{end_timer, start_timer};

use halo2_proofs::{
    circuit::{floor_planner::FlatFloorPlanner, Chip, Layouter, Region},
    dev::MockProver,
    pairing::bn256::Fq as Felt,
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error,
    },
};

use std::convert::TryInto;

use zkwasm_host_circuits::{
    circuits::{
        anemoi::{AnemoiChip, NUM_HASH_ROUNDS, RATE},
        CommonGateConfig,
    },
    utils::Limb,
    value_for_assign,
};

// CONSTANTS
// ================================================================================================

const C: [Felt; NUM_HASH_ROUNDS] = [
    Felt::from_raw([
        0x0000000000000023,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000, // converted
    ]), // should be 35
    Felt::from_raw([
        0x775b1f206923c47d,
        0xa8f87a7963284fbb,
        0x3bae816d61d6132a,
        0xdeaee26fa771e0b, // converted
    ]),
    Felt::from_raw([
        0x22a976e6d07d60f5,
        0xc34df41e5fe46ab6,
        0x260d3da3fedf84b,
        0x2f4c8ca1724196cf, // converted
    ]),
    Felt::from_raw([
        0xc30db64d510ee564,
        0x95744059950b323d,
        0x650e5c6bd5cfcb3e,
        0x5d30d8a084ddd31, // converted
    ]),
    Felt::from_raw([
        0xcd05768f1b651e71,
        0xad09e76646f8fc45,
        0xdad4ecd80712fe07,
        0x21d0c94592289e73, // converted
    ]),
    Felt::from_raw([
        0xeee4a5b31c720775,
        0xe685edbf1f0f875e,
        0xecda8089d8eb9a3d,
        0xad405df9e60b24e, // converted 5
    ]),
    Felt::from_raw([
        0x37019677c912b86e,
        0xf1b16555957afe6c,
        0x3631c2568a36f711,
        0xcc03a758b72c918, // converted
    ]),
    Felt::from_raw([
        0x433a8db6250f1315,
        0x16c912d5d9d4ed48,
        0x7d7c67b60ccdf98d,
        0xbc1b9119e2f8d32, // converted
    ]),
    Felt::from_raw([
        0x46cb1f57666d0206,
        0x8a58a8f27efdb933,
        0x83e8dd8a41625cd6,
        0xfdefd9a0f81cc28, // converted
    ]),
    Felt::from_raw([
        0x8add6292e2e1e661,
        0xf1f53531867319e8,
        0x3d6fcf9e000ccbcd,
        0x545268f14d1ef2d, // converted
    ]),
    Felt::from_raw([
        0xa2def1f14b524aae,
        0x275d597192211146,
        0xa42c1f3e6a1f7e3b,
        0x304083d89066c255, // converted 10
    ]),
    Felt::from_raw([
        0x250db07064b2c906,
        0x1b6b4eeb73bd34db,
        0x33427c42db863ba9,
        0x2f6c68f4f14399a4, // converted
    ]),
    Felt::from_raw([
        0xc316649d3fc3381d,
        0xc0454a7c949fa493,
        0xafc8f158a8e78784,
        0x2c253abeaa8f1309, // converted
    ]),
    Felt::from_raw([
        0x28ee11171ca3660e,
        0xeb197941a15815a9,
        0xd6329fa5a982a43,
        0x28a62c2fcdf31601, // converted
    ]),
    Felt::from_raw([
        0x4e0f7d84e1129058,
        0x940999a2a073a089,
        0xcceab807358a652f,
        0xb8c0b1fdb7e110a, // converted
    ]),
    Felt::from_raw([
        0x70cf039d739d1046,
        0xf569e914e8d94eee,
        0xfb255b7fde25b695,
        0x1468c3253afd5301, // converted 15
    ]),
    Felt::from_raw([
        0x3d2a365c3b57cd1b,
        0x4312821f06af1a11,
        0xd30bc6c4014eb88e,
        0x76505a8aac3ed67, // converted
    ]),
    Felt::from_raw([
        0x671b73192354638f,
        0x7001d04e2195dd2,
        0xfaeb9a1e631fc8f5,
        0x1989a97904a6cc74, // converted
    ]),
    Felt::from_raw([
        0xf1e8b99b2fe59e14,
        0x6c3bcc9fa9f0c3ee,
        0x7fb680e63a8b45a4,
        0xcc2035b47d9bb9e, // converted
    ]),
    Felt::from_raw([
        0xe55901d82eafa11d,
        0x38694ed7495dc378,
        0x85acb7120a4ca071,
        0x218d252816b694c5, // converted
    ]),
    Felt::from_raw([
        0x7b2bfc5a6086dccd,
        0x2a44cbfa06667305,
        0xa335ab84fa3fd829,
        0xf083607ff8712f6, // converted 20
    ]),
];

/// Additive round constants D for Anemoi.
const D: [Felt; NUM_HASH_ROUNDS] = [
    Felt::from_raw([
        0xd2c05d64905353a8,
        0xba56470b9af68708,
        0xd03583cf0100e593,
        0x2042def740cbc01b,
    ]),
    Felt::from_raw([
        0x73a2fbd4019568b4,
        0x5cb6796c004a370d,
        0xbdd497eaca1967df,
        0x20e95d0e6735f19a,
    ]),
    Felt::from_raw([
        0xee681bf532a91923,
        0x8385c5e9d09c9ee3,
        0x4072d35cf31e5204,
        0x2b6b3836e5247620,
    ]),
    Felt::from_raw([
        0xf48fc0aaaaad418a,
        0xf9a5f194fb14170a,
        0x5fe8df694a1bfe5c,
        0x3f3ec435fea59d9,
    ]),
    Felt::from_raw([
        0xe014fffb8fc1f126,
        0x350043a3cf4f64c8,
        0x2afd01afa94add8c,
        0xe760bbfd4bc5260,
    ]),
    Felt::from_raw([
        0x15162795759ef68,
        0x1727676991bd7352,
        0x5f43de4dc2cd5c9c,
        0x148baca8bb5a730c, // 5
    ]),
    Felt::from_raw([
        0x7aad2edb101c1926,
        0xd96956877d2d5b4b,
        0x17a23a1d8b446506,
        0x2dac0dc7fef687d7,
    ]),
    Felt::from_raw([
        0x2fef6d8c3c4c4457,
        0x8464595c1a04bf97,
        0xeaff4b1dc220b4c3,
        0x239dc36bdce081cf,
    ]),
    Felt::from_raw([
        0x8999c35c997fb84e,
        0x64dadc90d848b6c9,
        0xe87539e33456eeeb,
        0x293f0565a6c6611c,
    ]),
    Felt::from_raw([
        0xe7e351515eaddd87,
        0xa9eaebd37ecda9ba,
        0x278f2326549a3427,
        0x1ba459601d9c6c78,
    ]),
    Felt::from_raw([
        0x55f14c562a9a9308,
        0xd5c8c8fd76fab00b,
        0x6feeb1125758e33b,
        0x23f26cea6945ec15, // 10
    ]),
    Felt::from_raw([
        0xe1342a430bee2f41,
        0xb3f8b199ef4d013d,
        0x6a9548ebb41718dc,
        0xbac5daffbafcd13,
    ]),
    Felt::from_raw([
        0x2aeef4a67c235b35,
        0xd9977df9611952df,
        0xb95fbb84b009d6be,
        0x184e80dc14df31ee,
    ]),
    Felt::from_raw([
        0x968b0e12479b11c9,
        0x4f7050525593443a,
        0x4881803e03833ab5,
        0x2a9075fbd6deb7d8,
    ]),
    Felt::from_raw([
        0xdfcd056b4a53c1d7,
        0xef8833b711fc7e09,
        0x495ec0abfeea5d19,
        0x170c18b10ac6cccf,
    ]),
    Felt::from_raw([
        0x23398e1996ad0ff8,
        0xf5b7bae9cc1d59bb,
        0x6612bce50cb34e4d,
        0x395e21f8759fb40, // 15
    ]),
    Felt::from_raw([
        0xd623a49CAB9C1525,
        0xF9CDE1D0F3A45A16,
        0x6074C20FA3EB065E,
        0x00AC9DA9488ECDFB,
    ]),
    Felt::from_raw([
        0xfe19c069491f78ba,
        0x5aa95dc039eb7f8a,
        0x190f717dfd1a2a1c,
        0x24fae1a08a518137,
    ]),
    Felt::from_raw([
        0x5c3ac9fb10b98b6c,
        0x78709792f130f84b,
        0xaba2e0fff5246b1c,
        0x3428dc08c3b8b36,
    ]),
    Felt::from_raw([
        0x96e4cea20b00019d,
        0x7f47df444750efae,
        0x4accf8d91870397b,
        0x2d2a504d0f8d8c1e,
    ]),
    Felt::from_raw([
        0xe68abccf2b3601a8,
        0x8dc73527bccb9ec2,
        0xd126f57ec2b39998,
        0x2ef503c0bb8962e7,
    ]),
];

/// Exponent of the Anemoi S-Box
#[allow(unused)]
const ALPHA: u32 = 5;

#[allow(unused)]
/// Inverse exponent
const INV_ALPHA: [u64; 4] = [
    0x180d04d5f031fee9,
    0xd633c43a29c71dd2,
    0x49b9b57c33cd568b,
    0x135b52945a13d9aa,
];

#[allow(unused)]
/// Multiplier of the Anemoi S-Box
const BETA: u32 = 3;

/// First added constant of the Anemoi S-Box
const DELTA: Felt = Felt::from_raw([
    0xd2c05d6490535385,
    0xba56470b9af68708,
    0xd03583cf0100e593,
    0x2042def740cbc01b,
]);

// HelperChip and its implementations
#[derive(Clone, Debug)]
pub struct HelperChipConfig {
    limb: Column<Advice>,
}

#[derive(Clone, Debug)]
pub struct HelperChip {
    config: HelperChipConfig,
}

impl Chip<Felt> for HelperChip {
    type Config = HelperChipConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl HelperChip {
    fn new(config: HelperChipConfig) -> Self {
        HelperChip { config }
    }

    fn configure(cs: &mut ConstraintSystem<Felt>) -> HelperChipConfig {
        let limb = cs.advice_column();
        cs.enable_equality(limb);
        HelperChipConfig { limb }
    }

    fn assign_inputs(
        &self,
        region: &Region<Felt>,
        offset: &mut usize,
        inputs: &[Felt; RATE],
    ) -> Result<[Limb<Felt>; RATE], Error> {
        let r = inputs.map(|x| {
            let c = region
                .assign_advice(
                    || format!("assign input"),
                    self.config.limb,
                    *offset,
                    || value_for_assign!(x.clone()),
                )
                .unwrap();
            *offset += 1;
            Limb::new(Some(c), x.clone())
        });
        Ok(r)
    }

    fn assign_result(
        &self,
        region: &Region<Felt>,
        offset: &mut usize,
        result: &Felt,
    ) -> Result<Limb<Felt>, Error> {
        let c = region.assign_advice(
            || format!("assign result"),
            self.config.limb,
            *offset,
            || value_for_assign!(result.clone()),
        )?;
        *offset += 1;
        Ok(Limb::new(Some(c), result.clone()))
    }
}

// TestCircuit and its implementations
#[derive(Clone, Debug, Default)]
struct TestCircuit {
    inputs: Vec<Felt>,
    result: Felt,
}

#[derive(Clone, Debug)]
struct TestConfig {
    anemoiconfig: CommonGateConfig,
    helperconfig: HelperChipConfig,
}

impl Circuit<Felt> for TestCircuit {
    type Config = TestConfig;
    type FloorPlanner = FlatFloorPlanner;

    fn without_witnesses(&self) -> Self {
        let inputs = vec![Felt::zero(), Felt::zero()];
        let result = Felt::from_raw([
            0x94672c47f345700a,
            0xe5168077fd5eeb90,
            0xae14f132fcc041ec,
            0x2ac427786f4818bf,
        ]);
        Self { inputs, result }
    }

    fn configure(cs: &mut ConstraintSystem<Felt>) -> Self::Config {
        let witness = vec![
            cs.advice_column(),
            cs.advice_column(),
            cs.advice_column(),
            cs.advice_column(),
            cs.advice_column(),
        ];
        Self::Config {
            anemoiconfig: AnemoiChip::<Felt>::configure(cs, &witness),
            helperconfig: HelperChip::configure(cs),
        }
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Felt>) -> Result<(), Error> {
        layouter.assign_region(
            || "assign anemoi test",
            |region| {
                let helperchip = HelperChip::new(config.clone().helperconfig);
                let mut anemoichip =
                    AnemoiChip::<Felt>::construct(config.clone().anemoiconfig, C, D, DELTA);
                let mut offset = 0;
                let result = helperchip.assign_result(&region, &mut offset, &self.result)?;
                let input = helperchip.assign_inputs(
                    &region,
                    &mut offset,
                    &self.inputs.clone().try_into().unwrap(),
                )?;
                offset = 0;
                anemoichip.initialize(&config.anemoiconfig, &region, &mut offset)?; // init to all zeros
                anemoichip.hash(&region, &mut offset, &input, &result)?;
                Ok(())
            },
        )?;
        Ok(())
    }
}

fn main() {
    const K: u32 = 16;

    let input_data = [vec![Felt::one(), Felt::one()]];

    let expected = [Felt::from_raw([
        0x9f72277137a37266,
        0x17bdddc79f44f08b,
        0x76008edf3b0d7d10,
        0x11f013adb9e0ff65,
    ])];

    for i in 0..input_data.len() {
        // 构造电路实例
        let test_circuit = TestCircuit {
            inputs: input_data[i].clone(),
            result: expected[i],
        };

        println!("Message: {:?}", input_data);
        println!("Expected Poseidon Hash Output: {:?}", expected);

        // TODO: Replace `MockProver` with actual benchmarking if needed
        let prover = MockProver::run(16, &test_circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
