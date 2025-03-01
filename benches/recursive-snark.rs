#![allow(non_snake_case)]

use bellperson::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError};
use core::marker::PhantomData;
use criterion::*;
use ff::PrimeField;
use nova_snark::{
  traits::{
    circuit::{StepCircuit, TrivialTestCircuit},
    Group,
  },
  PublicParams, RecursiveSNARK,
};
use std::time::Duration;

type G1 = pasta_curves::pallas::Point;
type G2 = pasta_curves::vesta::Point;
type C1 = NonTrivialTestCircuit<<G1 as Group>::Scalar>;
type C2 = TrivialTestCircuit<<G2 as Group>::Scalar>;

// To run these benchmarks, first download `criterion` with `cargo install cargo install cargo-criterion`.
// Then `cargo criterion --bench recursive-snark`. The results are located in `target/criterion/data/<name-of-benchmark>`.
// For flamegraphs, run `cargo criterion --bench recursive-snark --features flamegraph -- --profile-time <secs>`.
// The results are located in `target/criterion/profile/<name-of-benchmark>`.
cfg_if::cfg_if! {
  if #[cfg(feature = "flamegraph")] {
    criterion_group! {
      name = recursive_snark;
      config = Criterion::default().warm_up_time(Duration::from_millis(3000)).with_profiler(pprof::criterion::PProfProfiler::new(100, pprof::criterion::Output::Flamegraph(None)));
      targets = bench_recursive_snark
    }
  } else {
    criterion_group! {
      name = recursive_snark;
      config = Criterion::default().warm_up_time(Duration::from_millis(3000));
      targets = bench_recursive_snark
    }
  }
}

criterion_main!(recursive_snark);

fn bench_recursive_snark(c: &mut Criterion) {
  let num_cons_verifier_circuit_primary = 9819;
  // we vary the number of constraints in the step circuit
  for &num_cons_in_augmented_circuit in
    [9819, 16384, 32768, 65536, 131072, 262144, 524288, 1048576].iter()
  {
    // number of constraints in the step circuit
    let num_cons = num_cons_in_augmented_circuit - num_cons_verifier_circuit_primary;

    let mut group = c.benchmark_group(format!("RecursiveSNARK-StepCircuitSize-{num_cons}"));
    group.sample_size(10);

    let c_primary = NonTrivialTestCircuit::new(num_cons);
    let c_secondary = TrivialTestCircuit::default();

    // Produce public parameters
    let pp = PublicParams::<G1, G2, C1, C2>::setup(c_primary.clone(), c_secondary.clone());

    // Bench time to produce a recursive SNARK;
    // we execute a certain number of warm-up steps since executing
    // the first step is cheaper than other steps owing to the presence of
    // a lot of zeros in the satisfying assignment
    let num_warmup_steps = 10;
    let mut recursive_snark: RecursiveSNARK<G1, G2, C1, C2> = RecursiveSNARK::new(
      &pp,
      &c_primary,
      &c_secondary,
      vec![<G1 as Group>::Scalar::from(2u64)],
      vec![<G2 as Group>::Scalar::from(2u64)],
    );

    for i in 0..num_warmup_steps {
      let res = recursive_snark.prove_step(
        &pp,
        &c_primary,
        &c_secondary,
        vec![<G1 as Group>::Scalar::from(2u64)],
        vec![<G2 as Group>::Scalar::from(2u64)],
      );
      assert!(res.is_ok());

      // verify the recursive snark at each step of recursion
      let res = recursive_snark.verify(
        &pp,
        i + 1,
        &[<G1 as Group>::Scalar::from(2u64)],
        &[<G2 as Group>::Scalar::from(2u64)],
      );
      assert!(res.is_ok());
    }

    group.bench_function("Prove", |b| {
      b.iter(|| {
        // produce a recursive SNARK for a step of the recursion
        assert!(black_box(&mut recursive_snark.clone())
          .prove_step(
            black_box(&pp),
            black_box(&c_primary),
            black_box(&c_secondary),
            black_box(vec![<G1 as Group>::Scalar::from(2u64)]),
            black_box(vec![<G2 as Group>::Scalar::from(2u64)]),
          )
          .is_ok());
      })
    });

    // Benchmark the verification time
    group.bench_function("Verify", |b| {
      b.iter(|| {
        assert!(black_box(&recursive_snark)
          .verify(
            black_box(&pp),
            black_box(num_warmup_steps),
            black_box(&[<G1 as Group>::Scalar::from(2u64)]),
            black_box(&[<G2 as Group>::Scalar::from(2u64)]),
          )
          .is_ok());
      });
    });
    group.finish();
  }
}

#[derive(Clone, Debug, Default)]
struct NonTrivialTestCircuit<F: PrimeField> {
  num_cons: usize,
  _p: PhantomData<F>,
}

impl<F> NonTrivialTestCircuit<F>
where
  F: PrimeField,
{
  pub fn new(num_cons: usize) -> Self {
    Self {
      num_cons,
      _p: Default::default(),
    }
  }
}
impl<F> StepCircuit<F> for NonTrivialTestCircuit<F>
where
  F: PrimeField,
{
  fn arity(&self) -> usize {
    1
  }

  fn synthesize<CS: ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    // Consider a an equation: `x^2 = y`, where `x` and `y` are respectively the input and output.
    let mut x = z[0].clone();
    let mut y = x.clone();
    for i in 0..self.num_cons {
      y = x.square(cs.namespace(|| format!("x_sq_{i}")))?;
      x = y.clone();
    }
    Ok(vec![y])
  }

  fn output(&self, z: &[F]) -> Vec<F> {
    let mut x = z[0];
    let mut y = x;
    for _i in 0..self.num_cons {
      y = x * x;
      x = y;
    }
    vec![y]
  }
}
