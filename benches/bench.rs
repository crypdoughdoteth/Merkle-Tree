use merkle_tree::{Keccak256, MerkleTree};
use rayon::prelude::*;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn thirtytwo() {
    let values = vec![
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q",
    ];
    let new_values: Vec<&[u8]> = values.par_iter().map(|e| e.as_bytes()).collect();

    let tree = MerkleTree::<Keccak256, 32>::new_from_bytes(new_values, Keccak256);
    let (root, proof) = tree.generate_proof(11);
    proof.validate_proof(&root, "l", Keccak256);
}

fn mt32(c: &mut Criterion) {
    c.bench_function("MT 32", |b| b.iter(|| thirtytwo()));
}
criterion_group!(benches, mt32);
criterion_main!(benches);
