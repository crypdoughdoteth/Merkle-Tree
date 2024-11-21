use merkle_tree::{Keccak256, MerkleTree};
use criterion::{criterion_group, criterion_main, Criterion};

fn thirtytwo() {
    let values = vec![
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q",
    ];
    let tree = MerkleTree::<Keccak256>::new(&values);
    let (root, proof) = tree.generate_proof(11);
    proof.validate(&root, "l");
}

fn mt32(c: &mut Criterion) {
    c.bench_function("MT 32", |b| b.iter(|| thirtytwo()));
}
criterion_group!(benches, mt32);
criterion_main!(benches);
