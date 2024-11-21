# Merkle Tree

This is a generic implementation of Merkle Trees that allows the end user to use our default 
(Keccak256) hashing function or bring their own! All hashing ops are done by in parallel by 
the rayon thread pool.

# Single Element Proofs with Keccak256
```rust
use merkle_tree::{Keccak256, MerkleTree};

let values = vec![
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q",
];
let my_new_tree: MerkleTree<Keccak256> = MerkleTree::new();
let (root, proof) = tree.generate_proof(11);
proof.validate(&root, "l");

```

# Bring Your Own Hashing Function 

This example is from the codebase using the Keccak256 hashing function.

In order to BYO hashing function, you must create a unit struct and implement the `HashFunction`
trait on it. In the example below, we specify the hash function digest length in bytes with the
constant `DIGEST_OUTPUT_SIZE`. The only method that is required to be implemented is called `hash`.
The method takes a byte slice and returns a fixed size array of bytes. 

```rust
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct Keccak256;

impl HashFunction for Keccak256 {
    const DIGEST_OUTPUT_SIZE: usize = 32;
    fn hash(input: &[u8]) -> [u8; Self::DIGEST_OUTPUT_SIZE] {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; Self::DIGEST_OUTPUT_SIZE];
        hasher.update(input);
        hasher.finalize(&mut output);
        output
    }
}
```
