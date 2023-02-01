# Merkle-Tree
Merkle tree implementation in Rust with Keccak256 from Tiny Keccak

# Usage 

Tree::new(...) will construct a new tree from a vector of Leaf 

Tree::spawn() for an empty tree

verify_proof(...) will be used to verify inclusion in the merkle tree with the leaf, root, index, and vector of proof hashes

Tree::generate proof(...) will generate a proof for an element in the tree given the leaf, index, and tree

