use rayon::prelude::*;
use tiny_keccak::{Hasher, Keccak};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MerkleTree {
    elements: Vec<[u8; 32]>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum NodeLocation {
    Left([u8; 32]),
    Right([u8; 32]),
}

impl MerkleTree {
    pub fn new<T: AsRef<[u8]> + Default + Clone>(mut elements: Vec<T>) -> MerkleTree {
        MerkleTree::pad_elements(&mut elements);
        println!("{}", elements.len());
        let elements = elements
            .iter()
            .map(|e| Self::hash(e.as_ref()))
            .collect::<Vec<[u8; 32]>>();

        Self { elements }
    }

    fn pad_elements<T: Default + Clone>(elements: &mut Vec<T>) {
        let len = elements.len();
        if len.is_power_of_two() {
            return;
        }
        let pad = len.next_power_of_two() - len;
        elements.extend_from_slice(vec![T::default(); pad].as_slice());
    }

    fn concat_hashes(a: &[u8], b: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(a);
        hasher.update(b);
        hasher.finalize(&mut output);
        output
    }

    fn hash(a: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(a);
        hasher.finalize(&mut output);
        output
    }

    pub fn merkle_root(&self) -> MerkleRoot {
        MerkleRoot(
            (0..(self.elements.len() / 2) - 1).into_iter().fold(
                self.elements.clone(),
                |mut acc, _| {
                    let new_set = acc
                        .into_par_iter()
                        .chunks(2)
                        .map(|e| Self::concat_hashes(&e[0], &e[1]))
                        .collect::<Vec<HashValue>>();
                    acc = new_set;
                    acc
                },
            )[0],
        )
    }

    pub fn generate_proof(&self, index: usize) -> (MerkleRoot, MerkleProof) {
        let (root, proof, _) = (0..(self.elements.len() / 2) - 1).into_iter().fold(
            (self.elements.clone(), MerkleProof::new(), index),
            |(mut hashes, mut proof, mut idx), _| {
                let proof_element = hashes[idx];
                let new_set = hashes.chunks(2).enumerate().fold(
                    (Vec::new(), Vec::new(), 0),
                    |mut acc, (i, e)| {
                        if e.contains(&proof_element) {
                            if e[0] == proof_element {
                                acc.0.push(NodeLocation::Right(e[1]));
                            } else {
                                acc.0.push(NodeLocation::Left(e[0]));
                            }
                            acc.2 = i;
                        }
                        let hash = Self::concat_hashes(&e[0], &e[1]);
                        acc.1.push(hash);
                        acc
                    },
                );
                hashes = new_set.1;
                proof.0.extend_from_slice(&new_set.0);
                idx = new_set.2;
                (hashes, proof, idx)
            },
        );

        (MerkleRoot(root[0]), proof)
    }

    pub fn validate_proof<T: AsRef<[u8]> + ?Sized>(
        &self,
        root: &MerkleRoot,
        element: &T,
        proof: &MerkleProof,
    ) -> bool {
        proof
            .0
            .iter()
            .fold(Self::hash(element.as_ref()), |mut acc, e| {
                acc = match e {
                    NodeLocation::Left(hash) => Self::concat_hashes(hash, &acc),
                    NodeLocation::Right(hash) => Self::concat_hashes(&acc, hash),
                };
                acc
            })
            .eq(&root.0)
    }
}

pub type HashValue = [u8; 32];

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MerkleRoot([u8; 32]);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MerkleProof(Vec<NodeLocation>);

impl MerkleProof {
    pub fn new() -> Self {
        MerkleProof(vec![])
    }

    pub fn push(&mut self, value: NodeLocation) {
        self.0.push(value)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_run() {
        let values = vec!["a", "b", "c", "d", "e"];

        let tree = MerkleTree::new(values);

        tree.merkle_root();

        let (root, proof) = tree.generate_proof(2);

        assert!(tree.validate_proof(&root, "c", &proof));
        assert!(!tree.validate_proof(&root, "a", &proof));
    }

    #[test]
    fn step_by_step() {
        let values = vec!["a", "b", "c", "d", "e"];
        let tree = MerkleTree::new(values);
        let first = MerkleTree::concat_hashes(&tree.elements[0], &tree.elements[1]);
        let second = MerkleTree::concat_hashes(&tree.elements[2], &tree.elements[3]);
        let third = MerkleTree::concat_hashes(&tree.elements[4], &tree.elements[5]);
        let fourth = MerkleTree::concat_hashes(&tree.elements[6], &tree.elements[7]);
        let fifth = MerkleTree::concat_hashes(&first, &second);
        let sixth = MerkleTree::concat_hashes(&third, &fourth);
        let root = MerkleTree::concat_hashes(&fifth, &sixth);
        assert_eq!(MerkleRoot(root), tree.merkle_root());
    }
}
