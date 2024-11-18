#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use rayon::prelude::*;
use tiny_keccak::{Hasher, Keccak};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MerkleTree<H: HashFunction + Send + Sync>
where
    H:,
    [(); H::DIGEST_OUTPUT_SIZE]:,
{
    elements: Vec<[u8; H::DIGEST_OUTPUT_SIZE]>,
}

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

pub trait HashFunction {
    const DIGEST_OUTPUT_SIZE: usize;
    fn hash(input: &[u8]) -> [u8; Self::DIGEST_OUTPUT_SIZE];
    fn concat_hashes(a: &[u8], b: &[u8]) -> [u8; Self::DIGEST_OUTPUT_SIZE]
    where
        [(); Self::DIGEST_OUTPUT_SIZE + Self::DIGEST_OUTPUT_SIZE]:,
    {
        let out: [u8; Self::DIGEST_OUTPUT_SIZE + Self::DIGEST_OUTPUT_SIZE] = {
            let mut whole: [u8; Self::DIGEST_OUTPUT_SIZE + Self::DIGEST_OUTPUT_SIZE] =
                [0; { Self::DIGEST_OUTPUT_SIZE + Self::DIGEST_OUTPUT_SIZE }];
            let (one, two) = whole.split_at_mut(a.len());
            one.copy_from_slice(a);
            two.copy_from_slice(b);
            whole
        };
        Self::hash(&out)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum NodeLocation<H: HashFunction + Copy + Clone>
where
    H: Clone + Copy,
    [(); H::DIGEST_OUTPUT_SIZE]:,
{
    Left([u8; H::DIGEST_OUTPUT_SIZE]),
    Right([u8; H::DIGEST_OUTPUT_SIZE]),
}

impl<H: HashFunction + Send + Sync + Copy> MerkleTree<H>
where
    H:,
    [u8; H::DIGEST_OUTPUT_SIZE]: Default,
{
    pub fn new(elements: &[impl AsRef<[u8]>]) -> MerkleTree<H> {
        let mut elements = elements
            .iter()
            .map(|e| <H>::hash(e.as_ref()))
            .map(|e| <H>::hash(&e))
            .collect::<Vec<[u8; <H>::DIGEST_OUTPUT_SIZE]>>();
        MerkleTree::pad_elements(&mut elements);
        Self { elements }
    }

    fn pad_elements<T: Copy + Clone + Default>(elements: &mut Vec<T>) {
        let len = elements.len();
        if len.is_power_of_two() {
            return;
        }
        let pad = len.next_power_of_two() - len;
        elements.extend_from_slice(vec![T::default(); pad].as_slice());
    }

    fn concat_hashes(&self, a: &[u8], b: &[u8]) -> [u8; <H>::DIGEST_OUTPUT_SIZE]
    where
        [(); <H>::DIGEST_OUTPUT_SIZE + <H>::DIGEST_OUTPUT_SIZE]:,
    {
        <H>::concat_hashes(a, b)
    }

    pub fn merkle_root(&self) -> MerkleRoot<H>
    where
        [(); <H>::DIGEST_OUTPUT_SIZE + <H>::DIGEST_OUTPUT_SIZE]:,
    {
        let mut elements = self.elements.clone();
        loop {
            if elements.len() == 1 {
                break;
            }

            let new_set = elements
                .into_par_iter()
                .chunks(2)
                .map(|e| self.concat_hashes(&e[0], &e[1]))
                .collect::<Vec<HashValue<H>>>();
            elements = new_set;
        }

        MerkleRoot(elements[0])
    }

    pub fn generate_proof(&self, index: usize) -> (MerkleRoot<H>, MerkleProof<H>)
    where
        [(); <H>::DIGEST_OUTPUT_SIZE + <H>::DIGEST_OUTPUT_SIZE]:,
    {
        let mut elements = self.elements.clone();
        let mut proof = MerkleProof::new();
        let mut idx: usize = index;
        loop {
            if elements.len() == 1 {
                break;
            }
            let proof_element = elements[idx];

            let (proof_elements, new_set, index) = elements
                .into_par_iter()
                .chunks(2)
                .enumerate()
                .fold(
                    || (Vec::new(), Vec::new(), 0usize),
                    |mut acc, (i, e)| {
                        if e.contains(&proof_element) {
                            if e[0] == proof_element {
                                acc.0.push(NodeLocation::Right(e[1]));
                            } else {
                                acc.0.push(NodeLocation::Left(e[0]));
                            }
                            acc.2 = i;
                        }
                        acc.1.push(self.concat_hashes(&e[0], &e[1]));
                        acc
                    },
                )
                .reduce(
                    || (Vec::new(), Vec::new(), 0),
                    |mut acc, x| {
                        acc.0.extend_from_slice(&x.0);
                        acc.1.extend_from_slice(&x.1);
                        acc.2 += x.2;
                        acc
                    },
                );

            elements = new_set;
            idx = index;
            proof.extend_from_slice(&proof_elements);
        }
        (MerkleRoot(elements[0]), proof)
    }
}

pub type HashValue<H: HashFunction> = [u8; <H>::DIGEST_OUTPUT_SIZE];

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MerkleRoot<H>([u8; <H>::DIGEST_OUTPUT_SIZE])
where
    H: HashFunction,
    [(); H::DIGEST_OUTPUT_SIZE]:;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MerkleProof<H: HashFunction + Copy + Clone>(Vec<NodeLocation<H>>)
where
    H: Clone + Copy,
    [(); H::DIGEST_OUTPUT_SIZE]:;

impl<H: HashFunction> Default for MerkleProof<H>
where
    H: Clone + Copy,
    [(); H::DIGEST_OUTPUT_SIZE]:,
{
    fn default() -> Self {
        MerkleProof(Vec::with_capacity(128))
    }
}

impl<H: HashFunction + Clone + Copy> MerkleProof<H>
where
    H: Clone + Copy,
    [(); H::DIGEST_OUTPUT_SIZE + H::DIGEST_OUTPUT_SIZE]:,
{
    pub fn validate_proof<T: AsRef<[u8]> + ?Sized>(
        &self,
        root: &MerkleRoot<H>,
        element: &T,
    ) -> bool {
        self.0
            .iter()
            .fold(<H>::hash(&<H>::hash(element.as_ref())), |mut acc, e| {
                acc = match e {
                    NodeLocation::Left(hash) => <H>::concat_hashes(hash, &acc),
                    NodeLocation::Right(hash) => <H>::concat_hashes(&acc, hash),
                };
                acc
            })
            .eq(&root.0)
    }

    pub fn new() -> Self {
        MerkleProof(vec![])
    }

    pub fn push(&mut self, value: NodeLocation<H>) {
        self.0.push(value)
    }

    pub fn extend_from_slice(&mut self, proof_elements: &[NodeLocation<H>]) {
        self.0.extend_from_slice(proof_elements)
    }
}

#[cfg(test)]
pub mod test {

    use super::*;

    #[test]
    fn test_run() {
        let values = vec!["a", "b", "c", "d", "e"];
        let tree = MerkleTree::<Keccak256>::new(&values);
        tree.merkle_root();
        let (root, proof) = tree.generate_proof(2);
        assert!(proof.validate_proof(&root, "c"));
        assert!(!proof.validate_proof(&root, "a"));
    }

    #[test]
    fn unpadded() {
        let values = vec!["a", "b", "c", "d"];
        let tree = MerkleTree::<Keccak256>::new(&values);

        let first = tree.concat_hashes(&tree.elements[0], &tree.elements[1]);
        let second = tree.concat_hashes(&tree.elements[2], &tree.elements[3]);
        let root = tree.concat_hashes(&first, &second);

        assert_eq!(MerkleRoot(root), tree.merkle_root());
        let (root, proof) = tree.generate_proof(1);
        assert!(proof.validate_proof(&root, "b"));
    }

    #[test]
    fn padded() {
        let values = vec!["a", "b", "c", "d", "e"];
        let tree = MerkleTree::<Keccak256>::new(&values);
        let first = tree.concat_hashes(&tree.elements[0], &tree.elements[1]);
        let second = tree.concat_hashes(&tree.elements[2], &tree.elements[3]);
        let third = tree.concat_hashes(&tree.elements[4], &tree.elements[5]);
        let fourth = tree.concat_hashes(&tree.elements[6], &tree.elements[7]);
        let fifth = tree.concat_hashes(&first, &second);
        let sixth = tree.concat_hashes(&third, &fourth);
        let root = tree.concat_hashes(&fifth, &sixth);
        assert_eq!(MerkleRoot(root), tree.merkle_root());
        let (root, proof) = tree.generate_proof(3);
        assert!(proof.validate_proof(&root, "d"));
    }

    #[test]
    fn sixteen() {
        let values = vec!["a", "b", "c", "d", "e", "f", "g", "h", "i"];
        let tree = MerkleTree::<Keccak256>::new(&values);
        let first = tree.concat_hashes(&tree.elements[0], &tree.elements[1]);
        let second = tree.concat_hashes(&tree.elements[2], &tree.elements[3]);
        let third = tree.concat_hashes(&tree.elements[4], &tree.elements[5]);
        let fourth = tree.concat_hashes(&tree.elements[6], &tree.elements[7]);
        let fifth = tree.concat_hashes(&tree.elements[8], &tree.elements[9]);
        let sixth = tree.concat_hashes(&tree.elements[10], &tree.elements[11]);
        let seventh = tree.concat_hashes(&tree.elements[12], &tree.elements[13]);
        let eighth = tree.concat_hashes(&tree.elements[14], &tree.elements[15]);
        // second row
        let nineth = tree.concat_hashes(&first, &second);
        let tenth = tree.concat_hashes(&third, &fourth);
        let eleventh = tree.concat_hashes(&fifth, &sixth);
        let twelfth = tree.concat_hashes(&seventh, &eighth);
        // third
        let thirteenth = tree.concat_hashes(&nineth, &tenth);
        let fourteenth = tree.concat_hashes(&eleventh, &twelfth);
        let root = tree.concat_hashes(&thirteenth, &fourteenth);
        assert_eq!(MerkleRoot(root), tree.merkle_root());
        let (root, proof) = tree.generate_proof(6);
        assert!(proof.validate_proof(&root, "g"));
    }
}
