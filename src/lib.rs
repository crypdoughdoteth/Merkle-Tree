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
        let elements = elements
            .iter()
            .map(|e| Self::hash(e.as_ref()))
            .collect::<Vec<[u8; 32]>>();

        Self { elements }
    }

    pub fn new_from_bytes(mut elements: Vec<&[u8]>) -> MerkleTree {
        MerkleTree::pad_elements(&mut elements);
        let elements = elements
            .par_iter()
            .map(|e| Self::hash(e))
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
        let mut output2 = [0u8; 32];
        let mut hasher2 = Keccak::v256();
        hasher2.update(&output);
        hasher2.finalize(&mut output2);
        output2
    }

    pub fn merkle_root(&self) -> MerkleRoot {
        let mut elements = self.elements.clone();
        loop {
            if elements.len() == 1 {
                break;
            }

            let new_set = elements
                .into_par_iter()
                .chunks(2)
                .map(|e| MerkleTree::concat_hashes(&e[0], &e[1]))
                .collect::<Vec<HashValue>>();
            elements = new_set;
        }

        MerkleRoot(elements[0])
    }

    pub fn generate_proof(&self, index: usize) -> (MerkleRoot, MerkleProof) {
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
                        acc.1.push(Self::concat_hashes(&e[0], &e[1]));
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

pub type HashValue = [u8; 32];

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MerkleRoot([u8; 32]);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MerkleProof(Vec<NodeLocation>);

impl MerkleProof {
    pub fn validate_proof<T: AsRef<[u8]> + ?Sized>(&self, root: &MerkleRoot, element: &T) -> bool {
        self.0
            .iter()
            .fold(MerkleTree::hash(element.as_ref()), |mut acc, e| {
                acc = match e {
                    NodeLocation::Left(hash) => MerkleTree::concat_hashes(hash, &acc),
                    NodeLocation::Right(hash) => MerkleTree::concat_hashes(&acc, hash),
                };
                acc
            })
            .eq(&root.0)
    }
}

impl MerkleProof {
    pub fn new() -> Self {
        MerkleProof(vec![])
    }

    pub fn push(&mut self, value: NodeLocation) {
        self.0.push(value)
    }

    pub fn extend_from_slice(&mut self, proof_elements: &[NodeLocation]) {
        self.0.extend_from_slice(&proof_elements)
    }
}

#[cfg(test)]
pub mod test {

    use super::*;

    #[test]
    fn test_run() {
        let values = vec!["a", "b", "c", "d", "e"];
        let new_values: Vec<&[u8]> = values.par_iter().map(|e| e.as_bytes()).collect();
        let tree = MerkleTree::new_from_bytes(new_values);

        tree.merkle_root();

        let (root, proof) = tree.generate_proof(2);

        assert!(proof.validate_proof(&root, "c"));
        assert!(!proof.validate_proof(&root, "a"));
    }

    #[test]
    fn unpadded() {
        let values = vec!["a", "b", "c", "d"];
        let tree = MerkleTree::new(values);

        let first = MerkleTree::concat_hashes(&tree.elements[0], &tree.elements[1]);
        let second = MerkleTree::concat_hashes(&tree.elements[2], &tree.elements[3]);
        let root = MerkleTree::concat_hashes(&first, &second);

        assert_eq!(MerkleRoot(root), tree.merkle_root());
        let (root, proof) = tree.generate_proof(1);
        assert!(proof.validate_proof(&root, "b"));
    }

    #[test]
    fn padded() {
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
        let (root, proof) = tree.generate_proof(3);
        assert!(proof.validate_proof(&root, "d"));
    }

    #[test]
    fn sixteen() {
        let values = vec!["a", "b", "c", "d", "e", "f", "g", "h", "i"];
        let new_values: Vec<&[u8]> = values.par_iter().map(|e| e.as_bytes()).collect();
        let tree = MerkleTree::new(new_values);
        let first = MerkleTree::concat_hashes(&tree.elements[0], &tree.elements[1]);
        let second = MerkleTree::concat_hashes(&tree.elements[2], &tree.elements[3]);
        let third = MerkleTree::concat_hashes(&tree.elements[4], &tree.elements[5]);
        let fourth = MerkleTree::concat_hashes(&tree.elements[6], &tree.elements[7]);
        let fifth = MerkleTree::concat_hashes(&tree.elements[8], &tree.elements[9]);
        let sixth = MerkleTree::concat_hashes(&tree.elements[10], &tree.elements[11]);
        let seventh = MerkleTree::concat_hashes(&tree.elements[12], &tree.elements[13]);
        let eighth = MerkleTree::concat_hashes(&tree.elements[14], &tree.elements[15]);
        // second row
        let nineth = MerkleTree::concat_hashes(&first, &second);
        let tenth = MerkleTree::concat_hashes(&third, &fourth);
        let eleventh = MerkleTree::concat_hashes(&fifth, &sixth);
        let twelfth = MerkleTree::concat_hashes(&seventh, &eighth);
        // third
        let thirteenth = MerkleTree::concat_hashes(&nineth, &tenth);
        let fourteenth = MerkleTree::concat_hashes(&eleventh, &twelfth);
        let root = MerkleTree::concat_hashes(&thirteenth, &fourteenth);
        assert_eq!(MerkleRoot(root), tree.merkle_root());
        let (root, proof) = tree.generate_proof(6);
        assert!(proof.validate_proof(&root, "g"));
    }
}
