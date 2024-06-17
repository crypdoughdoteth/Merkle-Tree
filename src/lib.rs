use rayon::prelude::*;
use tiny_keccak::{Hasher, Keccak};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MerkleTree<H: HashFunction + Send + Sync, const LENGTH: usize> {
    elements: Vec<[u8; LENGTH]>,
    hasher: H,
}

#[derive(Clone, Copy, Default)]
pub struct Keccak256;

impl HashFunction for Keccak256 {
    fn hash<const LENGTH: usize>(input: &[u8]) -> [u8; LENGTH] {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; LENGTH];
        hasher.update(input);
        hasher.finalize(&mut output);
        output
    }

    fn concat_hashes<const LENGTH: usize>(a: &[u8], b: &[u8]) -> [u8; LENGTH] {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; LENGTH];
        hasher.update(a);
        hasher.update(b);
        hasher.finalize(&mut output);
        output
    }
}

pub trait HashFunction {
    fn hash<const LENGTH: usize>(input: &[u8]) -> [u8; LENGTH];
    fn concat_hashes<const LENGTH: usize>(a: &[u8], b: &[u8]) -> [u8; LENGTH] {
        let first: [u8; LENGTH] = Self::hash(a);
        let second: [u8; LENGTH] = Self::hash(b);
        let mut out = Vec::new();
        out.extend_from_slice(&first);
        out.extend_from_slice(&second);
        Self::hash(&out)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum NodeLocation<const LENGTH: usize> {
    Left([u8; LENGTH]),
    Right([u8; LENGTH]),
}

impl<H: HashFunction + Send + Sync, const LENGTH: usize> MerkleTree<H, LENGTH> {
    pub fn new<T>(mut elements: Vec<T>, hasher: H) -> MerkleTree<H, { LENGTH }>
    where
        T: AsRef<[u8]> + Default + Clone,
    {
        MerkleTree::<H, LENGTH>::pad_elements::<T>(&mut elements);
        let elements = elements
            .iter()
            .map(|e| <H>::hash(&<H>::hash::<LENGTH>(e.as_ref())))
            .collect::<Vec<[u8; LENGTH]>>();

        Self { elements, hasher }
    }

    pub fn new_from_bytes(
        mut elements: Vec<&[u8]>,
        hashing_function: H,
    ) -> MerkleTree<H, { LENGTH }> {
        MerkleTree::<H, LENGTH>::pad_elements::<&[u8]>(&mut elements);
        let elements = elements
            .par_iter()
            .map(|e| <H>::hash(&<H>::hash::<LENGTH>(e.as_ref())))
            .collect::<Vec<[u8; LENGTH]>>();

        Self {
            elements,
            hasher: hashing_function,
        }
    }

    fn pad_elements<T: Default + Clone>(elements: &mut Vec<T>) {
        let len = elements.len();
        if len.is_power_of_two() {
            return;
        }
        let pad = len.next_power_of_two() - len;
        elements.extend_from_slice(vec![T::default(); pad].as_slice());
    }

    fn concat_hashes(&self, a: &[u8], b: &[u8]) -> [u8; LENGTH] {
        <H>::concat_hashes(a, b)
    }

    pub fn merkle_root(&self) -> MerkleRoot<LENGTH> {
        let mut elements = self.elements.clone();
        loop {
            if elements.len() == 1 {
                break;
            }

            let new_set = elements
                .into_par_iter()
                .chunks(2)
                .map(|e| self.concat_hashes(&e[0], &e[1]))
                .collect::<Vec<HashValue<LENGTH>>>();
            elements = new_set;
        }

        MerkleRoot(elements[0])
    }

    pub fn generate_proof(&self, index: usize) -> (MerkleRoot<LENGTH>, MerkleProof<LENGTH>) {
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

pub type HashValue<const LENGTH: usize> = [u8; LENGTH];

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MerkleRoot<const LENGTH: usize>([u8; LENGTH]);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MerkleProof<const LENGTH: usize>(Vec<NodeLocation<LENGTH>>);

impl<const LENGTH: usize> Default for MerkleProof<LENGTH> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const LENGTH: usize> MerkleProof<LENGTH> {
    pub fn validate_proof<T: AsRef<[u8]> + ?Sized, H: HashFunction>(
        &self,
        root: &MerkleRoot<LENGTH>,
        element: &T,
        _hash_function: H,
    ) -> bool {
        self.0
            .iter()
            .fold(
                <H>::hash::<LENGTH>(&<H>::hash::<LENGTH>(element.as_ref())),
                |mut acc, e| {
                    acc = match e {
                        NodeLocation::Left(hash) => <H>::concat_hashes(hash, &acc),
                        NodeLocation::Right(hash) => <H>::concat_hashes(&acc, hash),
                    };
                    acc
                },
            )
            .eq(&root.0)
    }

    pub fn new() -> Self {
        MerkleProof(vec![])
    }

    pub fn push(&mut self, value: NodeLocation<LENGTH>) {
        self.0.push(value)
    }

    pub fn extend_from_slice(&mut self, proof_elements: &[NodeLocation<LENGTH>]) {
        self.0.extend_from_slice(proof_elements)
    }
}

#[cfg(test)]
pub mod test {

    use super::*;

    #[test]
    fn test_run() {
        let values = vec!["a", "b", "c", "d", "e"];
        let new_values: Vec<&[u8]> = values.par_iter().map(|e| e.as_bytes()).collect();
        let tree = MerkleTree::<Keccak256, 32>::new_from_bytes(new_values, Keccak256);
        tree.merkle_root();
        let (root, proof) = tree.generate_proof(2);
        assert!(proof.validate_proof(&root, "c", Keccak256));
        assert!(!proof.validate_proof(&root, "a", Keccak256));
    }

    #[test]
    fn unpadded() {
        let values = vec!["a", "b", "c", "d"];
        let tree = MerkleTree::<Keccak256, 32>::new(values, Keccak256);

        let first = tree.concat_hashes(&tree.elements[0], &tree.elements[1]);
        let second = tree.concat_hashes(&tree.elements[2], &tree.elements[3]);
        let root = tree.concat_hashes(&first, &second);

        assert_eq!(MerkleRoot(root), tree.merkle_root());
        let (root, proof) = tree.generate_proof(1);
        assert!(proof.validate_proof(&root, "b", Keccak256));
    }

    #[test]
    fn padded() {
        let values = vec!["a", "b", "c", "d", "e"];
        let tree = MerkleTree::<Keccak256, 32>::new(values, Keccak256);
        let first = tree.concat_hashes(&tree.elements[0], &tree.elements[1]);
        let second = tree.concat_hashes(&tree.elements[2], &tree.elements[3]);
        let third = tree.concat_hashes(&tree.elements[4], &tree.elements[5]);
        let fourth = tree.concat_hashes(&tree.elements[6], &tree.elements[7]);
        let fifth = tree.concat_hashes(&first, &second);
        let sixth = tree.concat_hashes(&third, &fourth);
        let root = tree.concat_hashes(&fifth, &sixth);
        assert_eq!(MerkleRoot(root), tree.merkle_root());
        let (root, proof) = tree.generate_proof(3);
        assert!(proof.validate_proof(&root, "d", Keccak256));
    }

    #[test]
    fn sixteen() {
        let values = vec!["a", "b", "c", "d", "e", "f", "g", "h", "i"];
        let new_values: Vec<&[u8]> = values.par_iter().map(|e| e.as_bytes()).collect();
        let tree = MerkleTree::<Keccak256, 32>::new(new_values, Keccak256);
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
        assert!(proof.validate_proof(&root, "g", Keccak256));
    }
}
