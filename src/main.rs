extern crate tiny_keccak;
use std::collections::HashMap;
use tiny_keccak::Keccak;
use crate::tiny_keccak::Hasher;

#[warn(dead_code)]

#[derive(Clone, Debug)]
struct Tree{
    root: Node,
    nodes: Vec<Node>,
    neighbors: HashMap<[u8;32], [u8;32]>,
    depth: u32,
}

 impl Tree{
     fn new(mut self, leafs: Vec<Leaf>) -> Tree{
        //returns new merkle tree constructed from leafs: Vec<Leaf>
        // ---------------------------------------
        //creates initial nodes for merkle tree
        //iterate through leafs
        //on each iteration, hash the data contained in the leaf with Keccak256
        //append new Node to children_nodes  
        let mut parent_nodes: Vec<Node> = Vec::new();
        let mut children_nodes: Vec<Node> = leafs.iter().map(|x|{
           let x_hashed = Leaf::hash_leaf(x.data.as_bytes());
           println!("child hash: {:?}", &x_hashed);
            let y = Node::new(Box::new(None), Box::new(None), x_hashed);
            self.nodes.push(y.clone());
            y
        }).collect();

        //check length of leaf nodes, if there is an odd number of leaf nodes, copy the odd element and push it to the array
        let len = &children_nodes.len();
        if len % 2 == 1 { 
            children_nodes.push(children_nodes[len -1].clone()); 
            children_nodes[len-1].copied = true;
            println!("inserted child hash: {:?}", &children_nodes[len-1].hash);
        }

        let mut n = children_nodes.len();
        self.depth = 1; 
        //main loop, make sure there is at least two elemnts left, otherwise we've hit the root
        while n > 1{
            let mut o: usize = 0;
            let mut i = 0;
            //iterates over children_nodes to create new parent nodes
            while i < n - 1 {
                //link neighbors using hashmap, allows us to reconstruct the tree later with K:V pairs
                let node_one = children_nodes[i].hash.clone();
                let node_two = children_nodes[i+ 1].hash.clone();
                self.neighbors.insert(node_one, node_two);
                self.neighbors.insert(node_two, node_one);
                //create input for Node::hash_nodes()
                let array = [&node_one, &node_two];
                //hash nodes together
                let new_node_hash = Node::hash_nodes(array);

                println!("node hash: {:?}", &new_node_hash);
                let new_node =                    
                    Node{ 
                        left_child: Box::new(Some(children_nodes[i].clone())),
                        right_child: Box::new(Some(children_nodes[i + 1].clone())),
                        hash: new_node_hash,
                        copied: false, 
                        index: o,
                    };
                parent_nodes.push(new_node.clone());
                self.nodes.push(new_node);
                


                //println!("node child left: {:#?}", &new_node.left_child);
                //println!("node child right: {:#?}", &new_node.right_child);
                
                o += 1; 
                //increment loop by 2
                i += 2;
            }
            //change level
            self.depth += 1;
            children_nodes = parent_nodes;
            parent_nodes = Vec::new();
            //divide # of starting nodes by 2, represents remaining population of nodes that can be hashed together
            n = n / 2;
            //if there is an odd number of nodes excluding the root, insert copy of the [len-1] node
            let length : usize = self.nodes.len();
            if n > 1 && n % 2 == 1{
                children_nodes.push(children_nodes[children_nodes.len() -1].clone());
                self.nodes.push(children_nodes[children_nodes.len() -1].clone());
                self.nodes[length -1].copied = true;
                println!("inserted node hash: {:#?}", self.nodes[length-1].hash);
                n += 1;
            }
            if n == 1{
                self.root = Node{                        
                    left_child: Box::new(Some(self.nodes[length - 3].clone())),
                    right_child: Box::new(Some(self.nodes[length - 2].clone())),
                    hash: self.nodes[length - 1].hash,
                    copied: false,
                    index: self.nodes.len() + 1,
                };
                println!("root: {:#?}", self.root.hash);
            }
        }
        self
    }

    //we can calculate a balanced tree's number of elements by 2^(depth)
    fn print_tree(self) {

        
    }
    fn get_element_count(self) -> usize{
        let base: usize = 2;
        base.pow(self.depth)
    }
    fn get_root(self) -> [u8;32]{
        self.root.hash
    }

    //use hashmap to locate neighbored elements and generate parent node hashes
    fn generate_proof(self, leaf: &[u8;32]) -> Option<Vec<[u8;32]>> {

        //strat 2.0: the leaf hash we receive MUST be located in the HashMap, else throw error, invalid leaf (or end of set).
        //retrieve the corresponding VALUE inside of the HashMap for leaf's hash
        //hash together the resulting hashes
        //lookup result and repeat process
        
        let mut proof_hashes: Vec<[u8;32]> = vec![];
        let mut current_hash = leaf;
        let mut parent_node_hash:[u8;32];
        loop{
            let neighbor_hash = self.neighbors.get(current_hash);
            match neighbor_hash{
                Some(hash) => {
                    parent_node_hash = Node::hash_nodes([current_hash, hash]);
                    proof_hashes.push(*hash);
                    current_hash = &parent_node_hash;
                },
                //if we cannot locate a value in the mapping given the key, break the loop and return the vector of hashes
                None => break,
            }           
        }
       
        if proof_hashes.len() == 0 {
           return None;
        }
        else{
            Some(proof_hashes)
        }

    }
    
    
    //okay, I gotta refactor this to be cleaner. I don't need this extra loop sequence
fn search_tree(self, intermediate_hashes: Vec<[u8;32]>, leaf: [u8;32]) -> bool{
        //stategy: root => match ((left child || right child), intermediate_hash[i])  => node @ matched index ... => ... =>    
        
        let mut found: bool = false;
        
        let mut ptr = 0;
        
        match &*self.root.left_child {
            Some(x) => {

                if x.hash == leaf{
                    found = true;
                }
                if x.hash == intermediate_hashes[0]{
                    ptr = x.index;
                }
            },
            None => ()
        };
        if found == true { return found; }

        match &*self.root.right_child {
            Some(x) => {

                if x.hash == leaf{
                    found = true;
                }
                if x.hash == intermediate_hashes[0]{
                    ptr = x.index;
                }
            },
            None => ()
        };
        if found == true { return found; }
        //counter for intermediate hashes variable
        let mut int_hashes: usize = 1;
        //for keeping track of depth
        let mut i: usize = 2;
        while i < self.depth.try_into().unwrap() {

           let node = &self.nodes[ptr];
           
            match &*node.left_child {
                Some(x) => {
                    if x.hash == leaf{
                        found = true;
                    }
                    if x.hash == intermediate_hashes[int_hashes]{
                        ptr = x.index;
                    }
                },
                None => ()
             };
             match &*node.right_child {
                Some(x) => {
                    if x.hash == leaf{
                        found = true;
                    }
                    if x.hash == intermediate_hashes[int_hashes]{
                        ptr = x.index;
                    }
                },
                None => ()

                };
            if found == true { return found; }
            int_hashes += 1;
            i += 1; 
        };
        found
     }
}

#[derive(Clone, Debug)]
struct Node{
    left_child: Box<Option<Node>>,
    right_child: Box<Option<Node>>,
    hash: [u8;32],
    copied: bool,
    index: usize,
}

impl Node{
    fn new(lc: Box<Option<Node>>, rc: Box<Option<Node>>, h: [u8;32]) -> Node{
        Self{left_child: lc, right_child: rc, hash: h, copied: false, index : 0}
    }
    fn get_left(self) -> Box<Option<Node>>{
        self.left_child
    }
    fn get_right(self) -> Box<Option<Node>>{
        self.right_child
    }
    fn get_hash(self) -> [u8;32]{
        self.hash
    }
    fn is_copied(self) -> bool{
        self.copied
    }
    
    fn hash_nodes(input: [&[u8;32];2]) -> [u8;32] {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(input[0]);
        hasher.update(input[1]);
        hasher.finalize(&mut output);
        output
    }
}
#[derive(Clone, Debug)]

struct Leaf{
    data: &'static str,
}
impl Leaf{
    fn new(leaf_data: &'static str) -> Self{
        let x = leaf_data.as_bytes();
        Leaf::hash_leaf(x);
        Self{data: leaf_data}
    }
    
    fn hash_leaf(input: &[u8]) -> [u8;32] {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(input);
        hasher.finalize(&mut output);
        output
    }
}   

fn verify_proof(merkle_root: [u8;32], leaf: Leaf, hashes: Vec<[u8;32]>, index: usize) -> bool{
    let mut counter = 0;
    let mut idx = index;
    let mut hash = Leaf::hash_leaf(leaf.data.as_bytes());
    let mut verified = false;
    loop{
        let proof_element = hashes[counter];
        
        if idx % 2 == 0 {
            hash = Node::hash_nodes([&hash, &proof_element]);
        }
        else{
            hash = Node::hash_nodes([&proof_element, &hash]);
        }
        println!("Verifying...{:?}", &hash);

        if hash == merkle_root{
           verified = true;
           break
        }
        if counter == hashes.len() - 1{
            break;
        }
        counter += 1;
        idx /= 2;
    }

    verified

}

fn main(){

    let a = Leaf::new("a");
    let b = Leaf::new("b");
    let c = Leaf::new("c");
    let d = Leaf::new("d");
    let e = Leaf::new("e");

    let leafs = vec![a.clone(), b, c, d, e];
    let tree = Tree{
        root: Node::new(Box::new(None), Box::new(None), Leaf::hash_leaf(a.data.as_bytes())),
        nodes: vec![],
        neighbors: HashMap::new(),
        depth: 0,
    };
    
    let x = Tree::new(tree, leafs);

    let a_hashed = Leaf::hash_leaf(&a.data.as_bytes());

    let elements =  Tree::generate_proof(x.clone(), &a_hashed).expect("no proof bruh");
    println!("Proof Elements: {:?}", &elements);

    let verified: bool = verify_proof(x.root.hash, a, elements, 0);
    println!("Valid Leaf: {}", verified);

 }
