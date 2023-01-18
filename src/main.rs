extern crate tiny_keccak;
use std::fmt::Display;

use tiny_keccak::Keccak;
use crate::tiny_keccak::Hasher;

#[warn(dead_code)]

struct Tree{
    root: Node,
    nodes: Vec<Node>,
    depth: u32,
}


 impl Tree{
     fn new(mut self, leafs: Vec<Leaf>) -> Tree {
        //returns new merkle tree constructed from leafs: Vec<Leaf>
        // ---------------------------------------
        //creates initial nodes for merkle tree
        //iterate through leafs
        //on each iteration, hash the data contained in the leaf with Keccak256
        //append new Node to children_nodes  
        let mut parent_nodes: Vec<Node> = Vec::new();
        let mut children_nodes: Vec<Node> = leafs.iter().map(|x|{
           let x_hashed = Leaf::hashLeaf(x.data.as_bytes());
            Node::new(Box::new(None), Box::new(None), x_hashed)
        }).collect();
        //check length of leaf nodes, if there is an odd number of leaf nodes, copy the odd element and push it to the array
        let len = &children_nodes.len();
        if len % 2 == 1 { 
            children_nodes.push(children_nodes[len -1].clone()); 
            children_nodes[len-1].copied = true;
        }
         
        let mut n = children_nodes.len();
        
        //main loop, make sure there is at least two elemnts left, otherwise we've hit the root
        while n > 1{
            let mut o: usize = 0;
            let mut i = 0;
            //iterates over children_nodes to create new parent nodes
            while i < n - 1 {
                //create input for Node::hashNodes()
                let array = [&children_nodes[i].hash, &children_nodes[i + 1].hash];
                //hash nodes together
                let new_node_hash = Node::hashNodes(array);
                o += 1; 
                parent_nodes.push(
                    Node{ 
                        left_child: Box::new(Some(children_nodes[i].clone())),
                        right_child: Box::new(Some(children_nodes[i + 1].clone())),
                        hash: new_node_hash,
                        copied: false, 
                        index: o,
                    });
                self.nodes.push(
                    Node{ 
                        left_child: Box::new(Some(children_nodes[i].clone())),
                        right_child: Box::new(Some(children_nodes[i + 1].clone())),
                        hash: new_node_hash,
                        copied: false, 
                        index: o,
                    }
                );
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
            if n > 1 && n % 2 == 1{
                children_nodes.push(children_nodes[len -1].clone());
                self.nodes.push(children_nodes[len -1].clone());
                self.nodes[len-1].copied = true;
            }
            if n == 1{
               
                self.root = Node{                        
                    left_child: Box::new(Some(self.nodes[len - 2].clone())),
                    right_child: Box::new(Some(self.nodes[len - 1].clone())),
                    hash: Node::hashNodes([&self.nodes[len - 2].hash.clone(), &self.nodes[len - 1].hash.clone()]),
                    copied: false,
                    index: self.nodes.len() + 1,
                }
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
            if found == true { return found; }
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
    
    fn hashNodes(input: [&[u8;32];2]) -> [u8;32] {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(input[0]);
        hasher.update(input[1]);
        hasher.finalize(&mut output);
        output
    }
}
struct Leaf{
    data: &'static str,
}
impl Leaf{
    fn new(leaf_data: &'static str) -> Self{
        let mut x = leaf_data.as_bytes();
        Leaf::hashLeaf(x);
        Self{data: leaf_data/* , hashed_data: x*/}
    }
    
    fn hashLeaf(input: &[u8]) -> [u8;32] {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(input);
        hasher.finalize(&mut output);
        output
    }
}   


fn main(){
    todo!();
}
