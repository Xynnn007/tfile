use std::cmp::min;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;
use std::path::Path;
use std::cmp::Ordering;
use std::sync::{Mutex, mpsc, mpsc::TryRecvError, Arc};
use std::thread;
use std::time::Duration;

use aes::cipher::generic_array::GenericArray;
use aes::Aes128Ctr;
use aes_gcm::aead::{Aead, NewAead, Payload};
use aes_gcm::{Aes128Gcm, Key as AesGcmKey, Nonce as AesGcmNonce};
use bytes::{Buf, Bytes, BytesMut};
use chacha20::cipher::{NewStreamCipher, SyncStreamCipher};
use chacha20::{ChaCha8, Key, Nonce};
use ctr::cipher::{NewCipher, StreamCipher};
use log::{debug, info};
use nohash_hasher::NoHashHasher;
use rand::seq::SliceRandom;
use rand::{thread_rng, AsByteSliceMut, Rng};
use serde::{Deserialize, Serialize};
use queue::Queue;
use hashlink::LinkedHashMap;

use crate::io::BaseIOService;
use crate::oram::toram::{layer::Layer};
use crate::oram::BaseORAM;
use crate::{ORAMConfig, ORAMManager};

pub mod layer;

#[allow(dead_code)]

#[derive(Clone, Serialize, Deserialize)]

// here id = -1 means it's a dummy block
pub struct Block {
    id: i64,
    payload: Bytes,
}

#[derive(Serialize, Deserialize)]
pub struct Bucket {
    version: String,
    format: String,
    blocks: Vec<Block>,
}

impl Bucket {
    fn contains(&mut self, id: i64) -> bool {
        for b in &self.blocks {
            if b.id == id {
                return true;
            }
        }
        false
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedBytes {
    iv: Bytes,
    ciphertext: BytesMut,
}


// payoff queue and counter, refered as R
#[derive(Serialize, Deserialize)]
pub struct R {
    rq : Queue<i64>,
    rc : Vec<i64>
}

impl R {
    pub fn new(l : i64) -> Self {
        let r = Self {
            rq: Queue::<i64>::new(),
            rc: std::vec::from_elem(0, l as usize)
        };
        r
    }

    // when dummy hit comes, return a generated hit
    pub fn dummy_hit(&mut self, l : i64) -> i64{
        if self.rc[l as usize] > 0 {
            self.rc[l as usize] -= 1;
            return self.rq.dequeue().unwrap()
        }

        l
    }

    // when true hit comes, change R
    pub fn true_hit(&mut self, l : i64) {
        self.rc[l as usize] += 1;
        let mut rng = thread_rng();
        let pay_l = rng.gen_range(0, l + 1);
        match self.rq.queue(pay_l) {
            Ok(_) => {},
            Err(()) => panic!("True hit enqueue failed.")
        }
    }
} 

#[derive(Serialize, Deserialize)]
pub struct Stash {
    size: i64,
    q: Vec<LinkedHashMap<i64,Block>>
}

impl Stash {
    pub fn new(l : i64) -> Self {
        let r = Self {
            size: l,
            q: std::vec::from_elem(LinkedHashMap::<i64,Block>::new(), l as usize)
        };
        r
    }

    pub fn len(&self, l: i64) -> i64 {
        self.q[l as usize].len() as i64
    }

    pub fn push2(&mut self, l: i64, block: Block) {
        self.q[l as usize].insert(block.id, block);
    }

    pub fn push3(&mut self, l: i64, add: i64, block: Block) {
        self.q[l as usize].insert(add, block);
    }

    pub fn pop(&mut self, id: i64) -> Option<Block> {
        for q in &mut self.q {
            if q.contains_key(&id) {
                let block = q.get(&id).unwrap().clone();
                (*q).remove(&id);
                return Some(block);
            }
        }
        None
    }

    pub fn is_empty(&self, l: i64) -> bool {
        self.q[l as usize].is_empty()
    }

    pub fn pop_layer(&mut self, l: i64) -> Option<Block> {
        match self.q[l as usize].is_empty() {
            true => {
                None
            },
            false => {
                let (_, v) = self.q[l as usize].pop_front().unwrap();
                Some(v)
            }
        }
    }
} 

pub enum Operation {
    READ,
    WRITE,
}

enum OpResult {
    R(Vec<u8>),
    W(usize),
}
pub struct Task {
    op: Operation, 
    add: i64, 
    data: Option<Bytes>
}

struct Engine<'a> {
    pub args: ORAMConfig,
    pub io: Box<dyn BaseIOService + 'a>,
    pub position_map: HashMap<i64, (i64, i64), BuildHasherDefault<NoHashHasher<i64>>>,
    pub stash: Stash,
    pub layer: Layer,
    pub r: R,
    pub encryption_key: Vec<u8>,
    pub delta: i64,

    pub task_rc: mpsc::Receiver<Task> ,
    pub result_sc: mpsc::Sender<OpResult>
}

impl<'a> Engine<'a> {
    pub fn new(
        args: ORAMConfig, 
        io: Box<dyn BaseIOService>, 
        task_rc: mpsc::Receiver<Task>,
        result_sc: mpsc::Sender<OpResult>,
        height: i64
    ) -> Self {
        Self {
            args,
            io,
            position_map: HashMap::<i64, (i64, i64), BuildHasherDefault<NoHashHasher<i64>>>::default(),
            layer: Layer::new(height),
            stash: Stash::new(height),
            r: R::new(height),
            encryption_key: Vec::new(),
            task_rc,
            result_sc,
            delta: 1
        }
    }

    pub fn setup(&mut self) {
        info!("Initializing T-ORAM...");
        self.load_encryption_key();
        let rbmap = self.init_position_map();
        self.init_public_storage(rbmap);
        info!("...initialization complete!");

        info!("Starting daemon to handle true access...");
        self.start_daemon();
    }

    fn start_daemon(&mut self) {
        println!("Successfully started t-oram daemon...");
        loop {
            println!("123");
            match &self.task_rc.try_recv() {
                Err(e) => match e {
                    TryRecvError::Empty => {
                        self.dummy_access();
                    },
                    _ => {
                        panic!("Closed pipeline!");
                    }
                },
                Ok(t) => {
                    let r = self.access(&t.op, &t.add, &t.data);
                    match t.op {
                        Operation::WRITE => {
                            let siz = r.unwrap().len();
                            self.result_sc.send(OpResult::W(siz));
                        },
                        Operation::READ => {
                            let data = r.unwrap().to_vec();
                            self.result_sc.send(OpResult::R(data));
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(self.delta as u64));
        }
    }

    /// Verify that each block is correctly mapped to a bucket
    // pub fn verify_main_invariant(&mut self) -> bool {
    //     let mut incorrectly_mapped_blocks = vec![];
    //     for block_id in 0..self.args.n {
    //         let bucket = self.read_bucket(bucket_id);
    //         for block in bucket {
    //             if block.id != -1 {
    //                 let (l, x) = self.position_map.get(&block.id ).unwrap();
    //                 let path = self.tree.path(*leaf);
    //                 if !bucket.contains(&bucket_id) {
    //                     incorrectly_mapped_blocks.push(block.id);
    //                 }
    //             }
    //         }
    //     }
    //     incorrectly_mapped_blocks.is_empty()
    //     true
    // }

    /// The T-ORAM Access function.
    /// Do operation `op` ("read" or "write") on block with ID `a`.
    /// If it is a "write", replace data with `data_star`.
    /// Return the block's data, if op == "read".
    /// Return the block's previous data if op == "write".
    pub fn access(&mut self, op: &Operation, add: &i64, data_str: &Option<Bytes>) -> Option<Bytes> {
        // alg 1-7
        match self.stash.pop(*add) {
            Some(t) => {
                match op {
                    Operation::WRITE => {
                        let b = data_str.as_ref().unwrap();
                        let data = Block {
                            id: *add,
                            payload: b.clone()
                        };
                        self.stash.push3(0, *add, data);
                        self.dummy_access();
                        return Some(b.clone());
                    },
                    Operation::READ => {
                        self.stash.push3(0, *add, t.clone());
                        self.dummy_access();
                        return Some(t.payload);
                    }
                }
            },
            _ => {}
        };

        // alg 11-14
        let (l,x) = self.position_map.get(&add).unwrap().clone();
        self.r.true_hit(l);

        // alg 15-16
        let bucket_id = self.get_bucket_id(&l, &x);
        let blocks: Vec<Block> = self.read_bucket(bucket_id);
        let mut _data = self.push_down(blocks, &add).unwrap();

        //alg 18-24
        match op {
            Operation::WRITE => {
                _data.payload = data_str.as_ref().unwrap().clone();
            },
            _ => {},
        }
        let res = _data.payload.clone();
        self.stash.push3(0, *add, _data);
        let bucket = self.dequeue(&l, &x);
        self.write_bucket(bucket_id, bucket);

        Some(res)
    }

    pub fn push_down(&mut self, bucket: Vec<Block>, add: &i64) -> Option<Block> {
        let mut data = None; 
        for b in bucket {
            if b.id != *add || *add == -1 {
                let _add = b.id;
                let  (mut _l, mut _x) = self.position_map
                    .get(&_add)
                    .unwrap()
                    .clone();
                _l = min(_l + 1, self.layer.height());
                self.position_map.insert(_add, (_l, -1));
                self.stash.push3(_l, _add, b);
            } else {
                data = Some(b.clone());
            }
        }

        data
    }

    pub fn dequeue(&mut self, l: &i64, x: &i64) -> Vec<Block> {
        let mut bucket: Vec<Block> = Vec::new();
        for i in 0..self.args.z {
            if self.stash.is_empty(i) {
                let block = self.stash.pop_layer(*l).unwrap();
                let add = block.id.clone();
                bucket.push(block);
                self.position_map.insert(add, (l.clone(), x.clone()));
            } else {
                bucket.push(self.get_dummy_block());
            }
        }
        bucket
    }   

    pub fn dummy_access(&mut self) {
        // 1-6
        let mut l = thread_rng().gen_range(0, self.layer.height());
        l = self.r.dummy_hit(l);
        let x = thread_rng().gen_range(0, self.layer.len(l));

        // 8-13
        let bucket_id = self.get_bucket_id(&l, &x);
        let mut bucket: Vec<Block> = self.read_bucket(bucket_id);
        let mut _bucket: Vec<Block> = Vec::new();
        if self.stash.len(l) > self.args.g {
            let _ = self.push_down(bucket, &-1);
            bucket = self.get_dummy_bucket();
        }

        // 15-28
        for i in 0..self.args.z {
            if (&bucket)[i as usize].id >= 0 {
                _bucket.push((&bucket)[i as usize].clone());
                continue
            } 

            if self.stash.len(l) > 0 {
                let block = self.stash.pop(l).unwrap();
                let add = block.id;
                _bucket.push(block);
                self.position_map.insert(add, (l.clone(),x.clone()));
            } else {
                let block = self.get_dummy_block();
                _bucket.push(block);
            }
        }

        // 30
        self.write_bucket(bucket_id, _bucket);
    }

    /// Return the path to the file containing the stash
    /// in the client data directory.
    pub fn stash_path(&self) -> String {
        String::from(
            Path::new(&self.args.client_data_dir)
                .join("stash.bin")
                .to_str()
                .unwrap(),
        )
    }

    /// Return the path to the file containing the position map
    /// in the client data directory.
    pub fn position_map_path(&self) -> String {
        String::from(
            Path::new(&self.args.client_data_dir)
                .join("position_map.bin")
                .to_str()
                .unwrap(),
        )
    }

    /// Return the path to the file containing the Rc and Rq
    /// in the client data directory.
    pub fn r_path(&self) -> String {
        String::from(
            Path::new(&self.args.client_data_dir)
                .join("r.bin")
                .to_str()
                .unwrap(),
        )
    }

    /// Load the encryption key
    ///
    /// Unless encryption is disabled, this loads the encryption key.
    /// This is achieved by deriving a master key from the given passphrase, and then
    /// using this master key to decrypt the actual encryption key for this ORAM.
    pub fn load_encryption_key(&mut self) {
        if !self.args.disable_encryption {
            let (derived_key, _) =
                ORAMManager::derive_key(&self.args.encryption_passphrase, &self.args.salt);

            // decrypt encryption key using derived_key
            let (ciphertext, nonce) =
                ORAMManager::deserialize_key(self.args.clone().encrypted_encryption_key);
            let encryption_key = ORAMManager::decrypt_key(derived_key, ciphertext, nonce)
                .expect("Failed to load encryption key. Invalid passphrase?");

            // set encryption_key to decrypted_key
            self.encryption_key = encryption_key;
        }
    }

    /// Load the client data
    pub fn load(&mut self) {
        debug!("Loading client data from disk...");
        self.load_encryption_key();

        let stash_bytes = self.io.read_file(self.stash_path());
        self.stash = bincode::deserialize(&stash_bytes).unwrap();

        let position_map_bytes = self.io.read_file(self.position_map_path());
        self.position_map = bincode::deserialize(&position_map_bytes).unwrap();

        let r_bytes = self.io.read_file(self.r_path());
        self.r = bincode::deserialize(&r_bytes).unwrap();

        debug!("...done!");
    }

    /// Save the client data
    pub fn save(&mut self) {
        debug!("Saving client data to disk...");
        // create client data dir if it doesn't exist
        match std::fs::create_dir_all(Path::new(&self.args.client_data_dir)) {
            Ok(_) => (),
            Err(e) => panic!("Failed to create client directory: {}", e),
        }

        // save stash and position map
        let stash_bytes = bincode::serialize(&self.stash).unwrap();
        let position_map_bytes = bincode::serialize(&self.position_map).unwrap();
        let r_bytes = bincode::serialize(&self.r).unwrap();
        self.io.write_file(self.stash_path(), &stash_bytes);
        self.io
            .write_file(self.position_map_path(), &position_map_bytes);
        self.io
            .write_file(self.r_path(), &r_bytes);
        debug!("...done!");
    }

    /// Initialize the position map with random values.
    /// Each block is assigned to a random layer, and a random bucket
    pub fn init_position_map(&mut self) -> HashMap<i64, HashMap<i64, i64>> {
        let block_count = self.args.n * self.args.z;
        let mut block_ids: Vec<i64> = (0..block_count).collect();
        block_ids.shuffle(&mut thread_rng());

        // l_id = log2(bucket_id + 1)
        // b_id = bucket_id + 1 - (1 << l_id)
        let mut bmap = HashMap::<i64, (i64, i64)>::new(); // block_id -> (bucket_id, block_index_within_bucket)
        let mut rbmap: HashMap<i64, HashMap<i64, i64>> = HashMap::new(); // bucket_id -> block_index_within_bucket -> block_id

        let mut i = 0;
        for bucket_id in 0..self.args.n {
            for block_index in 0..self.args.z {
                let block_id = block_ids.get(i).unwrap();
                bmap.insert(*block_id, (bucket_id, block_index));

                // rbmap.put(bucket_id, block_index, block_id)
                Self::mapmap_insert(&mut rbmap, &bucket_id, block_index, block_id);
                i += 1;
            }
        }
        
        for block_id in 0..self.args.n  {
            let (bucket_id, _) = bmap.get(&block_id).unwrap();
            let l = ((bucket_id + 1) as f64).log2().floor() as i64;
            let b = bucket_id + 1 - (1 << l) ;

            self.position_map.insert(block_id, (l, b));
        }

        rbmap
    }

    /// Insert into a map<i64, map<i64, i64>> more easily
    pub fn mapmap_insert(
        rbmap: &mut HashMap<i64, HashMap<i64, i64>>,
        bucket_id: &i64,
        block_index: i64,
        block_id: &i64,
    ) {
        match rbmap.get_mut(&bucket_id) {
            Some(entry) => {
                entry.insert(block_index, *block_id);
            }
            _ => {
                let mut new_map = HashMap::new();
                new_map.insert(block_index, *block_id);
                rbmap.insert(*bucket_id, new_map);
            }
        }
    }

    /// Initialize the public storage
    ///
    /// This creates one file per bucket in the tree.
    /// Each file is filled with zeros so that the file size matches the bucket size.
    pub fn init_public_storage(&mut self, rbmap: HashMap<i64, HashMap<i64, i64>>) {
        debug!("Initializing public storage...");
        for (bucket_id, y) in rbmap {
            let bucket_path = self.node_path(bucket_id);
            let mut block_ids = Vec::new();
            for block_index in 0..self.args.z {
                let block_id = *y.get(&block_index).unwrap();
                match block_id.cmp(&self.args.n) {
                    Ordering::Less => {
                        block_ids.push(block_id);
                    },
                    _ => {
                        block_ids.push(-1);
                    }
                }
            }
            self.write_empty_bucket(block_ids, bucket_path);
        }
        debug!("...done!");
    }

    /// Reads all the blocks from the bucket with ID `bucket_id`.
    fn read_bucket(&self, bucket_id: i64) -> Vec<Block> {
        let bucket_path = self.node_path(bucket_id);
        self.raw_read_bucket(bucket_path)
    }

    /// Write blocks to bucket with ID `bucket_id`
    #[allow(clippy::comparison_chain)]
    fn write_bucket(&mut self, bucket_id: i64, mut blocks: Vec<Block>) {
        let missing_blocks = self.args.z - blocks.len() as i64;
        if missing_blocks > 0 {
            // pad blocks
            for _ in 0..missing_blocks {
                blocks.push(self.get_dummy_block());
            }
        } else if missing_blocks < 0 {
            panic!("Error: trying to write more blocks than the bucket can hold");
        } else {
            // do nothing
        }

        // write blocks to bucket
        let node_path = self.node_path(bucket_id);
        self.raw_write_bucket(node_path, blocks);
    }

    /// Write empty blocks with the specified IDs to the given bucket
    pub fn write_empty_bucket(&mut self, block_ids: Vec<i64>, node_path: String) {
        let empty_block_contents = Bytes::from(vec![0u8; self.args.b as usize]);
        let mut blocks = Vec::new();

        for block_id in block_ids {
            blocks.push( Block{
                id: block_id ,
                payload: empty_block_contents.clone(),
            });
        }

        // write blocks to bucket
        self.raw_write_bucket(node_path, blocks);
    }

    /// Return the blocks in the bucket at given path.
    ///
    /// Note that if encryption is enabled (default),
    /// the bucket is decrypted after being read.
    fn raw_read_bucket(&self, path: String) -> Vec<Block> {
        let file_contents = self.io.read_file(path);

        let bucket: Bucket = match self.args.disable_encryption {
            true => bincode::deserialize(file_contents.as_slice()).unwrap(),
            false => {
                let encrypted_bytes: EncryptedBytes =
                    bincode::deserialize(file_contents.as_slice()).unwrap();
                self.decrypt_bucket(encrypted_bytes)
            }
        };

        bucket.blocks
    }

    /// Write the given blocks to the bucket at given path.
    ///
    /// Note that if encryption is enabled (default),
    /// The bucket is encrypted before being written.
    fn raw_write_bucket(&mut self, path: String, blocks: Vec<Block>) {
        let bucket = Bucket {
            blocks,
            format: self.name(),
            version: String::from("1.0"),
        };

        let bytes: Vec<u8> = match self.encryption_key.is_empty() {
            true => bincode::serialize(&bucket).unwrap(),
            false => {
                let encrypted_bytes = self.encrypt_bucket(bucket);
                bincode::serialize(&encrypted_bytes).unwrap()
            }
        };

        self.io.write_file(path, bytes.as_slice());
    }

    /// Encrypt a bucket and return the ciphertext and IV
    fn encrypt_bucket(&self, bucket: Bucket) -> EncryptedBytes {
        let mut data = bincode::serialize(&bucket).unwrap();
        let (iv, ct) = self.encrypt(&mut data);

        let mut bm = BytesMut::new();

        match ct {
            Some(ciphertext) => {
                bm.extend_from_slice(&ciphertext);
            }
            None => {
                bm.extend_from_slice(&data);
            }
        }

        EncryptedBytes {
            iv: Bytes::from(iv),
            ciphertext: bm,
        }
    }

    /// Decrypt a bucket, given the ciphertext and IV
    fn decrypt_bucket(&self, encrypted_bytes: EncryptedBytes) -> Bucket {
        let mut data = encrypted_bytes.ciphertext;
        let ciphertext = data.as_byte_slice_mut();

        match self.decrypt(encrypted_bytes.iv.bytes(), ciphertext) {
            Some(plaintext) => {
                let bucket: Bucket = bincode::deserialize(&plaintext).unwrap();
                bucket
            }
            None => {
                let bucket: Bucket = bincode::deserialize(&ciphertext).unwrap();
                bucket
            }
        }
    }

    /// Encrypt the given data
    fn encrypt(&self, mut data: &mut [u8]) -> (Vec<u8>, Option<Vec<u8>>) {
        match &self.args.cipher[..] {
            "aes-ctr" => {
                let iv = thread_rng().gen::<[u8; 16]>();

                let key = GenericArray::from_slice(&self.encryption_key);
                let nonce = GenericArray::from_slice(&iv);
                let mut cipher = Aes128Ctr::new(key, nonce);
                cipher.apply_keystream(&mut data);
                (iv.to_vec(), None)
            }
            "chacha8" => {
                let iv = thread_rng().gen::<[u8; 12]>();

                let key = Key::from_slice(&self.encryption_key);
                let nonce = Nonce::from_slice(&iv);
                let mut cipher = ChaCha8::new(&key, &nonce);
                cipher.apply_keystream(&mut data);
                (iv.to_vec(), None)
            }
            "aes-gcm" => {
                let key = AesGcmKey::from_slice(&self.encryption_key);
                let cipher = Aes128Gcm::new(key);

                let iv = thread_rng().gen::<[u8; 12]>();
                let nonce = AesGcmNonce::from_slice(&iv);

                let ad = b"oramfs";
                let payload = Payload { aad: ad, msg: data };
                let ciphertext = cipher
                    .encrypt(nonce, payload)
                    .expect("AES-GCM encryption failure");

                (iv.to_vec(), Some(ciphertext))
            }
            _ => panic!("Unsupported cipher."),
        }
    }

    /// Decrypt the given data
    fn decrypt(&self, iv: &[u8], mut data: &mut [u8]) -> Option<Vec<u8>> {
        match &self.args.cipher[..] {
            "aes-ctr" => {
                let key = GenericArray::from_slice(&self.encryption_key);
                let nonce = GenericArray::from_slice(&iv);
                let mut cipher = Aes128Ctr::new(key, nonce);
                cipher.apply_keystream(&mut data);
                None
            }
            "chacha8" => {
                let key = Key::from_slice(self.encryption_key.as_slice());
                let nonce = Nonce::from_slice(iv);
                let mut cipher = ChaCha8::new(&key, &nonce);
                cipher.apply_keystream(&mut data);
                None
            }
            "aes-gcm" => {
                let key = AesGcmKey::from_slice(&self.encryption_key);
                let cipher = Aes128Gcm::new(key);
                let nonce = AesGcmNonce::from_slice(&iv);

                let ad = b"oramfs";
                let payload = Payload { aad: ad, msg: data };
                let plaintext = cipher
                    .decrypt(nonce, payload)
                    .expect("[SECURITY WARNING] It looks like the ciphertext or tag has been tampered with. Aborting.");
                Some(plaintext)
            }
            _ => panic!("Unsupported cipher."),
        }
    }

    /// Get bucket_id by (l,x)
    fn get_bucket_id(&self, l: &i64, x: &i64) -> i64 {
        (1 << l) + x - 1
    }

    fn get_dummy_block(&self) -> Block {
        let empty_block_contents = Bytes::from(vec![0u8; self.args.b as usize]);

            // pad blocks
        Block {
            id: -1,
            payload: empty_block_contents.clone(),
        }
    }

    fn get_dummy_bucket(&self) -> Vec<Block> {
        let mut bucket: Vec<Block> = Vec::new();
        for _ in 0..self.args.z {
            bucket.push(self.get_dummy_block())
        } 
        bucket
    }

    fn node_filename(&self, i: i64) -> String {
        format!("node_{}.oram", i)
    }

    /// Return the path to the node with given number
    fn node_path(&self, i: i64) -> String {
        let filename = self.node_filename(i);
        let path = Path::new(&self.args.public_directory);
        let node_path = path.join(filename);
        String::from(node_path.to_str().unwrap())
    }

    fn name(&self) -> String {
        String::from("t-oram")
    }
}

pub struct TORAM<'a> {
    args: &'a ORAMConfig,
    task_sc: mpsc::Sender<Task> ,
    result_rc: mpsc::Receiver<OpResult>,

    handler: thread::JoinHandle<()>,
    size: i64,
}

impl BaseORAM for TORAM<'_> {
    fn test_state(&mut self) -> bool {
        true
    }

    fn init(&mut self) {
        // self.engine.setup()
    }

    fn cleanup(&mut self) {
        debug!("T-ORAM cleanup...");
        // self.engine.save();
        debug!("...done!");
    }

    /// Save the stash and position map after each operation.
    /// This should prevent data loss in case the process is killed before unmounting.
    fn post_op(&mut self) {
        // self.engine.save();
    }

    /// Delegate read operations to the access() method of Path ORAM
    fn read(&mut self, block_id: i64) -> Vec<u8> {
        let t = Task {
            op: Operation::READ,
            add: block_id,
            data: None
        };

        self.task_sc.send(t);
        // let rc = mpsc::Receiver::
        match  self.result_rc.recv().unwrap() {
            OpResult::R(r) => {
                r
            },
            _ => panic!("Could not read block"),
        }
    }

    /// Delegate write operations to the access() method of Path ORAM
    fn write(&mut self, block_id: i64, data: Bytes) -> usize {
        let t = Task {
            op: Operation::WRITE,
            add: block_id,
            data: Some(data)
        };

        self.task_sc.send(t);
        // let rc = mpsc::Receiver::
        match  self.result_rc.recv().unwrap() {
            OpResult::W(w) => {
                w
            },
            _ => panic!("Could not write block"),
        }
    }

    fn size(&self) -> i64 {
        self.size
    }

    fn name(&self) -> String {
        String::from("t-oram")
    }

    fn args(&self) -> &ORAMConfig {
        self.args
    }
}

impl<'a> TORAM<'a> {
    pub fn new(args: &'a ORAMConfig, io: Box<dyn BaseIOService>) -> Self {
        let height = calc_height(args.n);
        let (task_sc,task_rc) = mpsc::channel::<Task>();
        let (result_sc,result_rc) = mpsc::channel::<OpResult>();
        let args2 = args.clone();
        //let io2 = io.clone();

        let handler = thread::spawn(move || {
            let mut engine = Engine::new(
                args2,
                io,
                task_rc,
                result_sc,
                height
            );

            engine.setup();
        });

        let mut toram = Self {
            args,
            handler,
            task_sc,
            result_rc,

            size: args.b * args.z * args.n,
        };

        // if !args.init {
        //     toram.engine.load();
        // }

        toram
    }
}

fn calc_height(n: i64) -> i64 {
    ((n + 1) as f64).log2().ceil() as i64
}