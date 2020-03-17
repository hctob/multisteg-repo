use std::env; //eivnornment variables
              //use std::path;
use std::collections::HashMap;
use std::str::FromStr;
//extern crate regex;
use multisteglib;
use std::cmp;
use std::fs;
use std::io; //file io
use std::io::prelude::*;
use std::str;

//Threading/Parallelism
use std::rc::Rc;
use std::sync::{Mutex, Arc};
use std::sync::atomic::{AtomicUsize};
use std::thread;
use std::sync::mpsc;

const NULL_BYTE: u8 = 0x00;


fn main() {
    let args: Vec<String> = env::args().collect();
    match args.len() - 1 {
        0 => {
            eprintln!("Usage: \nDecoding: cargo run <threads> <directory>\nEncoding: cargo run <threads> <message file> <input image directory> <output directory>");
        }
        2 => {
            /*println!("Two arguments");
            let args_slice = &args[1].trim();
            let file_bytes: Vec<u8> = multisteglib::read_byte_by_byte(args_slice).expect("Error: could not read file bytes.");
            let valid_header: i32 = multisteglib::validate_header(&file_bytes);
            if valid_header == -1 {
                eprintln!("Error: invalid header type.");
            }
            else {
                let valid_header: usize = valid_header as usize;
                println!("Header length: {}", valid_header);
                let data_bytes: Vec<u8> = file_bytes[valid_header..].to_vec();
                let decoded_message = multisteglib::decode_message(&data_bytes).unwrap();
                println!("{}", decoded_message);
            }*/
            //working decode for one image
            let _threads: u32 = u32::from_str(&args[1].trim()).unwrap();
            let decode_directory = &args[2].trim();

            let directory_check = std::path::Path::new(decode_directory)
                .metadata()
                .expect("Error: could not find path to specified directory");
            assert!(directory_check.is_dir()); //assert that argument is actually a directory
                                               //let dir = std::path::Path::new(decode_directory);
                                               //assert!(std::env::set_current_dir(&dir).is_ok());
                                               //println!("Successfully set working directory to {:?}", dir.display());
            let mut ret: String = String::new();
            //iterate through each picture in the directory
            for file in std::fs::read_dir(decode_directory)
                .expect("Error: could not iterate through directory contents")
            {
                let dir = file.expect("Error: could not check file path");
                //println!("{:?}", dir.path());
                let file_path = dir.path();
                assert!(file_path.is_file()); //assert that file is a file
                let file_name: &str = file_path.file_name().unwrap().to_str().unwrap();

                //println!("{}", file_name);
                let file_bytes: Vec<u8> =
                multisteglib::read_byte_by_byte(file_path.to_str().unwrap()).unwrap();
                let valid_header = multisteglib::validate_header(&file_bytes);
                if valid_header == -1 {
                    eprintln!("Skipped invalid PPM at {:?}", dir.path());
                    continue;
                } else {
                    //for each valid PPM file
                    let valid_header = valid_header as usize;
                    let data_bytes: Vec<u8> = file_bytes[valid_header..].to_vec();
                    ret = multisteglib::decode_message(&data_bytes).unwrap();
                }
            }
            println!("{}", ret);
        }
        4 => {
            println!("Four arguments");
            //let mut _suffix: u32 = 0; //will be prepended to each output file and then increase
            let _threads: u32 = u32::from_str(&args[1].trim()).unwrap();
            //let mut thread_handles = vec![];
            let message = &args[2].trim();
            let message = fs::read_to_string(message).expect("Error could not read message file.");
            let encode_directory = &args[3].trim();
            let output_directory = &args[4].trim();

            let directory_check = std::path::Path::new(encode_directory)
                .metadata()
                .expect("Error: could not find path to specified directory");
            assert!(directory_check.is_dir()); //assert that argument is actually a directory
            let directory_check2 = std::path::Path::new(output_directory)
                .metadata()
                .expect("Error: could not find path to specified directory");
            assert!(directory_check2.is_dir());

            let valid = multisteglib::enumerate_ppm(encode_directory.to_string()); //TODO: finish
            let valid_num = valid.len();
            for i in 0..valid_num {
                println!("{}: {:#?}", i , valid.get(&i).unwrap());
            }
            /*let mut valid_num: u32 = 0;
            for file in std::fs::read_dir(encode_directory).expect("Error: could not iterate through directory contents") {
                let dir = file.expect("Error: could not check file path");
                //println!("{:?}", dir.path());
                let file_path = dir.path();
                assert!(file_path.is_file()); //assert that file is a file
                let file_type = dir.file_type().unwrap();
                println!("{:?}", file_type);
            }*/
            //time to finally encode stuff
            //let mut input_files: HaspMap<u32, &str> = HashMap::new();
            //let mut count: u32 = 0;
            //let ppm_header = Regex::new("P6\n\d \d\n\d").unwrap();

            //https://users.rust-lang.org/t/solved-how-to-split-string-into-multiple-sub-strings-with-given-length/10542
            let message_chunks: Vec<&str> = message
                .as_bytes()
                .chunks(valid_num)
                .map(str::from_utf8)
                .collect::<Result<Vec<&str>, _>>()
                .unwrap();
            //message_chunks.push()

            println!("{:?}", message_chunks);
            //let mut message_chunks_bytes: Vec<u8> = vec![message.as_bytes().chunks(valid_num) as u8];//.collect().unwrap();
            /*let _encoded = message.as_bytes();
            let mut encoded: Vec<u8> = vec![0u8; 0];
            for i in 0.._encoded.len() {
                encoded.push(_encoded[i]);
            }*/
            //println!("{}", encoded.len());
            //encoded.push(NULL_BYTE);

            let mut message_chunks_bytes = vec![];
            /*for chunk in message_chunks {
                message_chunks_bytes.push(chunk.as_butes());
                //message_chunks_bytes[]
            }*/
            for i in 0..message_chunks.len() {
                let mut chunk: Vec<u8> = message_chunks[i].as_bytes().to_vec();
                chunk.push(NULL_BYTE);
                message_chunks_bytes.push(chunk);
            }
            println!("{:?}", message_chunks_bytes);
            //:todo threading
            //https://blog.softwaremill.com/multithreading-in-rust-with-mpsc-multi-producer-single-consumer-channels-db0fc91ae3fa
            let mut handles = vec![];
            //let _suffix = Arc::new(AtomicUsize::new(0));
            let _suffix = Arc::new(Mutex::new(0));
            //let (sender, receiver) = mpsc::channel();
            let jobs_num = message_chunks.len() / _threads as usize;
            let job_remainder = message_chunks.len() % _threads as usize;
            for i in 0.._threads {
                //each thread needs to do a batch for encoding
                let counter = Arc::clone(&_suffix);
                let start = i as usize * jobs_num;
                let handle = thread::spawn(move || {
                    //let mut shared_data = counter.lock().unwrap();
                    for j in start..start + jobs_num {
                        let mut shared_data = counter.lock().unwrap();
                        //encode chunk
                        let index = *shared_data as usize % valid_num;
                        //let _valid = valid.clone();
                        let file_bytes: Vec<u8> =
                        multisteglib::read_byte_by_byte(valid.get(&index).unwrap()).unwrap();
                        let valid_header = multisteglib::validate_header(&file_bytes);
                        let valid_header = valid_header as usize;
                        let mut data_bytes: Vec<u8> = file_bytes[valid_header..].to_vec();

                        let mut i = 0;
                        let encoded: Vec<u8> = message_chunks_bytes[*shared_data].iter().cloned().collect();
                        loop {
                            if i == encoded.len() { break };
                            //println!("Iteration {}", i);
                            //println!("{:b}", encoded[i]);
                            for j in 0..8 {
                                //skip zero as there is no ascii in that range - nevermind lol
                                //let mask = 0b10000000 >> j;
                                /*let val = match encoded[i] & mask {
                                    0 => {
                                        0b00000000
                                    },
                                    _ => {
                                        0b00000001
                                    }
                                };*/
                                //println!("val={}", val);
                                let mut val = encoded[i] >> (7 - j);
                                val &= 1;
                                let index = (8 * i) + j;
                                let data = data_bytes[index] & !1; //remove least signifcant bit
                                data_bytes[index] = data | val;
                            }
                            i += 1;
                        }
                        let mut stdout = io::stdout();
                        //file_bytes.push(0xa); //add new line in order to pass diff check
                        //let file_b: Vec<u8> = file_bytes;
                        let _len: usize = file_bytes.len();
                        //file_bytes.push(0x0a); //newline character
                        stdout.write_all(&file_bytes[0.._len + 1]).expect("Error: could not write PPM to stdout");
                        println!("Thread #{} encoded chunk #{}", i, *shared_data);
                        *shared_data += 1;
                    }
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join().unwrap();
            }


            //TODO: parallelization of the image encoding - for each string chunk, encode into images in input directory in round robin fashion.
            let mut ret: String = String::new();
            //iterate through each picture in the directory
            let mut count = 0;
            /*for file in std::fs::read_dir(encode_directory)
                .expect("Error: could not iterate through directory contents")
            {
                let dir = file.expect("Error: could not check file path");
                //println!("{:?}", dir.path());
                let file_path = dir.path();
                assert!(file_path.is_file()); //assert that file is a file
                let file_name: &str = file_path.file_name().unwrap().to_str().unwrap();

                //println!("{}", file_name);
                let file_bytes: Vec<u8> =
                    multisteglib::read_byte_by_byte(file_path.to_str().unwrap()).unwrap();
                let valid_header = multisteglib::validate_header(&file_bytes);
                if valid_header == -1 {
                    eprintln!("Skipped invalid PPM at {:?}", dir.path());
                    continue;
                } else {
                    //for each valid PPM file
                    let valid_header = valid_header as usize;
                    let data_bytes: Vec<u8> = file_bytes[valid_header..].to_vec();

                    //ret = multisteglib::decode_message(&data_bytes).unwrap();
                    count += 1;
                    _suffix += 1;
                }
            }*/
            println!("{}", ret);
        }
        _ => {
            eprintln!("Usage: \nDecoding: cargo run <threads> <directory>\nEncoding: cargo run <threads> <message file> <input image directory> <output directory>");
        }
    }
}
