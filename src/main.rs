#![feature(slice_range)]
#![feature(ascii_char)]
#![feature(concat_bytes)]

mod ecb_cbc_detection;


use std::collections::HashMap;
use std::collections::HashSet;
use aes::cipher::KeyInit;
#[warn(unused_imports, unused_variables)]

use aes::cipher::{block_padding::Pkcs7, BlockCipherDecrypt, BlockCipherEncrypt, KeyIvInit};
use base64;
use base64::engine::general_purpose::STANDARD as engine;
use rand::Rng;
use std::error::Error;
use std::ops::Range;

fn detect_block_size(encrypt: impl Fn(&[u8], &[u8]) -> Vec<u8>, key: &[u8]) -> usize {
    let mut prev_len = encrypt(&[], key).len();
    for i in 1..=32 {
        let input = vec![b'A'; i];
        let curr_len = encrypt(&input, key).len();
        if curr_len > prev_len {
            return curr_len - prev_len;
        }
        prev_len = curr_len;
    }
    panic!("Block size not detected");
}

fn is_ecb(encrypt: impl Fn(&[u8], &[u8]) -> Vec<u8>, key: &[u8], block_size: usize) -> bool {
    let input = vec![b'A'; block_size * 2];
    let encrypted = encrypt(&input, key);
    encrypted[..block_size] == encrypted[block_size..2 * block_size]
}

fn crack_unknown_string(encrypt: impl Fn(&[u8], &[u8]) -> Vec<u8>, key: &[u8], block_size: usize) -> Vec<u8> {
    let target = encrypt(&[], key);
    println!("Target ciphertext: {:?}", target);
    if target.is_empty() {
        println!("Error: unknown-string is empty or encrypt function returned no data");
        return Vec::new();
    }

    let mut unknown_string = Vec::new();
    for pos in 0..target.len() {
        let input_len = block_size - 1 - (pos % block_size);
        let mut input = vec![b'A'; input_len];
        let target_block = &target[(pos / block_size) * block_size..(pos / block_size + 1) * block_size];
        println!("Position: {}, Input: {:?}", pos, input);

        let mut dict = HashMap::new();
        for i in 0..=255 {
            let mut test_input = input.clone();
            test_input.extend_from_slice(&unknown_string);
            test_input.push(i);
            if test_input.len() != block_size {
                println!("Error: test_input length is {}, expected {}", test_input.len(), block_size);
                continue;
            }
            let encrypted = encrypt(&test_input, key);
            println!("Test input: {:?}, Encrypted block: {:?}", test_input, &encrypted[..block_size]);
            dict.insert(encrypted[..block_size].to_vec(), i);
        }
        println!("Target block: {:?}", target_block);

        if let Some(&byte) = dict.get(target_block) {
            unknown_string.push(byte);
            println!("Found byte: {} ('{}')", byte, byte as char);
        } else {
            println!("No match found at position {}", pos);
            break;
        }
    }

   unknown_string
}
fn main() {
    let key = b"YELLOW SUBMARINE";
    let block_size = detect_block_size(ecb_encrypt, key);
    println!("Detected block size: {}", block_size);

    let is_ecb = is_ecb(ecb_encrypt, key, block_size);
    println!("Is ECB mode: {}", is_ecb);

    if is_ecb {
        let unknown_string = crack_unknown_string(ecb_encrypt, key, block_size);
        println!("Cracked string: {:?}", String::from_utf8_lossy(&unknown_string));
    }

}


#[cfg(test)]
/// ### Reference: [Crypto Challenge Set 1](https://cryptopals.com/sets/1)
///
/// * 這些測試用於驗證加密和解密功能，並確保它們能夠正確處理 Base64 編碼、十六進位字串轉換、XOR 操作等。
/// * 也可以用於學習基礎的加密技術和解密方法。
/// * 按照順序執行這些測試，並確保它們都能通過。
mod tests_crypto_challenge_set_1 {
    use super::*;
    use aes::cipher::BlockCipherDecrypt;
    use aes::cipher::KeyInit;
    use std::collections::HashSet;
    use std::fs;


    #[test]
    /// 將十六進位字串轉換為 Base64 編碼
    ///
    /// 每兩個十六進位字符代表一個字節，將其轉換為字節後，再使用 Base64 編碼。
    ///
    /// result:
    /// `Hex Decoded: I'm killing your brain like a poisonous mushroom`
    /// `Base64 Encoded: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t`
    ///
    fn hex_to_base64() {
        let hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let mut hex_decoded = Vec::new();
        for i in (0..hex_string.len()).step_by(2) {
            let byte = u8::from_str_radix(&hex_string[i..i + 2], 16).unwrap();
            // print!("{:?} ", byte.as_ascii());
            hex_decoded.push(byte);
        }
        println!(
            "Hex Decoded: {}",
            String::from_utf8(hex_decoded.clone()).unwrap()
        );
        // I'm killing your brain like a poisonous mushroom
        let base64_encoded = base64::Engine::encode(&engine, &hex_decoded);
        println!("Base64 Encoded: {}", base64_encoded);
        // SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

        // let bytes = hex_string.as_bytes();
        // let base64_encoded = base64::decode("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        // println!("{:?}\n{:?}", &base64_encoded.clone(),String::from_utf8(base64_encoded.unwrap()).unwrap());
        /*
        SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

        Ok([73, 39, 109, 32, 107, 105, 108, 108, 105, 110, 103, 32, 121, 111, 117, 114, 32, 98, 114, 97, 105, 110, 32, 108, 105, 107, 101, 32, 97, 32, 112, 111, 105, 115, 111, 110, 111, 117, 115, 32, 109, 117, 115, 104, 114, 111, 111, 109])

        "I'm killing your brain like a poisonous mushroom"
        */
    }


    #[test]
    /// XOR combination
    ///
    /// 將兩個十六進位字串轉換為字節，然後進行 XOR 操作，最後將結果轉換回十六進位字串。
    ///
    /// result:
    /// ```
    /// Input1: [28, 1, 17, 0, 31, 1, 1, 0, 6, 26, 2, 75, 83, 83, 80, 9, 24, 28]
    /// Input2: [104, 105, 116, 32, 116, 104, 101, 32, 98, 117, 108, 108, 39, 115, 32, 101, 121, 101]
    /// XOR Result: [116, 104, 101, 32, 107, 105, 100, 32, 100, 111, 110, 39, 116, 32, 112, 108, 97, 121]
    /// XOR Hex: 746865206b696420646f6e277420706c6179
    /// ```
    fn xor_combination() {
        let input1 = "1c0111001f010100061a024b53535009181c";
        let input2 = "686974207468652062756c6c277320657965";

        let input1_bytes: Vec<u8> = input1
            .as_bytes()
            .chunks(2)
            .map(|hex_pair| u8::from_str_radix(std::str::from_utf8(hex_pair).unwrap(), 16).unwrap())
            .collect::<Vec<u8>>();
        println!("Input1: {:?}", input1_bytes);

        let input2_bytes: Vec<u8> = input2
            .as_bytes()
            .chunks(2)
            .map(|hex_pair| u8::from_str_radix(std::str::from_utf8(hex_pair).unwrap(), 16).unwrap())
            .collect::<Vec<u8>>();
        println!("Input2: {:?}", input2_bytes);

        let xor_result: Vec<u8> = input1_bytes
            .iter()
            .zip(input2_bytes.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        println!("XOR Result: {:?}", xor_result);
        let xor_hex: String = xor_result
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect();
        println!("XOR Hex: {}", xor_hex);
    }


    #[test]
    /// 從 hex 字符串中找出單一 byte 0x00~0xFF 當做 key, 被用來加密整段信息
    ///
    /// hex -> bytes
    ///
    /// Try XORing each byte with every key from 0 to 255.
    /// find the key that produces the most common English words
    ///
    /// result:
    /// ```
    /// Hex Bytes: [27, 55, 55, 51, 49, 54, 63, 120, 21, 27, 127, 43, 120, 52, 49, 51, 61, 120, 57, 120, 40, 55, 45, 54, 60, 120, 55, 62, 120, 58, 57, 59, 55, 54]
    /// Best Key: 58
    /// Best Decrypted(length:34): [67, 111, 111, 107, 105, 110, 103, 32, 77, 67, 39, 115, 32, 108, 105, 107, 101, 32, 97, 32, 112, 111, 117, 110, 100, 32, 111, 102, 32, 98, 97, 99, 111, 110]
    /// Best Decrypted String: Cooking MC's like a pound of bacon
    /// ```
    fn single_byte_xor() {
        let hex_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let hex_bytes: Vec<u8> = hex_string
            .as_bytes()
            .chunks(2)
            .map(|hex_pair| u8::from_str_radix(std::str::from_utf8(hex_pair).unwrap(), 16).unwrap())
            .collect();
        println!("Hex Bytes: {:?}", hex_bytes);
        let mut best_score = 0;
        let mut best_key = 0;
        let mut best_decrypted = Vec::new();
        for key in 0..=255 {
            let decrypted: Vec<u8> = hex_bytes.iter().map(|&byte| byte ^ key).collect();
            let score = decrypted
                .iter()
                .filter(|&&c| c.is_ascii_alphabetic() || c.is_ascii_whitespace())
                .count();
            if score > best_score {
                best_score = score;
                best_key = key;
                best_decrypted = decrypted;
            }
        }

        println!("Best Key: {:02x}", best_key);
        println!(
            "Best Decrypted(length:{}): {:?}",
            best_decrypted.len(),
            best_decrypted
        );
        println!(
            "Best Decrypted String: {}",
            String::from_utf8(best_decrypted).unwrap()
        );
        /*
        Best Key: 58
        Best Decrypted(length:34): [67, 111, 111, 107, 105, 110, 103, 32, 77, 67, 39, 115, 32, 108, 105, 107, 101, 32, 97, 32, 112, 111, 117, 110, 100, 32, 111, 102, 32, 98, 97, 99, 111, 110]
        Best Decrypted String: Cooking MC's like a pound of bacon
        */
    }


    #[tokio::test]
    /// [test strings](https://cryptopals.com/static/challenge-data/4.txt)
    ///
    /// use [single_byte_xor](single_byte_xor) to find the best key
    ///
    /// result:
    /// ```
    /// Character length: 19944
    /// Lines: 327
    /// Best Key: 35
    /// Best Decrypted(length:30): [78, 111, 119, 32, 116, 104, 97, 116, 32, 116, 104, 101, 32, 112, 97, 114, 116, 121, 32, 105, 115, 32, 106, 117, 109, 112, 105, 110, 103, 10]
    /// Best Decrypted String: Now that the party is jumping
    /// ```
    async fn single_byte_xor_test() {
        // http req. from https://cryptopals.com/static/challenge-data/4.txt
        // let hex_string = reqwest::get("https://cryptopals.com/static/challenge-data/4.txt")
        //     .await
        //     .expect("Failed to fetch data")
        //     .text()
        //     .await
        //     .expect("Failed to read response text");
        let hex_string: String = fs::read_to_string("data/4.txt")
            .expect("Failed to read file");
        println!("Character length: {}", hex_string.len());
        println!("Lines: {}", hex_string.lines().count());
        // Character length: 19944
        // Lines: 327

        let mut best_score = 0;
        let mut best_key = 0;
        let mut best_decrypted = Vec::new();
        for line in hex_string.lines() {
            let hex_bytes: Vec<u8> = line
                .as_bytes()
                .chunks(2)
                .map(|hex_pair| {
                    u8::from_str_radix(std::str::from_utf8(hex_pair).unwrap(), 16).unwrap()
                })
                .collect();
            for key in 0..=255 {
                let decrypted: Vec<u8> = hex_bytes.iter().map(|&byte| byte ^ key).collect();
                let score = decrypted
                    .iter()
                    .filter(|&&c| c.is_ascii_alphabetic() || c.is_ascii_whitespace())
                    .count();
                if score > best_score {
                    best_score = score;
                    best_key = key;
                    best_decrypted = decrypted;
                }
            }
        }
        println!("Best Key: {:02x}", best_key);
        println!(
            "Best Decrypted(length:{})",
            best_decrypted.len()
        );
        println!(
            "Best Decrypted String: {}",
            String::from_utf8(best_decrypted).unwrap()
        );
    }


    #[test]
    /// 使用 key "ICE" 重複 XOR 加密
    ///
    /// 重複 XOR 加密的方式是將 key 重複使用，直到與明文長度相同。
    ///
    /// 第一個字節與 I XOR, 第二個字節與 C XOR, 第三個字節與 E XOR, 然後重複。
    ///
    /// 第四個字節與 I XOR, 以此類推。
    ///
    /// result:
    /// `Hex String: 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`
    fn repeat_key_xor_ice() {
        let key = "ICE";
        let plaintext =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key_bytes: Vec<u8> = key.as_bytes().to_vec();
        let plaintext_bytes: Vec<u8> = plaintext.as_bytes().to_vec();
        let bytes = plaintext_bytes
            .into_iter()
            .zip(key_bytes.iter().cycle())
            .map(|(p, k)| p ^ k)
            .collect::<Vec<u8>>();
        let hex_string: String = bytes.iter().map(|byte| format!("{:02x}", byte)).collect();
        println!("Hex String: {}", hex_string);
        // Hex String: 0b363b3f1c373
    }


    #[tokio::test]
    /// [test strings](https://cryptopals.com/static/challenge-data/6.txt)
    /// It's been base64'd after being encrypted with repeating-key XOR.
    ///
    /// The goal is to decrypt the message and find the key.
    ///
    /// 1. 實現 hamming_distance 函數[已驗證](handling_distance)
    ///
    /// 2. 將 base64 字符串解碼為字節數組
    ///
    /// 3. 嘗試 KEYSIZE = 2..=40, 找到最小的 normalize hamming_distance (Hamming distance/KEYSIZE)
    /// `KEYSIZE 越大, hamming_distance 越大, 實際上除以 KEYSIZE 才能明確相識度程度`
    ///
    /// 4. 用 KEYSIZE 轉置 blocks `(每 KEYSIZE 個字節為一個 block)`
    /// `轉置 (每個 block 的 index 取出來組成新的 blocks [block1[0], block2[0] ...])`
    ///
    /// 5. 對每個轉置的 block 使用 [single_byte_xor](single_byte_xor) 找出最佳 key
    ///
    /// 6. 將所有 key 組合起來，解密原始數據, 使用 [repeat_key_XOR](repeat_key_XOR) 方法
    ///
    /// result:
    /// ```
    /// Best Keysize: 1d
    /// Best Normalized Hamming Distance: 1.09
    /// Keys: [84, 101, 114, 109, 105, 110, 97, 116, 111, 114, 32, 88, 58, 32, 66, 114, 105, 110, 103, 32, 116, 104, 101, 32, 110, 111, 105, 115, 101]
    /// Recovered Key: "Terminator X: Bring the noise"
    /// Decoded (as string):
    /// "I'm back and I'm ringin' the bell..."
    /// ```
    async fn break_repeating_key_xor() {
        // 解碼 base64 字符串
        // let base64_string: String =
        //     reqwest::get("https://cryptopals.com/static/challenge-data/6.txt")
        //         .await
        //         .expect("Failed to fetch data")
        //         .text()
        //         .await
        //         .expect("Failed to read response text")
        //         .lines()
        //         .collect();
        let base64_string: String = fs::read_to_string("data/6.txt")
            .expect("Failed to read file")
            .lines()
            .collect();
        let bytes =
            base64::Engine::decode(&engine, base64_string).expect("Failed to decode base64");

        // 嘗試 KEYSIZE
        let keysize_range = 2..=40;
        let mut best_normaolized_distance = 0.0;
        let mut best_keysize = 0;
        let mut best_transposed_blocks: Vec<Vec<u8>> = Vec::new();
        for keysize in keysize_range {
            let mut avg_hamming_distance = 0.0;
            let bytes_blocks = bytes.chunks(keysize).collect::<Vec<&[u8]>>();

            for i in 0..bytes_blocks.len() {
                for j in i + 1..bytes_blocks.len() {
                    let a = &bytes_blocks[i];
                    let b = &bytes_blocks[j];
                    if a.len() == b.len() {
                        avg_hamming_distance += (super::hamming_distance(a, b)
                            .expect("Failed to calculate hamming distance")
                            / keysize as usize)
                            as f64;
                    }
                }
            }
            avg_hamming_distance /= (bytes_blocks.len() * (bytes_blocks.len() - 1)) as f64;
            if avg_hamming_distance < best_normaolized_distance || best_normaolized_distance == 0.0
            {
                best_normaolized_distance = avg_hamming_distance;
                best_keysize = keysize;

                best_transposed_blocks = super::transpose_blocks(&bytes, keysize);
            }
        }
        println!("Best Keysize: {:02x}", best_keysize);
        println!(
            "Best Normalized Hamming Distance: {:.2}",
            best_normaolized_distance
        );
        // println!("Transposed Blocks: {:?}", best_transposed_blocks);
        let mut keys: Vec<u8> = Vec::new();
        for block in best_transposed_blocks {
            let key = super::single_byte_xor(block)
                .await
                .expect("Failed to decrypt block");
            keys.push(key);
        }
        println!("Keys: {:?}", keys);
        println!("Recovered Key: {:?}", String::from_utf8_lossy(&keys));

        let decoded = super::repeat_key_xor(&bytes, &keys);

        println!(
            "Decoded (as string):\n{}",
            String::from_utf8_lossy(&decoded)
        );
    }


    #[test]
    /// this is a pre-test for test [break_repeating_key_xor()](break_repeating_key_xor)
    ///
    /// result: `37`
    fn hamming_distance() {
        let str1 = b"this is a test";
        let str2 = b"wokka wokka!!!";
        let distance = str1
            .iter()
            .zip(str2.iter())
            .map(|(a, b)| a ^ b)
            .map(|byte| byte.count_ones() as usize)
            .sum::<usize>();
        println!("Hamming Distance: {}", distance);
    }


    #[test]
    /// test transpose blocks
    /// ```
    /// Original Bytes: [116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116]
    /// Transposed Blocks: [[116, 32, 97, 115], [104, 105, 32, 116], [105, 115, 116], [115, 32, 101]]
    /// ```
    fn transpose_blocks() {
        let bytes = b"this is a test";
        let keysize = 4;
        let bytes_blocks = bytes.chunks(keysize).collect::<Vec<&[u8]>>();
        let bytes_blocks_transposed: Vec<Vec<u8>> = (0..keysize)
            .map(|i| {
                bytes_blocks
                    .iter()
                    .filter_map(|block| block.get(i))
                    .cloned()
                    .collect()
            })
            .collect();
        println!("Original Bytes: {:?}", bytes);
        println!("Transposed Blocks: {:?}", bytes_blocks_transposed);
    }


    #[tokio::test]
    /// this is for varifying the correctness of `break_repeating_key_xor()`
    async fn test_break_repeating_key_xor() {
        let bytes = base64::Engine::decode(
            &engine,
            "HUIfTQsPAh9PE048GmllH0kcDk4TAQsHThsBFkU2AB4BSWQgVB0dQzNTTmVS
BgBHVBwNRU0HBAxTEjwMHghJGgkRTxRMIRpHKwAFHUdZEQQJAGQmB1MANxYG
DBoXQR0BUlQwXwAgEwoFR08SSAhFTmU+Fgk4RQYFCBpGB08fWXh+amI2DB0P
QQ1IBlUaGwAdQnQEHgFJGgkRAlJ6f0kASDoAGhNJGk9FSA8dDVMEOgFSGQEL
QRMGAEwxX1NiFQYHCQdUCxdBFBZJeTM1CxsBBQ9GB08dTnhOSCdSBAcMRVhI
CEEATyBUCHQLHRlJAgAOFlwAUjBpZR9JAgJUAAELB04CEFMBJhAVTQIHAh9P
G054MGk2UgoBCVQGBwlTTgIQUwg7EAYFSQ8PEE87ADpfRyscSWQzT1QCEFMa
TwUWEXQMBk0PAg4DQ1JMPU4ALwtJDQhOFw0VVB1PDhxFXigLTRkBEgcKVVN4
Tk9iBgELR1MdDAAAFwoFHww6Ql5NLgFBIg4cSTRWQWI1Bk9HKn47CE8BGwFT
QjcEBx4MThUcDgYHKxpUKhdJGQZZVCFFVwcDBVMHMUV4LAcKQR0JUlk3TwAm
HQdJEwATARNFTg5JFwQ5C15NHQYEGk94dzBDADsdHE4UVBUaDE5JTwgHRTkA
Umc6AUETCgYAN1xGYlUKDxJTEUgsAA0ABwcXOwlSGQELQQcbE0c9GioWGgwc
AgcHSAtPTgsAABY9C1VNCAINGxgXRHgwaWUfSQcJABkRRU8ZAUkDDTUWF01j
OgkRTxVJKlZJJwFJHQYADUgRSAsWSR8KIgBSAAxOABoLUlQwW1RiGxpOCEtU
YiROCk8gUwY1C1IJCAACEU8QRSxORTBSHQYGTlQJC1lOBAAXRTpCUh0FDxhU
ZXhzLFtHJ1JbTkoNVDEAQU4bARZFOwsXTRAPRlQYE042WwAuGxoaAk5UHAoA
ZCYdVBZ0ChQLSQMYVAcXQTwaUy1SBQsTAAAAAAAMCggHRSQJExRJGgkGAAdH
MBoqER1JJ0dDFQZFRhsBAlMMIEUHHUkPDxBPH0EzXwArBkkdCFUaDEVHAQAN
U29lSEBAWk44G09fDXhxTi0RAk4ITlQbCk0LTx4cCjBFeCsGHEETAB1EeFZV
IRlFTi4AGAEORU4CEFMXPBwfCBpOAAAdHUMxVVUxUmM9ElARGgZBAg4PAQQz
DB4EGhoIFwoKUDFbTCsWBg0OTwEbRSonSARTBDpFFwsPCwIATxNOPBpUKhMd
Th5PAUgGQQBPCxYRdG87TQoPD1QbE0s9GkFiFAUXR0cdGgkADwENUwg1DhdN
AQsTVBgXVHYaKkg7TgNHTB0DAAA9DgQACjpFX0BJPQAZHB1OeE5PYjYMAg5M
FQBFKjoHDAEAcxZSAwZOBREBC0k2HQxiKwYbR0MVBkVUHBZJBwp0DRMDDk5r
NhoGACFVVWUeBU4MRREYRVQcFgAdQnQRHU0OCxVUAgsAK05ZLhdJZChWERpF
QQALSRwTMRdeTRkcABcbG0M9Gk0jGQwdR1ARGgNFDRtJeSchEVIDBhpBHQlS
WTdPBzAXSQ9HTBsJA0UcQUl5bw0KB0oFAkETCgYANlVXKhcbC0sAGgdFUAIO
ChZJdAsdTR0HDBFDUk43GkcrAAUdRyonBwpOTkJEUyo8RR8USSkOEENSSDdX
RSAdDRdLAA0HEAAeHQYRBDYJC00MDxVUZSFQOV1IJwYdB0dXHRwNAA9PGgMK
OwtTTSoBDBFPHU54W04mUhoPHgAdHEQAZGU/OjV6RSQMBwcNGA5SaTtfADsX
GUJHWREYSQAnSARTBjsIGwNOTgkVHRYANFNLJ1IIThVIHQYKAGQmBwcKLAwR
DB0HDxNPAU94Q083UhoaBkcTDRcAAgYCFkU1RQUEBwFBfjwdAChPTikBSR0T
TwRIEVIXBgcURTULFk0OBxMYTwFUN0oAIQAQBwkHVGIzQQAGBR8EdCwRCEkH
ElQcF0w0U05lUggAAwANBxAAHgoGAwkxRRMfDE4DARYbTn8aKmUxCBsURVQf
DVlOGwEWRTIXFwwCHUEVHRcAMlVDKRsHSUdMHQMAAC0dCAkcdCIeGAxOazkA
BEk2HQAjHA1OAFIbBxNJAEhJBxctDBwKSRoOVBwbTj8aQS4dBwlHKjUECQAa
BxscEDMNUhkBC0ETBxdULFUAJQAGARFJGk9FVAYGGlMNMRcXTRoBDxNPeG43
TQA7HRxJFUVUCQhBFAoNUwctRQYFDE43PT9SUDdJUydcSWRtcwANFVAHAU5T
FjtFGgwbCkEYBhlFeFsABRcbAwZOVCYEWgdPYyARNRcGAQwKQRYWUlQwXwAg
ExoLFAAcARFUBwFOUwImCgcDDU5rIAcXUj0dU2IcBk4TUh0YFUkASEkcC3QI
GwMMQkE9SB8AMk9TNlIOCxNUHQZCAAoAHh1FXjYCDBsFABkOBkk7FgALVQRO
D0EaDwxOSU8dGgI8EVIBAAUEVA5SRjlUQTYbCk5teRsdRVQcDhkDADBFHwhJ
AQ8XClJBNl4AC1IdBghVEwARABoHCAdFXjwdGEkDCBMHBgAwW1YnUgAaRyon
B0VTGgoZUwE7EhxNCAAFVAMXTjwaTSdSEAESUlQNBFJOZU5LXHQMHE0EF0EA
Bh9FeRp5LQdFTkAZREgMU04CEFMcMQQAQ0lkay0ABwcqXwA1FwgFAk4dBkIA
CA4aB0l0PD1MSQ8PEE87ADtbTmIGDAILAB0cRSo3ABwBRTYKFhROHUETCgZU
MVQHYhoGGksABwdJAB0ASTpFNwQcTRoDBBgDUkksGioRHUkKCE5THEVCC08E
EgF0BBwJSQoOGkgGADpfADETDU5tBzcJEFMLTx0bAHQJCx8ADRJUDRdMN1RH
YgYGTi5jMURFeQEaSRAEOkURDAUCQRkKUmQ5XgBIKwYbQFIRSBVJGgwBGgtz
RRNNDwcVWE8BT3hJVCcCSQwGQx9IBE4KTwwdASEXF01jIgQATwZIPRpXKwYK
BkdEGwsRTxxDSToGMUlSCQZOFRwKUkQ5VEMnUh0BR0MBGgAAZDwGUwY7CBdN
HB5BFwMdUz0aQSwWSQoITlMcRUILTxoCEDUXF01jNw4BTwVBNlRBYhAIGhNM
EUgIRU5CRFMkOhwGBAQLTVQOHFkvUkUwF0lkbXkbHUVUBgAcFA0gRQYFCBpB
PU8FQSsaVycTAkJHYhsRSQAXABxUFzFFFggICkEDHR1OPxoqER1JDQhNEUgK
TkJPDAUAJhwQAg0XQRUBFgArU04lUh0GDlNUGwpOCU9jeTY1HFJARE4xGA4L
ACxSQTZSDxsJSw1ICFUdBgpTNjUcXk0OAUEDBxtUPRpCLQtFTgBPVB8NSRoK
SREKLUUVAklkERgOCwAsUkE2Ug8bCUsNSAhVHQYKUyI7RQUFABoEVA0dWXQa
Ry1SHgYOVBFIB08XQ0kUCnRvPgwQTgUbGBwAOVREYhAGAQBJEUgETgpPGR8E
LUUGBQgaQRIaHEshGk03AQANR1QdBAkAFwAcUwE9AFxNY2QxGA4LACxSQTZS
DxsJSw1ICFUdBgpTJjsIF00GAE1ULB1NPRpPLF5JAgJUVAUAAAYKCAFFXjUe
DBBOFRwOBgA+T04pC0kDElMdC0VXBgYdFkU2CgtNEAEUVBwTWXhTVG5SGg8e
AB0cRSo+AwgKRSANExlJCBQaBAsANU9TKxFJL0dMHRwRTAtPBRwQMAAATQcB
FlRlIkw5QwA2GggaR0YBBg5ZTgIcAAw3SVIaAQcVEU8QTyEaYy0fDE4ITlhI
Jk8DCkkcC3hFMQIEC0EbAVIqCFZBO1IdBgZUVA4QTgUWSR4QJwwRTWM="
                .lines()
                .collect::<String>(),
        )
            .expect("Failed to decode base64");
        let keysize_range = 2..40;
        let result = super::break_repeating_key_xor(&bytes, keysize_range);
        if let Ok(decoded) = result.await {
            println!("Decoded: {}", String::from_utf8_lossy(&decoded));
        } else {
            println!("Failed to break repeating key XOR");
        }
    }


    #[test]
    /// ### [resources](https://cryptopals.com/static/challenge-data/7.txt)
    /// AES in ECB mode description
    ///
    fn aes_ecb() {
        let result: String = fs::read_to_string("data/7.txt")
            .expect("Failed to read file")
            .lines()
            .collect();
        let key = b"YELLOW SUBMARINE";
        let mut base64_string =
            base64::Engine::decode(&engine, result).expect("Failed to decode base64");
        // println!("Base64 Decoded: {:?}", base64_string);
        let cipher = aes::Aes128Dec::new_from_slice(key).expect("Failed to decode base64");

        let decrypted = cipher
            .decrypt_padded::<Pkcs7>(&mut base64_string)
            .expect("Failed to decrypt");
        // println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
    }


    #[test]
    /// AES ECB 解密
    /// plaintext: `I'm back and I'm ringin' the bellaabbccddeeff`
    fn aes_ecb_decrypt() {
        let key = b"YELLOW SUBMARINE";
        let ciphertext = [9, 18, 48, 170, 222, 62, 179, 48, 219, 170, 67, 88, 248, 141, 42, 108, 55, 183, 45, 12, 244, 194, 44, 52, 74, 236, 65, 66, 208, 12, 229, 48, 252, 32, 60, 43, 28, 19, 32, 87, 185, 126, 229, 216, 10, 213, 112, 187].to_vec();
        println!("Decrypted Bytes: {:?}", ciphertext);
        let cipher = aes::Aes128Dec::new_from_slice(key).expect("Failed to create cipher");

        let mut buffer = vec![0u8; ciphertext.len() + 16 - (ciphertext.len() % 16)];
        let decrypted = cipher.decrypt_padded_b2b::<Pkcs7>(&ciphertext, &mut buffer).unwrap();
        println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
    }


    #[test]
    /// aec_ecb encryption
    ///
    /// result:`091230aade3eb330dbaa4358f88d2a6c37b72d0cf4c22c344aec4142d00ce530fc203c2b1c132057b97ee5d80ad570bb`
    /// `[9, 18, 48, 170, 222, 62, 179, 48, 219, 170, 67, 88, 248, 141, 42, 108, 55, 183, 45, 12, 244, 194, 44, 52, 74, 236, 65, 66, 208, 12, 229, 48, 252, 32, 60, 43, 28, 19, 32, 87, 185, 126, 229, 216, 10, 213, 112, 187]`
    fn aes_ecb_encrypt() {
        let key = b"YELLOW SUBMARINE";
        let plaintext = b"I'm back and I'm ringin' the bellaabbccddeeff".to_vec();
        let cipher = aes::Aes128Enc::new_from_slice(key).expect("Failed to create cipher");
        let mut buffer = vec![0u8; plaintext.len() + 16 - (plaintext.len() % 16)];

        let encrypted = cipher.encrypt_padded_b2b::<Pkcs7>(&plaintext, &mut buffer).unwrap();
        println!("Encrypted: {:?}", encrypted);
        let hex_string: String = encrypted.iter().map(|byte| format!("{:02x}", byte)).collect();
        println!("Ciphertext Hex: {}", hex_string);
    }


    #[test]
    /// the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
    fn test_aes_ecb_mode() {
        let hex_string = fs::read_to_string("data/8.txt").expect("Failed to read file");
        if ecb_cbc_detection(&hex_string.as_bytes()){
            println!("ECB mode detected in the given hex string.");
        } else {
            println!("No ECB mode detected in the given hex string.");
        };
        // let blocks: Vec<&[u8]> = hex_string.as_bytes().chunks(16).collect();
        // let mut unique_blocks: HashSet<&[u8]> = HashSet::new();
        // for block in &blocks {
        //     if !unique_blocks.insert(block) {
        //         println!("Repeated block found: {:?}", block);
        //     }
        // }
        // if unique_blocks.len() < blocks.len() {
        //     println!("Likely ECB mode: detected repeated ciphertext blocks");
        // }

    }
    #[test]
    /// this test might fail because the strings are not long enough to detect ECB mode
    fn test_ecb_cbc_detection() {
        fn generate_random_key()->[u8;16]
        {
            let mut rng = rand::rng();
            let mut key = [0u8; 16];
            rng.fill(&mut key);
            key
        }
        fn generate_random_string()-> String {
            let mut rng = rand::rng();
            let length = rng.random_range(5..10);
            let chars: Vec<char> = (0..length).map(|_| rng.random_range('a'..='z')).collect();
            chars.into_iter().collect()
        }
        let repeat_times = 100;
        let mut result = 0;
        let mut rng = rand::rng();

        for i in 0..repeat_times {
            let key = generate_random_key();
            let appended_prefix = generate_random_string();
            let appended_suffix = generate_random_string();

            let mut plainttext = Vec::new();
            let input = b"Hello, World!";
            plainttext.extend_from_slice(appended_prefix.as_bytes());
            plainttext.extend_from_slice(input);
            plainttext.extend_from_slice(appended_suffix.as_bytes());
            let padded = super::pkcs7_pad(plainttext.as_slice(), 16);
            let mut encrypted = Vec::new();
            let mode_choice: bool = rng.random_bool(0.5);
            if  mode_choice {
                // ECB mode
                encrypted = super::ecb_encrypt(padded.as_slice(), &key);
            }else{
                // CBC mode
                let iv = generate_random_key();
                encrypted = super::cbc_encrypt(padded.as_slice(), &key, &iv);
            }

            // true if ECB mode is detected
            if  mode_choice && super::ecb_cbc_detection(&encrypted)
            || !mode_choice && !super::ecb_cbc_detection(&encrypted) {
                result += 1;
            }

        }

        // percentage of ECB mode detection
        let percentage = (result as f64 / repeat_times as f64) * 100.0;
        println!("ECB mode detected in {}% of the cases", percentage);
        assert!(percentage > 80.0, "ECB mode detection failed");
    }
}


/// 計算兩個字節切片之間的 Hamming 距離, 越小越好.
/// 對比兩個字節切片，計算它們之間不同位元的數量。`(101^110).count_ones() = 2`
/// Hamming 距離是指兩個字節切片之間不同位元的數量。
/// # Arguments
/// * `str1` - 第一個字節切片
/// * `str2` - 第二個字節切片
/// # Returns
/// * `Result<usize, &'static str>` - 返回 Hamming 距離，如果輸入切片為空或長度不一致則返回錯誤
fn hamming_distance(str1: &[u8], str2: &[u8]) -> Result<usize, &'static str> {
    if str1.is_empty() || str2.is_empty() {
        return Err("Input slices cannot be empty");
    }
    if str1.len() != str2.len() {
        return Err("Input slices must have the same length");
    }
    Ok(str1
        .iter()
        .zip(str2.iter())
        .map(|(a, b)| a ^ b)
        .map(|byte| byte.count_ones() as usize)
        .sum())
}


#[allow(dead_code)]
async fn single_byte_xor_string(str: String) -> Result<u8, Box<dyn Error>> {
    if str.is_empty() || str.len() < 2 {
        return Err("Input string must be at least 2 characters long".into());
    }
    let mut best_score = 0;
    let mut best_key = 0;
    let mut best_decrypted: Vec<u8> = Vec::new();
    for key in 0..=255 {
        let decrypted: Vec<u8> = str.as_bytes().iter().map(|&byte| byte ^ key).collect();
        let score = decrypted
            .iter()
            .filter(|&&c| c.is_ascii_alphabetic() || c.is_ascii_whitespace())
            .count();
        if score > best_score {
            best_score = score;
            best_key = key;
            best_decrypted = decrypted;
        }
    }
    println!("Best Key: {best_key:02x}\nBest Decrypted: {best_decrypted:?}");

    Ok(best_key) // Placeholder for the actual implementation
}


#[allow(dead_code)]
async fn single_byte_xor_u8(str: Vec<u8>) -> Result<u8, Box<dyn Error>> {
    if str.is_empty() || str.len() < 2 {
        return Err("Input string must be at least 2 characters long".into());
    }
    let mut best_score = 0;
    let mut best_key = 0;
    let mut best_decrypted: Vec<u8> = Vec::new();
    for key in 0..=255 {
        let decrypted: Vec<u8> = str.iter().map(|&byte| byte ^ key).collect();
        let score = decrypted
            .iter()
            .filter(|&&c| c.is_ascii_alphabetic() || c.is_ascii_whitespace())
            .count();
        if score > best_score {
            best_score = score;
            best_key = key;
            best_decrypted = decrypted;
        }
    }

    println!("Best Key: {best_key:02x}\nBest Decrypted: {best_decrypted:?}");
    Ok(best_key) // Placeholder for the actual implementation
}


/// 對輸入的字節數組進行單字節 XOR 解密，返回最佳的 key
///
/// 該函數會嘗試所有可能的 key (0x00 到 0xFF)，並計算每個解密結果的得分，
/// 得分是根據解密後的字節中 ASCII 字母和空格的數量來計算的。
///
/// 得分越高的解密結果越可能是正確的。
/// # Arguments
/// * `input` - 要解密的字節數組
/// # Returns
/// * `Result<u8, Box<dyn Error>>` - 返回最佳的 key
/// * 如果輸入的字節數組長度小於 2，則返回錯誤
/// * 如果輸入的字節數組為空，則返回錯誤
///
async fn single_byte_xor<T: AsRef<[u8]>>(input: T) -> Result<u8, Box<dyn Error>> {
    let bytes = input.as_ref();
    if bytes.is_empty() || bytes.len() < 2 {
        return Err("Input must be at least 2 bytes long".into());
    }
    let mut best_score = 0;
    let mut best_key = 0;
    for key in 0..=255 {
        let decrypted: Vec<u8> = bytes.iter().map(|&byte| byte ^ key).collect();
        let score = decrypted
            .iter()
            .filter(|&&c| c.is_ascii_alphabetic() || c.is_ascii_whitespace())
            .count();
        if score > best_score {
            best_score = score;
            best_key = key;
        }
    }
    Ok(best_key)
}


/// 將明文與重複的密鑰進行 XOR 操作，返回加密後的字節數組
///
/// 該函數會將明文的每個字節與密鑰的對應字節進行 XOR 操作，密鑰會循環使用。
/// # Arguments
/// * `plaintext` - 要加密的明文字節數組
/// * `key` - 用於加密的密鑰字節數組
///
/// # Returns
/// * `Vec<u8>` - 返回加密後的字節數組
fn repeat_key_xor(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    plaintext
        .iter()
        .zip(key.iter().cycle())
        .map(|(p, k)| p ^ k)
        .collect()
}


/// 將字節數組轉置為 KEYSIZE 個 block
///
/// 每個 block 包含 KEYSIZE 個字節，並且將每個 block 的 index 取出來組成新的 blocks
///
/// 例如，對於字節數組 [a, b, c, d, e, f] 和 KEYSIZE = 3，轉置後的結果為 [[a, d], [b, e], [c, f]]
fn transpose_blocks(bytes: &[u8], keysize: usize) -> Vec<Vec<u8>> {
    let bytes_blocks = bytes.chunks(keysize).collect::<Vec<&[u8]>>();
    (0..keysize)
        .map(|i| {
            bytes_blocks
                .iter()
                .filter_map(|block| block.get(i))
                .cloned()
                .collect()
        })
        .collect()
}


/// 嘗試使用重複的密鑰 XOR 解密字節數組，並返回解密後的字節數組
///
/// 這個函數會嘗試不同的 KEYSIZE，計算每個 KEYSIZE 的平均 Hamming 距離，並選擇最佳的 KEYSIZE。
///
/// 然後對每個轉置的 block 使用 [single_byte_xor](single_byte_xor) 找出最佳 key，最後將所有 key 組合起來，解密原始數據。
///
/// # Arguments
/// * `bytes` - 要解密的字節數組
/// * `keysize` - KEYSIZE 的範圍，通常是 2 到 40
/// # Returns
/// * `Result<Vec<u8>, Box<dyn Error>>` - 返回解密後的字節數組
/// * 如果計算 Hamming 距離失敗，則返回錯誤
/// * 如果 KEYSIZE 範圍無效，則返回錯誤
async fn break_repeating_key_xor(
    bytes: &[u8],
    keysize_range: Range<usize>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut keys: Vec<u8> = Vec::new();
    let mut best_normaolized_distance = f64::MAX;
    let mut best_keysize = 0;
    let mut best_transposed_blocks: Vec<Vec<u8>> = Vec::new();
    for keysize in keysize_range {
        let mut avg_hamming_distance = 0.0;
        let bytes_blocks = bytes.chunks(keysize).collect::<Vec<&[u8]>>();

        for i in 0..bytes_blocks.len() {
            for j in i + 1..bytes_blocks.len() {
                let a = &bytes_blocks[i];
                let b = &bytes_blocks[j];
                if a.len() == b.len() {
                    avg_hamming_distance += (hamming_distance(a, b)? / keysize as usize) as f64;
                }
            }
        }
        avg_hamming_distance /= (bytes_blocks.len() * (bytes_blocks.len() - 1)) as f64;
        if avg_hamming_distance < best_normaolized_distance {
            best_normaolized_distance = avg_hamming_distance;
            best_keysize = keysize;

            best_transposed_blocks = transpose_blocks(bytes, keysize);
        }
    }
    println!("Best Keysize: {:02x}", best_keysize);
    println!(
        "Best Normalized Hamming Distance: {:.2}",
        best_normaolized_distance
    );
    // println!("Transposed Blocks: {:?}", best_transposed_blocks);
    for block in best_transposed_blocks {
        let key = single_byte_xor(&block).await?;
        keys.push(key);
    }
    let decoded = repeat_key_xor(bytes, &keys);
    // println!("Keys: {keys:?}");
    // println!("Recovered Key: {:?}", String::from_utf8_lossy(&keys));
    // println!(
    //     "Decoded (as string):\n{}",
    //     String::from_utf8_lossy(&decoded)
    // );
    // 返回解密後的字節數組
    Ok(decoded)
}


#[cfg(test)]
/// [source](https://cryptopals.com/sets/2)
mod tests_crypto_challenge_2 {
    use crate::pkcs7_unpad;
    use aes::cipher::KeyInit;
    use std::fs;


    #[test]
    /// result: `Padded Data: [89, 69, 76, 76, 79, 87, 32, 83, 85, 66, 77, 65, 82, 73, 78, 69, 4, 4, 4, 4]`
    fn test_pkcs7_padding() {
        let data = b"YELLOW SUBMARINE";
        let fn_pad = |data: &[u8], size: usize| -> Vec<u8> {
            let padding_size = size - (data.len() % size);
            let mut padded_data = Vec::with_capacity(data.len() + padding_size);
            padded_data.extend_from_slice(data);
            padded_data.extend(vec![padding_size as u8; padding_size]);
            padded_data
        };
        let padded = fn_pad(data, 20);
        println!("Padded Data: {:?}", padded);
    }


    #[test]
    /// 1. 確定區塊大小（Block Size）：
    /// - 輸入越來越長的相同字符（例如 "A"、"AA"、"AAA" 等），觀察加密後的密文長度變化。
    /// - 當密文長度突然增加 16 字節時，說明區塊大小是 16 字節（AES-128 的標準區塊大小）。
    /// 2. 確認 ECB 模式：
    /// - 輸入 32 個相同字符（例如 32 個 "A"），檢查密文的前兩個 16 字節區塊是否相同。
    /// - 如果相同，證明是 ECB 模式，因為 ECB 對相同的明文區塊總是產生相同的密文區塊。
    /// 3. 構造一個少一字節的輸入：
    /// - 假設區塊大小是 16 字節，輸入 15 個 "A"，這樣加密的第一個 16 字節區塊會是 AAAAAAAAAAAAAAA || X，其中 X 是 unknown-string 的第一個字節。
    /// 4. 建立字典：
    /// - 構造 256 個輸入，形式為 AAAAAAAAAAAAAAA || b，其中 b 是從 0x00 到 0xFF 的每個可能字節。
    /// - 將這些輸入送入 oracle，記錄每個輸入對應的第一個 16 字節密文區塊，形成一個字典 {密文: b}。
    /// 5. 匹配第一個字節：
    /// - 將第 3 步的密文與字典比較，找到匹配的密文，從而得知 X 是哪個字節。
    /// 6. 重複破解下一個字節：
    /// - 知道第一個字節 X 後，輸入 14 個 "A" 加上 X（即 AAAAAAAAAAAAAAX），讓第一個區塊變成 AAAAAAAAAAAAAAX || Y，其中 Y 是第二個字節。
    /// - 重複第 4、5 步，構造新字典，找出 Y，依此類推，直到解出整個 unknown-string。
    fn test_ecb_encrypt_decrypt_block() {
        let key = b"YELLOW SUBMARINE";
        let plaintext = b"this is a test message 112233 aabbcc !@#$%^&*()_+";
        let padded_plaintext = super::pkcs7_pad(plaintext, 16);
        println!("Padded Plaintext: {:?}", padded_plaintext);
        let encrypted = super::ecb_encrypt(&padded_plaintext, key);
        println!("Encrypted: {:?}", encrypted);
        let decrypted = super::ecb_decrypt(&encrypted, key);
        let unpadded_decrypted = super::pkcs7_unpad(&decrypted);
        println!("Decrypted: {:?}", String::from_utf8_lossy(&unpadded_decrypted));
        assert_eq!(unpadded_decrypted, plaintext);

        println!("is ECB mode: {}", super::ecb_cbc_detection(&encrypted));

        // 測試加密的長度 32 個相同字節
        // 會出現重複的密文塊
        // [228, 64, 133, 250, 43, 218, 51, 216, 106, 163, 64, 180, 193, 108, 5, 173,
        // 228, 64, 133, 250, 43, 218, 51, 216, 106, 163, 64, 180, 193, 108, 5, 173, 96, 250, 54, 112, 126, 69, 244, 153, 219, 160, 242, 91, 146, 35, 1, 165]
        let test_plaintext = super::pkcs7_pad(b"AAAAAAAAAAAAAAA", 16);

        let encrypted_test = super::ecb_encrypt(&test_plaintext, key);
        let encrypted_len = encrypted_test.len();
        println!("Encrypted Test len {:?}: {:?}", encrypted_len,encrypted_test);
    }


    #[test]
    fn cbc_encrypt() {
        let data = b"This is a test message for CBC mode";
        let key = b"YELLOW SUBMARINE";
        const BLOCK_SIZE: usize = 16; // AES block size
        let iv = [0u8; BLOCK_SIZE]; // 128-bit IV
        let padded_data = super::pkcs7_pad(data, BLOCK_SIZE);

        let mut prev = iv.to_vec();
        let mut buffer_blocks: Vec<u8> = Vec::with_capacity(padded_data.len());

        for block in padded_data.chunks(BLOCK_SIZE) {
            let xored: Vec<u8> = block.iter()
                                      .zip(prev.iter())
                                      .map(|(b, p)| b ^ p)
                                      .collect();
            let encrypted = super::cbc_encrypt_block(&xored, key);
            prev = encrypted.clone();
            buffer_blocks.extend_from_slice(&encrypted);
            // println!("Encrypted Block: {:?}", encrypted);
        }
        // println!("CBC Encrypted Data: {:?}", buffer_blocks);
    }


    #[test]
    /// plaintext: `This is a test message for CBC mode`
    fn cbc_decrypt() {
        let encrypted_data: Vec<u8> = vec![89, 245, 143, 60, 140, 62, 115, 150, 176, 229, 133, 179, 184, 50, 45, 56, 254, 115, 179, 182, 199, 227, 156, 161, 162, 214, 247, 195, 43, 124, 255, 48, 245, 233, 151, 42, 12, 62, 18, 178, 249, 157, 219, 121, 171, 137, 239, 194];
        let key = b"YELLOW SUBMARINE";
        const BLOCK_SIZE: usize = 16;
        let iv = [0u8; BLOCK_SIZE];
        let mut prev = iv.to_vec();
        let mut plaintext = Vec::with_capacity(encrypted_data.len());

        for block in encrypted_data.chunks(BLOCK_SIZE) {
            let decrypted = super::cbc_decrypt_block(block, key);
            let xored: Vec<u8> = decrypted.iter()
                                          .zip(&prev)
                                          .map(|(b, p)| b ^ p)
                                          .collect();
            println!("Decrypted Block (as string): {}", String::from_utf8_lossy(&xored));

            prev = block.to_vec(); // 這裡要設為密文，而不是明文
            plaintext.extend_from_slice(&xored);
        }
        println!("Decrypted Block: {:?}", plaintext);
        println!("CBC Decrypted Data: {:?}", String::from_utf8_lossy(&pkcs7_unpad(&plaintext)));
    }

    #[test]
    /// result: `This is a test message for CBC mode`
    fn test_cbc_decrypt(){
        let data =  vec![89, 245, 143, 60, 140, 62, 115, 150, 176, 229, 133, 179, 184, 50, 45, 56, 254, 115, 179, 182, 199, 227, 156, 161, 162, 214, 247, 195, 43, 124, 255, 48, 245, 233, 151, 42, 12, 62, 18, 178, 249, 157, 219, 121, 171, 137, 239, 194];
        let decrypted = super::cbc_decrypt(&data, b"YELLOW SUBMARINE", &[0u8; 16]);
        println!("Decrypted Data: {:?}", String::from_utf8_lossy(&pkcs7_unpad(&decrypted)));
    }
    #[test]
    /// [89, 245, 143, 60, 140, 62, 115, 150, 176, 229, 133, 179,
    /// 184, 50, 45, 56, 254, 115, 179, 182, 199, 227, 156, 161,
    /// 162, 214, 247, 195, 43, 124, 255, 48, 245, 233, 151, 42,
    /// 12, 62, 18, 178, 249, 157, 219, 121, 171, 137, 239, 194]
    fn test_cbc_encrypt() {
        let data = b"This is a test message for CBC mode";
        let padded_data = super::pkcs7_pad(data, BLOCK_SIZE);
        let key = b"YELLOW SUBMARINE";
        const BLOCK_SIZE: usize = 16; // AES block size
        let iv = [0u8; BLOCK_SIZE]; // 128-bit IV

        let encrypted= super::cbc_encrypt(&padded_data, key, &iv);
            // println!("CBC Encrypted Data: {:?}", encrypted);
    }


    #[test]
    /// [download](https://cryptopals.com/static/challenge-data/10.txt)
    /// verify this by decryping whether the result is same as the encrypted data
    /// - use ECB function to encrypt
    /// - use XOR function to combine them
    /// retult:`I'm back and I'm ...`
    fn test_cbc_mode() {
        let data = fs::read_to_string("data/10.txt")
            .expect("Failed to read file").lines().collect::<String>();
        let data = base64::decode(
            data
        )
            .expect("Failed to decode base64");
        const BLOCK_SIZE: usize = 16; // AES block size
        let iv = [0u8; BLOCK_SIZE]; // 128bit = 16 bytes
        let key = b"YELLOW SUBMARINE";

        let decrypted = super::cbc_decrypt(&data, key, &iv);
        println!("CBC Encrypted Data: {}", String::from_utf8_lossy(&pkcs7_unpad(&decrypted)));
    }

    #[test]
    /// `Challenge 12
    /// Byte-at-a-time ECB decryption (Simple)
    fn test_oracle_ecb_decrypt() {
        let key = b"YELLOW SUBMARINE";
        let mut encrypted = Vec::new();
        let plaintext_prefix = base64::Engine::decode(&super::engine, "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").expect("REASON");

        let plaintext =  [plaintext_prefix.as_slice(),b" this is a test message 112233 aabbcc !@#$%^&*()_+"].concat();
        let padded_plaintext = super::pkcs7_pad(&plaintext, 16);
        encrypted.extend(super::ecb_encrypt(&padded_plaintext, key));
        println!("Encrypted: {:?}", encrypted);

        let decrypted = super::ecb_decrypt(&encrypted, key);
        println!("Decrypted: {:?} , {}", decrypted, String::from_utf8(decrypted.clone()).unwrap());
        assert_eq!(decrypted, padded_plaintext);


        // 測試逆向
        let bytes= b"AAAAAAAAAAAAAAA";
        let mut result = [0u8;16];
        result[..15].copy_from_slice(bytes);
        let compare = super::ecb_encrypt(&result, key);
        let mut a:Vec<Vec<u8>> = Vec::new();
        let mut b: Vec<u8>  = Vec::new();
        for i in 0..=255 {
            result[15] = i;
            println!("Testing byte: {:?}", &result);
            let encrypted = super::ecb_encrypt(&result, key);
            println!("Encrypted: {:?}", &encrypted);
            a.push(encrypted[..16].to_vec());
            // if encrypted == encrypted[..16] {
            //     println!("Found byte: {}", i);
            //     break;
            // }
        }
        println!("Encrypted Bytes: {:?}", a);
        println!("Compare: {:?}", compare);
        for (i,v) in a.iter().enumerate() {
            if v == &compare[..16] {
                println!(" found byte: {}", i);
                break;
            }
        }
    }
}


/// BLOCK_SIZE=16
fn ecb_encrypt_block(block: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(block.len(), 16, "Block must be exactly 16 bytes for AES");

    let cipher = aes::Aes128Enc::new_from_slice(key).expect("Failed to create cipher");
    let mut block_copy = block.to_vec();

    // Encrypt the 16-byte block directly
    for chunk in block_copy.chunks_mut(16) {
        let mut block_array = [0u8; 16];
        block_array.copy_from_slice(chunk);
        cipher.encrypt_block((&mut block_array).into());
        chunk.copy_from_slice(&block_array);
    }

    block_copy
}
fn ecb_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let unknown_string = b"longer secret message";
    let data = pkcs7_pad(&[data, unknown_string].concat(),16);
    let mut encrypted = Vec::new();
    for block in  data.chunks(16) {

        if block.len() == 16 {
            encrypted.extend(ecb_encrypt_block(block, key));
        } else {
            // This shouldn't happen if data is properly padded
            panic!("Data must be padded to 16-byte blocks before ECB encryption");
        }
    }
    encrypted
}


/// BLOCK_SIZE=16
fn ecb_decrypt_block(mut block: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = aes::Aes128Dec::new_from_slice(key).expect("Failed to create cipher");
    let mut block_copy = block.to_vec();
    // Decrypt without unpadding first
    for chunk in block_copy.chunks_mut(16) {
        if chunk.len() == 16 {
            let mut block_array = [0u8; 16];
            block_array.copy_from_slice(chunk);
            cipher.decrypt_block((&mut block_array).into());
            chunk.copy_from_slice(&block_array);
        }
    }
    block_copy
}
fn ecb_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut decrypted = Vec::new();
    for block in data.chunks(16) {

        let decrypted_block = ecb_decrypt_block(block, key);
        decrypted.extend_from_slice(&decrypted_block);
    }
    decrypted

}


/// 對輸入數據進行 PKCS#7 填充，返回填充後的數據
fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    println!("Data length: {}", data.len());
    let padding_size = block_size - (data.len() % block_size);
    if padding_size == block_size || padding_size == 0 {
        return data.to_vec(); // No padding needed
    }
    let mut padded_data = Vec::with_capacity(data.len() );
    padded_data.extend_from_slice(data);
    padded_data.extend(vec![padding_size as u8; padding_size]);
    println!("Padded Data: {:?}", padded_data.len());
    padded_data
}


fn pkcs7_unpad(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let padding_size = *data.last().unwrap() as usize;
    if padding_size == 0 || padding_size > data.len() {
        return Vec::new(); // Invalid padding
    }
    if data[data.len() - padding_size..].iter().any(|&x| x != padding_size as u8) {
        return Vec::new(); // Invalid padding
    }
    data[..data.len() - padding_size].to_vec()
}


fn cbc_decrypt_block(block: &[u8], key: &[u8]) -> Vec<u8> {
    use cipher::KeyInit;
    let cipher = aes::Aes128Dec::new(key[..16].try_into().expect("Key must be 16 bytes"));
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&block[..16]);
    cipher.decrypt_block((&mut buf).into());

    buf.to_vec()
}


fn cbc_encrypt_block(block: &[u8], key: &[u8]) -> Vec<u8> {
    use cipher::KeyInit;
    let cipher = aes::Aes128Enc::new(key[..16].try_into().expect("Key must be 16 bytes"));
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&block[..16]);
    cipher.encrypt_block((&mut buf).into());

    buf.to_vec()
}


fn cbc_decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut decrypted = Vec::new();
    let mut prev_block = iv.to_vec();

    for block in data.chunks(16) {
        let decrypted_block = cbc_decrypt_block(block, key);
        let xored_block: Vec<u8> = decrypted_block
            .iter()
            .zip(prev_block.iter())
            .map(|(b, p)| b ^ p)
            .collect();
        decrypted.extend_from_slice(&xored_block);
        prev_block = block.to_vec();
    }
    decrypted
}
fn cbc_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut prev = iv.to_vec();
    let mut buffer_blocks: Vec<u8> = Vec::with_capacity(data.len());

    for block in data.chunks(16) {
        let xored: Vec<u8> = block.iter()
                                  .zip(prev.iter())
                                  .map(|(b, p)| b ^ p)
                                  .collect();
        let encrypted = cbc_encrypt_block(&xored, key);
        prev = encrypted.clone();
        buffer_blocks.extend_from_slice(&encrypted);
        // println!("Encrypted Block: {:?}", encrypted);
    }
    // println!("CBC Encrypted Data: {:?}", buffer_blocks);
    buffer_blocks


}

/// 檢測 ECB/CBC 模式
///
/// True: ECB
/// False: CBC
fn ecb_cbc_detection(data: &[u8]) -> bool {
    let mut blocks: Vec<&[u8]> = data.chunks(16).collect();
    let mut unique_blocks: HashSet<&[u8]> = HashSet::new();
    for block in &blocks {
        if !unique_blocks.insert(block) {
            println!("Repeated block found: {:?}", block);
            return true; // Likely ECB mode
        }
    }
    false

}