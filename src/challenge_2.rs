use base64::engine::general_purpose::STANDARD as engine;
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use std::collections::HashSet;


#[cfg(test)]
/// [source](https://cryptopals.com/sets/2)
mod tests_crypto_challenge_2 {
    use crate::challenge_2::{ecb_encrypt_unknown_string, pkcs7_unpad};
    use std::collections::HashMap;
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
        let _padded = fn_pad(data, 20);
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
        println!(
            "Decrypted: {:?}",
            String::from_utf8_lossy(&unpadded_decrypted)
        );
        assert_eq!(unpadded_decrypted, plaintext);

        println!("is ECB mode: {}", super::ecb_cbc_detection(&encrypted));

        // 測試加密的長度 32 個相同字節
        // 會出現重複的密文塊
        // [228, 64, 133, 250, 43, 218, 51, 216, 106, 163, 64, 180, 193, 108, 5, 173,
        // 228, 64, 133, 250, 43, 218, 51, 216, 106, 163, 64, 180, 193, 108, 5, 173, 96, 250, 54, 112, 126, 69, 244, 153, 219, 160, 242, 91, 146, 35, 1, 165]
        let test_plaintext = super::pkcs7_pad(b"AAAAAAAAAAAAAAA", 16);

        let encrypted_test = super::ecb_encrypt(&test_plaintext, key);
        let encrypted_len = encrypted_test.len();
        println!(
            "Encrypted Test len {:?}: {:?}",
            encrypted_len, encrypted_test
        );
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
            let xored: Vec<u8> = block.iter().zip(prev.iter()).map(|(b, p)| b ^ p).collect();
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
        let encrypted_data: Vec<u8> = vec![
            89, 245, 143, 60, 140, 62, 115, 150, 176, 229, 133, 179, 184, 50, 45, 56, 254, 115,
            179, 182, 199, 227, 156, 161, 162, 214, 247, 195, 43, 124, 255, 48, 245, 233, 151, 42,
            12, 62, 18, 178, 249, 157, 219, 121, 171, 137, 239, 194,
        ];
        let key = b"YELLOW SUBMARINE";
        const BLOCK_SIZE: usize = 16;
        let iv = [0u8; BLOCK_SIZE];
        let mut prev = iv.to_vec();
        let mut plaintext = Vec::with_capacity(encrypted_data.len());

        for block in encrypted_data.chunks(BLOCK_SIZE) {
            let decrypted = super::cbc_decrypt_block(block, key);
            let xored: Vec<u8> = decrypted.iter().zip(&prev).map(|(b, p)| b ^ p).collect();
            println!(
                "Decrypted Block (as string): {}",
                String::from_utf8_lossy(&xored)
            );

            prev = block.to_vec(); // 這裡要設為密文，而不是明文
            plaintext.extend_from_slice(&xored);
        }
        println!("Decrypted Block: {:?}", plaintext);
        println!(
            "CBC Decrypted Data: {:?}",
            String::from_utf8_lossy(&pkcs7_unpad(&plaintext))
        );
    }

    #[test]
    /// result: `This is a test message for CBC mode`
    fn test_cbc_decrypt() {
        let data = vec![
            89, 245, 143, 60, 140, 62, 115, 150, 176, 229, 133, 179, 184, 50, 45, 56, 254, 115,
            179, 182, 199, 227, 156, 161, 162, 214, 247, 195, 43, 124, 255, 48, 245, 233, 151, 42,
            12, 62, 18, 178, 249, 157, 219, 121, 171, 137, 239, 194,
        ];
        let decrypted = super::cbc_decrypt(&data, b"YELLOW SUBMARINE", &[0u8; 16]);
        println!(
            "Decrypted Data: {:?}",
            String::from_utf8_lossy(&pkcs7_unpad(&decrypted))
        );
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

        let _encrypted = super::cbc_encrypt(&padded_data, key, &iv);
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
            .expect("Failed to read file")
            .lines()
            .collect::<String>();
        let data = base64::Engine::decode(&super::engine, data).expect("Failed to decode base64");
        const BLOCK_SIZE: usize = 16; // AES block size
        let iv = [0u8; BLOCK_SIZE]; // 128bit = 16 bytes
        let key = b"YELLOW SUBMARINE";

        let decrypted = super::cbc_decrypt(&data, key, &iv);
        println!(
            "CBC Encrypted Data: {}",
            String::from_utf8_lossy(&pkcs7_unpad(&decrypted))
        );
    }

    #[test]
    /// `Challenge 12
    /// Byte-at-a-time ECB decryption (Simple)
    fn test_oracle_ecb_decrypt() {
        let key = b"YELLOW SUBMARINE";
        let mut encrypted = Vec::new();
        let plaintext_prefix = base64::Engine::decode(&super::engine, "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").expect("REASON");

        let plaintext = [
            plaintext_prefix.as_slice(),
            b" this is a test message 112233 aabbcc !@#$%^&*()_+",
        ]
        .concat();
        let padded_plaintext = super::pkcs7_pad(&plaintext, 16);
        encrypted.extend(super::ecb_encrypt(&padded_plaintext, key));
        println!("Encrypted: {:?}", encrypted);

        let decrypted = super::ecb_decrypt(&encrypted, key);
        println!(
            "Decrypted: {:?} , {}",
            decrypted,
            String::from_utf8(decrypted.clone()).unwrap()
        );
        assert_eq!(decrypted, padded_plaintext);

        // 測試逆向
        let bytes = b"AAAAAAAAAAAAAAA";
        let mut result = [0u8; 16];
        result[..15].copy_from_slice(bytes);
        let compare = super::ecb_encrypt(&result, key);
        let mut a: Vec<Vec<u8>> = Vec::new();
        let _b: Vec<u8> = Vec::new();
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
        for (i, v) in a.iter().enumerate() {
            if v == &compare[..16] {
                println!(" found byte: {}", i);
                break;
            }
        }
    }

    fn test_detect_block_size(encrypt: impl Fn(&[u8], &[u8]) -> Vec<u8>, key: &[u8]) -> usize {
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

    fn test_is_ecb(
        encrypt: impl Fn(&[u8], &[u8]) -> Vec<u8>,
        key: &[u8],
        block_size: usize,
    ) -> bool {
        let input = vec![b'A'; block_size * 2];
        let encrypted = encrypt(&input, key);
        encrypted[..block_size] == encrypted[block_size..2 * block_size]
    }

    fn test_crack_unknown_string(
        encrypt: impl Fn(&[u8], &[u8]) -> Vec<u8>,
        key: &[u8],
        block_size: usize,
    ) -> Vec<u8> {
        let target = encrypt(&[], key);
        if target.is_empty() {
            println!("Error: unknown-string is empty or encrypt function returned no data");
            return Vec::new();
        }

        let mut unknown_string = Vec::new();
        for pos in 0..target.len() {
            let block_idx = pos / block_size;
            let input_len = block_size - 1 - (pos % block_size);
            let input = vec![b'A'; input_len];

            // 構造字典，嘗試所有可能的最後一個字節
            let mut dict = HashMap::new();
            for i in 0..=255 {
                // 構造用於生成字典條目的輸入: padding + 已知字符串 + 測試字節
                let mut test_input = input.clone();
                test_input.extend_from_slice(&unknown_string);
                test_input.push(i);
                // if test_input.len() != block_size {
                //     println!("Error: test_input length is {}, expected {}", test_input.len(), block_size);
                //     continue;
                // }
                // 加密並保存結果的前 block_size 字節
                let encrypted = encrypt(&test_input, key);
                // println!("Test input: {:?}, Encrypted block: {:?}", test_input, &encrypted[..block_size]);
                dict.insert(encrypted[..block_size].to_vec(), i);
            }
            // println!("Target block: {:?}", target_block);
            // 構造目標輸入：input
            let target_input = vec![b'A'; input_len];
            // 獲取目標密文的對應塊
            let target_encrypted = encrypt(&target_input, key);
            let target_block_start = block_idx * block_size;
            let target_block_end = (block_idx + 1) * block_size;
            if target_block_end > target_encrypted.len() {
                break; // 已經解密完所有塊
            }
            let target_block = &target_encrypted[target_block_start..target_block_end];

            // let target_block = &target[(pos / block_size) * block_size..(pos / block_size + 1) * block_size];
            // println!("Position: {}, Input: {:?}", pos, input);
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

    #[test]
    fn test_byte_at_a_time_ecb_decryption() {
        let key = b"YELLOW SUBMARINE";
        let block_size = test_detect_block_size(ecb_encrypt_unknown_string, key);
        println!("Detected block size: {}", block_size);

        let is_ecb = test_is_ecb(ecb_encrypt_unknown_string, key, block_size);
        println!("Is ECB mode: {}", is_ecb);

        if is_ecb {
            let unknown_string =
                test_crack_unknown_string(ecb_encrypt_unknown_string, key, block_size);
            println!(
                "Cracked string: {:?}",
                String::from_utf8_lossy(&unknown_string)
            );
        }
    }
}

#[allow(dead_code)]
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
#[allow(dead_code)]
pub fn ecb_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut encrypted = Vec::new();
    for block in data.chunks(16) {
        if block.len() == 16 {
            encrypted.extend(ecb_encrypt_block(block, key));
        } else {
            // This shouldn't happen if data is properly padded
            panic!("Data must be padded to 16-byte blocks before ECB encryption");
        }
    }
    encrypted
}
#[allow(dead_code)]
pub fn ecb_encrypt_unknown_string(data: &[u8], key: &[u8]) -> Vec<u8> {
    let unknown_string = base64::Engine::decode(
        &engine,
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK",
    );
    let data = pkcs7_pad(&[data, unknown_string.unwrap().as_slice()].concat(), 16);
    let mut encrypted = Vec::new();
    for block in data.chunks(16) {
        if block.len() == 16 {
            encrypted.extend(ecb_encrypt_block(block, key));
        } else {
            // This shouldn't happen if data is properly padded
            panic!("Data must be padded to 16-byte blocks before ECB encryption");
        }
    }
    encrypted
}

#[allow(dead_code)]
/// BLOCK_SIZE=16
pub fn ecb_decrypt_block(block: &[u8], key: &[u8]) -> Vec<u8> {
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
#[allow(dead_code)]
pub fn ecb_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut decrypted = Vec::new();
    for block in data.chunks(16) {
        let decrypted_block = ecb_decrypt_block(block, key);
        decrypted.extend_from_slice(&decrypted_block);
    }
    decrypted
}

#[allow(dead_code)]
/// 對輸入數據進行 PKCS#7 填充，返回填充後的數據
pub(crate) fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_size = block_size - (data.len() % block_size);
    if padding_size == block_size || padding_size == 0 {
        return data.to_vec(); // No padding needed
    }
    let mut padded_data = Vec::with_capacity(data.len());
    padded_data.extend_from_slice(data);
    padded_data.extend(vec![padding_size as u8; padding_size]);
    padded_data
}

#[allow(dead_code)]
fn pkcs7_unpad(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let padding_size = *data.last().unwrap() as usize;
    if padding_size == 0 || padding_size > data.len() {
        return Vec::new(); // Invalid padding
    }
    if data[data.len() - padding_size..]
        .iter()
        .any(|&x| x != padding_size as u8)
    {
        return Vec::new(); // Invalid padding
    }
    data[..data.len() - padding_size].to_vec()
}

#[allow(dead_code)]
pub fn cbc_decrypt_block(block: &[u8], key: &[u8]) -> Vec<u8> {
    use cipher::KeyInit;
    let cipher = aes::Aes128Dec::new(key[..16].try_into().expect("Key must be 16 bytes"));
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&block[..16]);
    cipher.decrypt_block((&mut buf).into());

    buf.to_vec()
}
#[allow(unused)]
pub fn cbc_encrypt_block(block: &[u8], key: &[u8]) -> Vec<u8> {
    use cipher::KeyInit;
    let cipher = aes::Aes128Enc::new(key[..16].try_into().expect("Key must be 16 bytes"));
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&block[..16]);
    cipher.encrypt_block((&mut buf).into());

    buf.to_vec()
}

#[allow(dead_code)]
pub fn cbc_decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
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
#[allow(dead_code)]
pub fn cbc_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut prev = iv.to_vec();
    let mut buffer_blocks: Vec<u8> = Vec::with_capacity(data.len());

    for block in data.chunks(16) {
        let xored: Vec<u8> = block.iter().zip(prev.iter()).map(|(b, p)| b ^ p).collect();
        let encrypted = cbc_encrypt_block(&xored, key);
        prev = encrypted.clone();
        buffer_blocks.extend_from_slice(&encrypted);
        // println!("Encrypted Block: {:?}", encrypted);
    }
    // println!("CBC Encrypted Data: {:?}", buffer_blocks);
    buffer_blocks
}
#[allow(dead_code)]
/// 檢測 ECB/CBC 模式
///
/// True: ECB
/// False: CBC
pub(crate) fn ecb_cbc_detection(data: &[u8]) -> bool {
    let blocks: Vec<&[u8]> = data.chunks(16).collect();
    let mut unique_blocks: HashSet<&[u8]> = HashSet::new();
    for block in &blocks {
        if !unique_blocks.insert(block) {
            println!("Repeated block found: {block:?}");
            return true; // Likely ECB mode
        }
    }
    false
}
