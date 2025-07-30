use cipher::BlockCipherEncrypt;
use rand::{Rng, thread_rng};
use crate::{cbc_encrypt, pkcs7_pad};


/// 生成 16 個隨機字節作為 AES 密鑰
fn generate_random_aes_key() -> [u8; 16] {
    let mut rng = rand::rng();
    let mut key = [0u8; 16];
    rng.fill(&mut key);
    key
}

/// 加密預言機 - 隨機選擇 ECB 或 CBC 模式加密
fn encryption_oracle(input: &[u8]) -> (Vec<u8>, bool) {
    let mut rng = rand::rng();
    // 生成隨機密鑰
    let key = generate_random_aes_key();

    // 在前面添加 5-10 個隨機字節
    let prefix_len = rng.random_range(5..=10);
    let mut prefix = vec![0u8; prefix_len];
    rng.fill(&mut prefix[..]);

    // 在後面添加 5-10 個隨機字節
    let suffix_len = rng.gen_range(5..=10);
    let mut suffix = vec![0u8; suffix_len];
    rng.fill(&mut suffix[..]);

    // 組合明文：prefix + input + suffix
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(&prefix);
    plaintext.extend_from_slice(input);
    plaintext.extend_from_slice(&suffix);

    // 進行 PKCS7 填充
    let padded = pkcs7_pad(&plaintext, 16);

    // 隨機選擇加密模式 (0 = ECB, 1 = CBC)
    let is_cbc = rng.random_bool(0.5);

    let encrypted = if is_cbc {
        // CBC 模式 - 使用隨機 IV
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);
        cbc_encrypt(&padded, &key, &iv)
    } else {
        // ECB 模式
        ecb_encrypt_all(&padded, &key)
    };

    (encrypted, is_cbc)
}

/// ECB 模式加密整個數據
fn ecb_encrypt_all(data: &[u8], key: &[u8]) -> Vec<u8> {
    use aes::cipher::KeyInit;
    let cipher = aes::Aes128Enc::new(key[..16].try_into().expect("Key must be 16 bytes"));

    let mut encrypted = Vec::new();
    for block in data.chunks(16) {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&block[..16]);
        cipher.encrypt_block((&mut buf).into());
        encrypted.extend_from_slice(&buf);
    }
    encrypted
}

/// 檢測加密模式 - 返回 true 如果是 ECB，false 如果是 CBC
fn detect_ecb_mode(ciphertext: &[u8]) -> bool {
    use std::collections::HashSet;

    // 將密文分成 16 字節的塊
    let blocks: Vec<&[u8]> = ciphertext.chunks(16).collect();
    let mut unique_blocks = HashSet::new();

    // 檢查是否有重複的塊
    for block in &blocks {
        if !unique_blocks.insert(block) {
            // 發現重複塊，很可能是 ECB 模式
            return true;
        }
    }

    // 沒有重複塊，可能是 CBC 模式
    false
}

#[cfg(test)]
mod oracle_tests {
    use super::*;

    #[test]
    fn test_ecb_cbc_detection_oracle() {
        let mut correct_detections = 0;
        let total_tests = 100;

        // 使用重複的明文來增加 ECB 模式下出現重複塊的機率
        let test_input = b"AAAAAAAAAAAAAAAA".repeat(10); // 160 字節的重複數據

        for i in 0..total_tests {
            let (encrypted, actual_is_cbc) = encryption_oracle(&test_input);
            let detected_is_ecb = detect_ecb_mode(&encrypted);

            // 如果檢測到 ECB 且實際是 ECB，或者沒檢測到 ECB 且實際是 CBC
            if detected_is_ecb != actual_is_cbc {
                correct_detections += 1;
            }

            println!(
                "Test {}: Actual: {}, Detected ECB: {}, Correct: {}",
                i + 1,
                if actual_is_cbc { "CBC" } else { "ECB" },
                detected_is_ecb,
                detected_is_ecb != actual_is_cbc
            );
        }

        let accuracy = correct_detections as f64 / total_tests as f64;
        println!("Detection accuracy: {:.2}% ({}/{})",
                 accuracy * 100.0, correct_detections, total_tests);

        // 準確率應該很高（通常 > 95%）
        assert!(accuracy > 0.8, "Detection accuracy too low: {:.2}%", accuracy * 100.0);
    }

    #[test]
    fn test_generate_random_key() {
        let key1 = generate_random_aes_key();
        let key2 = generate_random_aes_key();

        println!("Key 1: {:?}", key1);
        println!("Key 2: {:?}", key2);

        // 兩個隨機密鑰應該不同（極小機率相同）
        assert_ne!(key1, key2);
        assert_eq!(key1.len(), 16);
        assert_eq!(key2.len(), 16);
    }
}