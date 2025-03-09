#![no_std]
#![no_main]

extern crate sgx_tstd as std;
use sgx_types::*;
use sgx_tcrypto::*;
use sgx_tseal::*;
use std::vec::Vec;
use std::string::String;
use std::slice;

/// Fungsi untuk mengenkripsi data menggunakan AES-GCM
#[no_mangle]
pub extern "C" fn encrypt_data(data_ptr: *const u8, data_len: usize, key_ptr: *const u8, key_len: usize, output_ptr: *mut u8) -> sgx_status_t {
    let data = unsafe { slice::from_raw_parts(data_ptr, data_len) };
    let key = unsafe { slice::from_raw_parts(key_ptr, key_len) };

    let mut encrypted_data = vec![0u8; data_len + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE];
    let iv = &encrypted_data[..SGX_AESGCM_IV_SIZE];
    let mac = &mut encrypted_data[data_len + SGX_AESGCM_IV_SIZE..];

    let aes_key = SgxAesGcm::new(&key).unwrap();
    aes_key.encrypt(data, &iv, mac, &mut encrypted_data[SGX_AESGCM_IV_SIZE..data_len + SGX_AESGCM_IV_SIZE])
        .map_err(|_| sgx_status_t::SGX_ERROR_UNEXPECTED)?;

    unsafe {
        std::ptr::copy_nonoverlapping(encrypted_data.as_ptr(), output_ptr, encrypted_data.len());
    }
    
    sgx_status_t::SGX_SUCCESS
}

/// Fungsi untuk mendekripsi data dalam Secure Enclave
#[no_mangle]
pub extern "C" fn decrypt_data(encrypted_ptr: *const u8, enc_len: usize, key_ptr: *const u8, key_len: usize, output_ptr: *mut u8) -> sgx_status_t {
    let encrypted_data = unsafe { slice::from_raw_parts(encrypted_ptr, enc_len) };
    let key = unsafe { slice::from_raw_parts(key_ptr, key_len) };

    let iv = &encrypted_data[..SGX_AESGCM_IV_SIZE];
    let mac = &encrypted_data[enc_len - SGX_AESGCM_MAC_SIZE..];
    let cipher_text = &encrypted_data[SGX_AESGCM_IV_SIZE..enc_len - SGX_AESGCM_MAC_SIZE];

    let aes_key = SgxAesGcm::new(&key).unwrap();
    let mut decrypted_data = vec![0u8; cipher_text.len()];

    aes_key.decrypt(cipher_text, &iv, mac, &mut decrypted_data)
        .map_err(|_| sgx_status_t::SGX_ERROR_UNEXPECTED)?;

    unsafe {
        std::ptr::copy_nonoverlapping(decrypted_data.as_ptr(), output_ptr, decrypted_data.len());
    }
    
    sgx_status_t::SGX_SUCCESS
}
