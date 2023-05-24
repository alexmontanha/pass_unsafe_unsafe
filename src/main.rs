use crypto::symmetriccipher::SymmetricCipherError;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use crypto::aes::KeySize::KeySize128;
use crypto::blockmodes::{NoPadding};
use crypto::{symmetriccipher::{Decryptor, Encryptor}};
use crypto::blockmodes::Cbc;
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};

fn encrypt_password(password: &str, key: &[u8], iv: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut encryptor = crypto::aes::cbc_encryptor(
        KeySize128,
        key,
        iv,
        NoPadding,
    );

    let mut ciphertext = Vec::<u8>::new();
    let mut buffer = [0; 4096];
    let mut read_buffer = RefReadBuffer::new(password.as_bytes());
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;
        ciphertext.extend(write_buffer.take_read_buffer().take_remaining().iter().copied());

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(ciphertext)
}

fn decrypt_password(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<String, SymmetricCipherError> {
    let mut decryptor = crypto::aes::cbc_decryptor(
        KeySize128,
        key,
        iv,
        NoPadding,
    );

    let mut plaintext = Vec::<u8>::new();
    let mut buffer = [0; 4096];
    let mut read_buffer = RefReadBuffer::new(ciphertext);
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        plaintext.extend(write_buffer.take_read_buffer().take_remaining().iter().copied());

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(String::from_utf8_lossy(&plaintext).into_owned())
}

fn main() {
    let password = "senha123";
    let key = b"supersecretkey123";
    let iv = b"initializationvec";

    // Criptografar senha
    let ciphertext = match encrypt_password(password, key, iv) {
        Ok(ciphertext) => ciphertext,
        Err(err) => {
            eprintln!("Erro ao criptografar: {}", err);
            return;
        }
    };

    println!("Senha: {}", password);
    println!("Ciphertext: {:?}", ciphertext);

    // Descriptografar senha
    let decrypted_password = match decrypt_password(&ciphertext, key, iv) {
        Ok(decrypted) => decrypted,
        Err(err) => {
            eprintln!("Erro ao descriptografar: {}", err);
            return;
        }
    };

    println!("Senha descriptografada: {}", decrypted_password);
}
