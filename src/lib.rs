

#[cfg(feature = "aes_cbc")]
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

#[cfg(feature = "aes_cbc")]
use rand::RngCore;

#[cfg(feature = "aes_cbc")]
fn enc_256_cbc(data: Vec<u8>, key: &[u8; 32]) -> std::io::Result<Vec<u8>> {
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

        let mut block = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut block);

        block.extend(data);

        let iv = [0u8; 16];

        let mut buf = vec![0u8; 16+block.len()];
        let ct = Aes256CbcEnc::new(key.into(), &iv.into()).encrypt_padded_b2b_mut::<Pkcs7>(&block, &mut buf).unwrap();
        return Ok(ct.to_vec())
}

#[cfg(feature = "aes_cbc")]
fn dec_256_cbc(block: Vec<u8>, key: &[u8; 32]) -> std::io::Result<Vec<u8>> {
        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

        let iv = [0u8; 16];

        let mut buf = vec![0u8; block.len()];
        let pt = Aes256CbcDec::new(key.into(), &iv.into()).decrypt_padded_b2b_mut::<Pkcs7>(&block, &mut buf).unwrap();
        return Ok(pt[16..].to_vec())
}

#[cfg(feature = "openssl")]
extern crate openssl;

#[cfg(feature = "openssl")]
use openssl::symm::{Cipher, encrypt, decrypt};

#[cfg(feature = "openssl")]
use openssl::rand::rand_bytes;


#[cfg(feature = "openssl")]
fn enc_256_openssl(data: Vec::<u8>, key: &[u8; 32]) -> std::io::Result<Vec<u8>> {
	let mut ranarr = vec![0u8; 16];
	rand_bytes(&mut ranarr).unwrap();
	ranarr.extend(data);
    return Ok(encrypt(Cipher::aes_256_cbc(), key, None, &ranarr)?);
}

#[cfg(feature = "openssl")]
fn dec_256_openssl(data: Vec::<u8>, key: &[u8; 32]) -> std::io::Result<Vec<u8>> {
	let newdata = decrypt(Cipher::aes_256_cbc(), key, None, &data)?;
	return Ok(newdata[16..].to_vec());
}


fn convert_key(key: &str) -> [u8; 32] {
        let mut key = key.to_owned();
        while key.len() < 32 {
                key.push('x');
        }
        return key[..32].as_bytes().try_into().unwrap();
}




#[cfg(test)]
mod tests {
	use super::*;

	#[test]
        #[cfg(feature = "aes_cbc")]
	fn enc_cbc__dec_cbc() -> std::io::Result<()> {
		let text = "Hakuna Matata".as_bytes().to_vec();

		let key = convert_key("kekw");

                let ctxt = enc_256_cbc(text.clone(), &key)?;

		let newtext = dec_256_cbc(ctxt.clone(), &key)?;

                assert_eq!(text, newtext);

		return Ok(());
	}

	#[test]
        #[cfg(feature = "openssl")]
        #[cfg(feature = "aes_cbc")]
	fn enc_cbc__dec_openssl()  -> std::io::Result<()> {
		
                let text = "Hakuna Matata".as_bytes().to_vec();
  	   	  
                let key = convert_key("kekw");

                let ctxt = enc_256_cbc(text.clone(), &key)?;
		
                let newtext = dec_256_openssl(ctxt, &key)?;

                assert_eq!(text, newtext);
		
                return Ok(());

	}

        #[test]
        #[cfg(feature = "openssl")]
        #[cfg(feature = "aes_cbc")]
        fn enc_openssl__dec_cbc()  -> std::io::Result<()> {

                let text = "Hakuna Matata".as_bytes().to_vec();

                let key = convert_key("kekw");

                let ctxt = enc_256_openssl(text.clone(), &key)?;

                let newtext = dec_256_cbc(ctxt, &key)?;

                assert_eq!(text, newtext);

                 return Ok(());

        }

}

