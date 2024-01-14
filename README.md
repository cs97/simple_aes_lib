# simple_aes_lib
run test
```
cargo test --all-features 
```


dependencies
```
[dependencies]
simple_aes_lib = { git = "https://github.com/cs97/simple_aes_lib", features = ["aes_cbc"] }
simple_aes_lib = { git = "https://github.com/cs97/simple_aes_lib", features = ["openssl"] }
```

example usage
```
fn enc_cbc__dec_openssl()  -> std::io::Result<()> {
  let text = "Hakuna Matata".as_bytes().to_vec(); 
  let key = convert_key("kekw");
  let ctxt = enc_256_cbc(text.clone(), &key)?;
  let newtext = dec_256_openssl(ctxt, &key)?;
  assert_eq!(text, newtext);
  return Ok(());
}
```


