<?php

function chacha20_encrypt($plaintext, $key, $nonce) {
    if (strlen($key) !== 32) {
        throw new Exception("Key must be 32 bytes long.");
    }
    if (strlen($nonce) !== 12) {
        throw new Exception("Nonce must be 12 bytes long.");
    }
    return openssl_encrypt($plaintext, 'chacha20', $key, OPENSSL_RAW_DATA, $nonce);
}

function chacha20_decrypt($ciphertext, $key, $nonce) {
    if (strlen($key) !== 32) {
        throw new Exception("Key must be 32 bytes long.");
    }
    if (strlen($nonce) !== 12) {
        throw new Exception("Nonce must be 12 bytes long.");
    }
    return openssl_decrypt($ciphertext, 'chacha20', $key, OPENSSL_RAW_DATA, $nonce);
}

?> 