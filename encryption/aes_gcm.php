<?php

function aes_gcm_encrypt($plaintext, $key, $iv) {
    if (strlen($key) !== 32) {
        throw new Exception("Key must be 32 bytes long.");
    }
    if (strlen($iv) !== 12) {
        throw new Exception("IV must be 12 bytes long.");
    }
    $tag = '';
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    return base64_encode($ciphertext . $tag);
}

function aes_gcm_decrypt($ciphertext, $key, $iv) {
    if (strlen($key) !== 32) {
        throw new Exception("Key must be 32 bytes long.");
    }
    if (strlen($iv) !== 12) {
        throw new Exception("IV must be 12 bytes long.");
    }
    $data = base64_decode($ciphertext);
    $ciphertext = substr($data, 0, -16);
    $tag = substr($data, -16);
    return openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
}

?> 