<?php
function decrypt_user_data($encrypted_data) {
    // for development mode
    $encryption_key = '0123456789abcdef0123456789abcdef'; // 32 chars for AES-256
    $method = "AES-256-CBC";
    
    // Extract the IV and encrypted data
    $data = base64_decode($encrypted_data);
    $iv = substr($data, 0, 16); // Get the first 16 bytes for IV
    $encrypted = substr($data, 16); // Get the rest which is the encrypted data
    
    try {
        $decrypted = openssl_decrypt(
            $encrypted,
            $method,
            $encryption_key,
            OPENSSL_RAW_DATA,
            $iv
        );
        
        if ($decrypted === false) {
            error_log("OpenSSL decryption failed: " . openssl_error_string());
            return false;
        }
        
        return $decrypted;
    } catch (Exception $e) {
        error_log("Decryption error: " . $e->getMessage());
        return false;
    }
}
?> 