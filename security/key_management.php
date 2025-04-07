<?php
require_once 'ecc_encryption.php';

class KeyManagement {
    private $keyStorePath;
    private $ecc;
    
    public function __construct($keyStorePath = '../keys') {
        $this->keyStorePath = $keyStorePath;
        
        // Ensure OpenSSL is available
        if (!extension_loaded('openssl')) {
            throw new Exception("OpenSSL extension is not loaded");
        }
        
        // Create key store directory if it doesn't exist
        if (!file_exists($this->keyStorePath)) {
            if (!mkdir($this->keyStorePath, 0777, true)) {
                throw new Exception("Failed to create key store directory: " . $this->keyStorePath);
            }
        }
        
        // Ensure the directory is writable
        if (!is_writable($this->keyStorePath)) {
            throw new Exception("Key store directory is not writable: " . $this->keyStorePath);
        }
        
        $this->ecc = new ECCEncryption();
    }
    
    // Generate and store new key pair for a user
    public function generateUserKeys($userId) {
        try {
            // Generate the key pair
            $keyPair = $this->ecc->generateKeyPair();
            
            // Store private key
            $privateKeyPath = $this->getPrivateKeyPath($userId);
            if (file_put_contents($privateKeyPath, $keyPair['private']) === false) {
                throw new Exception("Failed to write private key file: " . $privateKeyPath);
            }
            
            // Store public key
            $publicKeyPath = $this->getPublicKeyPath($userId);
            if (file_put_contents($publicKeyPath, $keyPair['public']) === false) {
                // Clean up private key if public key write fails
                @unlink($privateKeyPath);
                throw new Exception("Failed to write public key file: " . $publicKeyPath);
            }
            
            return $keyPair;
        } catch (Exception $e) {
            // Clean up any files that might have been created
            @unlink($this->getPrivateKeyPath($userId));
            @unlink($this->getPublicKeyPath($userId));
            throw new Exception("Failed to generate and store keys: " . $e->getMessage());
        }
    }
    
    // Get user's public key
    public function getUserPublicKey($userId) {
        $publicKeyPath = $this->getPublicKeyPath($userId);
        if (!file_exists($publicKeyPath)) {
            throw new Exception("Public key not found for user: " . $userId);
        }
        $publicKey = file_get_contents($publicKeyPath);
        if ($publicKey === false) {
            throw new Exception("Failed to read public key file: " . $publicKeyPath);
        }
        return $publicKey;
    }
    
    // Get user's private key
    public function getUserPrivateKey($userId) {
        $privateKeyPath = $this->getPrivateKeyPath($userId);
        if (!file_exists($privateKeyPath)) {
            throw new Exception("Private key not found for user: " . $userId);
        }
        $privateKey = file_get_contents($privateKeyPath);
        if ($privateKey === false) {
            throw new Exception("Failed to read private key file: " . $privateKeyPath);
        }
        return $privateKey;
    }
    
    private function getPrivateKeyPath($userId) {
        return $this->keyStorePath . DIRECTORY_SEPARATOR . 'private_' . $userId . '.pem';
    }
    
    private function getPublicKeyPath($userId) {
        return $this->keyStorePath . DIRECTORY_SEPARATOR . 'public_' . $userId . '.pem';
    }
}
?> 