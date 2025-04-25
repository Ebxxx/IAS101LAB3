<?php
require_once '../security/homomorphic/homomorphic_key_management.php';
require_once '../security/homomorphic/paillier_encryption.php';

// Initialize homomorphic key management
$keyManager = new HomomorphicKeyManagement();

// Generate keys for a user
$userId = 1;
$keys = $keyManager->generateUserKeys($userId);

// Get Paillier instance
$paillier = new PaillierEncryption();

// Example values
$value1 = 10;
$value2 = 100;

// Encrypt values
$encrypted1 = $paillier->encrypt($value1, $keys['public']);
$encrypted2 = $paillier->encrypt($value2, $keys['public']);

// Perform homomorphic addition
$encryptedSum = $paillier->addEncrypted($encrypted1, $encrypted2, $keys['public']);

// Decrypt the result
$sum = $paillier->decrypt($encryptedSum, $keys['private'], $keys['public']);

echo "Value 1: $value1\n";
echo "Value 2: $value2\n";
echo "Encrypted sum: " . substr($encryptedSum, 0, 20) . "...\n";
echo "Decrypted sum: $sum\n";
?> 