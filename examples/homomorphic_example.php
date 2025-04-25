<?php
require_once '../security/key_management.php';
require_once '../security/homomorphic/paillier_encryption.php';

// Initialize key management
$keyManager = new KeyManagement();

// Generate keys for a user
$userId = 1;
$keys = $keyManager->generateUserKeys($userId);

// Get Paillier instance
$paillier = new PaillierEncryption();

// Example values
$value1 = 278;
$value2 = 100;

// Encrypt values
$encrypted1 = $paillier->encrypt($value1, $keys['paillier']['public']);
$encrypted2 = $paillier->encrypt($value2, $keys['paillier']['public']);

// Perform homomorphic addition
$encryptedSum = $paillier->addEncrypted($encrypted1, $encrypted2, $keys['paillier']['public']);

// Decrypt the result
$sum = $paillier->decrypt($encryptedSum, $keys['paillier']['private'], $keys['paillier']['public']);

echo "Value 1: $value1\n";
echo "Value 2: $value2\n";
echo "Encrypted sum: " . substr($encryptedSum, 0, 20) . "...\n";
echo "Decrypted sum: $sum\n";
?> 