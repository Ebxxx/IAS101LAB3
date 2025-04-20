<?php
session_start();
require_once '../config/database.php';
require_once '../security/ecc_encryption.php';
require_once '../security/key_management.php';
require_once '../security/ntru_encryption.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT);
    $name = $_POST['name'];
    $phone_number = $_POST['phone_number'];
    $address = $_POST['address'];
    $social_security_number = $_POST['social_security_number'];
    $email = $_POST['email'];

    try {
        // First insert the user to get the user ID
        $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
        $stmt->execute([
            'username' => $username,
            'password' => $password
        ]);
        
        $userId = $pdo->lastInsertId();
        
        // Generate NTRU keys for the user
        $keyManager = new KeyManagement();
        $keys = $keyManager->generateUserKeys($userId);
        
        // Use NTRU for highly sensitive data
        $ntru = new NTRUEncryption();
        $encryptedSSN = $ntru->encrypt($social_security_number, $keys['ntru']['public']);
        $encryptedPII = $ntru->encrypt($name, $keys['ntru']['public']);
        $encryptedAddress = $ntru->encrypt($address, $keys['ntru']['public']);
        
        // Use ECC for less sensitive data or session-based data
        $ecc = new ECCEncryption();
        $encryptedEmail = $ecc->encrypt($email, $keys['ecc']['public']);
        $encryptedPreferences = $ecc->encrypt($phone_number, $keys['ecc']['public']);
        
        // Update user record with encrypted data
        $stmt = $pdo->prepare("UPDATE users SET 
            name = :name,
            phone_number = :phone_number,
            address = :address,
            social_security_number = :social_security_number,
            email = :email
            WHERE id = :id");
            
        $stmt->execute([
            'id' => $userId,
            'name' => $encryptedPII,
            'phone_number' => $encryptedPreferences,
            'address' => $encryptedAddress,
            'social_security_number' => $encryptedSSN,
            'email' => $encryptedEmail
        ]);
        
        header('Location: login.php');
        exit();
    } catch (Exception $e) {
        error_log("Registration error: " . $e->getMessage());
        $error = "Error during registration: " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Register</title>
    <link rel="stylesheet" href="app/styles.css">
</head>
<body>
    <div class="container">
        <h1>Register</h1>
        <?php if (isset($error)) echo "<p class='error'>$error</p>"; ?>
        <form method="POST" action="">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required><br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required><br>
            <label for="name">Name:</label>
            <input type="text" id="name" name="name" required><br>
            <label for="phone_number">Phone Number:</label>
            <input type="text" id="phone_number" name="phone_number" required><br>
            <label for="address">Address:</label>
            <textarea id="address" name="address" required></textarea><br>
            <label for="social_security_number">Social Security Number:</label>
            <input type="text" id="social_security_number" name="social_security_number" required><br>
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" required><br>
            <button type="submit">Register</button>
        </form>
        <p>Already have an account? <a href="login.php">Login here</a></p>
    </div>
</body>
</html> 