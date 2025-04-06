<?php
session_start();
require_once '../config/database.php';
require_once '../encryption/aes_gcm.php'; // Include AES-GCM encryption

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT);
    $name = $_POST['name'];
    $phone_number = $_POST['phone_number'];
    $address = $_POST['address'];
    $social_security_number = $_POST['social_security_number'];
    $email = $_POST['email'];

    // Generate a 32-byte key and 12-byte IV for AES-GCM
    $key = random_bytes(32);
    $iv = random_bytes(12);

    // Encrypt sensitive data
    $encrypted_name = aes_gcm_encrypt($name, $key, $iv);
    $encrypted_phone_number = aes_gcm_encrypt($phone_number, $key, $iv);
    $encrypted_address = aes_gcm_encrypt($address, $key, $iv);
    $encrypted_social_security_number = aes_gcm_encrypt($social_security_number, $key, $iv);
    $encrypted_email = aes_gcm_encrypt($email, $key, $iv);

    try {
        $stmt = $pdo->prepare("INSERT INTO users (username, password, name, phone_number, address, social_security_number, email) VALUES (:username, :password, :name, :phone_number, :address, :social_security_number, :email)");
        $stmt->execute([
            'username' => $username,
            'password' => $password,
            'name' => $encrypted_name,
            'phone_number' => $encrypted_phone_number,
            'address' => $encrypted_address,
            'social_security_number' => $encrypted_social_security_number,
            'email' => $encrypted_email
        ]);
        header('Location: login.php');
        exit();
    } catch (Exception $e) {
        $error = "Error: " . $e->getMessage();
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