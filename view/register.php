<?php
session_start();
require_once '../config/database.php';

function encrypt_user_data($data) {
    $encryption_key = '0123456789abcdef0123456789abcdef'; // 32 chars for AES-256
    $method = "AES-256-CBC";
    
    // Generate a random IV
    $iv = openssl_random_pseudo_bytes(16);
    
    $encrypted = openssl_encrypt(
        $data,
        $method,
        $encryption_key,
        OPENSSL_RAW_DATA,
        $iv
    );
    
    // Combine IV and encrypted data
    return base64_encode($iv . $encrypted);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT);
    $name = $_POST['name'];
    $phone_number = $_POST['phone_number'];
    $address = $_POST['address'];
    $social_security_number = $_POST['social_security_number'];
    $email = $_POST['email'];

    // Encrypt sensitive data
    $encrypted_name = encrypt_user_data($name);
    $encrypted_phone_number = encrypt_user_data($phone_number);
    $encrypted_address = encrypt_user_data($address);
    $encrypted_social_security_number = encrypt_user_data($social_security_number);
    $encrypted_email = encrypt_user_data($email);

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