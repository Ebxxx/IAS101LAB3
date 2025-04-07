<?php
session_start();
require_once '../config/database.php';
require_once '../security/ecc_encryption.php';
require_once '../security/key_management.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    try {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            
            // Initialize ECC decryption
            $keyManager = new KeyManagement();
            $privateKey = $keyManager->getUserPrivateKey($user['id']);
            $ecc = new ECCEncryption();
            
            try {
                // Decrypt sensitive data
                $_SESSION['name'] = $ecc->decrypt($user['name'], $privateKey);
                $_SESSION['phone_number'] = $ecc->decrypt($user['phone_number'], $privateKey);
                $_SESSION['address'] = $ecc->decrypt($user['address'], $privateKey);
                $_SESSION['social_security_number'] = $ecc->decrypt($user['social_security_number'], $privateKey);
                $_SESSION['email'] = $ecc->decrypt($user['email'], $privateKey);
                
                header('Location: dashboard.php');
                exit();
            } catch (Exception $e) {
                error_log("Decryption error for user {$user['id']}: " . $e->getMessage());
                $error = "Error decrypting user data. Please contact administrator.";
            }
        } else {
            $error = "Invalid username or password.";
        }
    } catch (Exception $e) {
        error_log("Login error: " . $e->getMessage());
        $error = "Error during login: " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="app/styles.css">
</head>
<body>
    <div class="container">
        <h1>Login</h1>
        <?php if (isset($error)) echo "<p class='error'>$error</p>"; ?>
        <form method="POST" action="">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required><br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required><br>
            <button type="submit">Login</button>
        </form>
        <p>Don't have an account? <a href="register.php">Register here</a></p>
    </div>
</body>
</html> 