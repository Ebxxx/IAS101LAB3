<?php
session_start();
require_once '../config/database.php';
require_once '../encryption/decrypt_user_data.php';

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
            
            // Decrypt sensitive data
            $_SESSION['name'] = decrypt_user_data($user['name']);
            $_SESSION['phone_number'] = decrypt_user_data($user['phone_number']);
            $_SESSION['address'] = decrypt_user_data($user['address']);
            $_SESSION['social_security_number'] = decrypt_user_data($user['social_security_number']);
            $_SESSION['email'] = decrypt_user_data($user['email']);

            if ($_SESSION['name'] === false || $_SESSION['phone_number'] === false || 
                $_SESSION['address'] === false || $_SESSION['social_security_number'] === false || 
                $_SESSION['email'] === false) {
                error_log("Decryption failed for user: " . $username);
                if ($_SESSION['name'] === false) error_log("Name decryption failed");
                if ($_SESSION['phone_number'] === false) error_log("Phone number decryption failed");
                if ($_SESSION['address'] === false) error_log("Address decryption failed");
                if ($_SESSION['social_security_number'] === false) error_log("SSN decryption failed");
                if ($_SESSION['email'] === false) error_log("Email decryption failed");
                $error = "Error decrypting user data. Please contact administrator.";
            } else {
                header('Location: dashboard.php');
                exit();
            }
        } else {
            $error = "Invalid username or password.";
        }
    } catch (Exception $e) {
        error_log("Login error: " . $e->getMessage());
        $error = "Error: " . $e->getMessage();
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