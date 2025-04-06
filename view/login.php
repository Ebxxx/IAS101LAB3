<?php
session_start();
require_once '../config/database.php';
require_once '../encryption/aes_gcm.php'; // Include AES-GCM encryption

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    try {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            // Decrypt sensitive data
            $key = random_bytes(32); // Use the same key used for encryption
            $iv = random_bytes(12); // Use the same IV used for encryption

            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['name'] = aes_gcm_decrypt($user['name'], $key, $iv);
            $_SESSION['phone_number'] = aes_gcm_decrypt($user['phone_number'], $key, $iv);
            $_SESSION['address'] = aes_gcm_decrypt($user['address'], $key, $iv);
            $_SESSION['social_security_number'] = aes_gcm_decrypt($user['social_security_number'], $key, $iv);
            $_SESSION['email'] = aes_gcm_decrypt($user['email'], $key, $iv);

            header('Location: dashboard.php');
            exit();
        } else {
            $error = "Invalid username or password.";
        }
    } catch (Exception $e) {
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