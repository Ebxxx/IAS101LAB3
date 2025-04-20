<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard</title>
    <link rel="stylesheet" href="app/styles.css">
</head>
<body>
    <div class="container">
        <h1>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?></h1>
        <p>Name: <?php echo isset($_SESSION['name']) ? htmlspecialchars($_SESSION['name']) : 'Not set'; ?></p>
        <p>Phone Number: <?php echo isset($_SESSION['phone_number']) ? htmlspecialchars($_SESSION['phone_number']) : 'Not set'; ?></p>
        <p>Address: <?php echo isset($_SESSION['address']) ? htmlspecialchars($_SESSION['address']) : 'Not set'; ?></p>
        <p>Social Security Number: <?php echo isset($_SESSION['social_security_number']) ? htmlspecialchars($_SESSION['social_security_number']) : 'Not set'; ?></p>
        <p>Email: <?php echo isset($_SESSION['email']) ? htmlspecialchars($_SESSION['email']) : 'Not set'; ?></p>
        <a href="logout.php">Logout</a>
    </div>
</body>
</html> 