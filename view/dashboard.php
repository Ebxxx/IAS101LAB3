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
        <p>Name: <?php echo htmlspecialchars($_SESSION['name']); ?></p>
        <p>Phone Number: <?php echo htmlspecialchars($_SESSION['phone_number']); ?></p>
        <p>Address: <?php echo htmlspecialchars($_SESSION['address']); ?></p>
        <p>Social Security Number: <?php echo htmlspecialchars($_SESSION['social_security_number']); ?></p>
        <p>Email: <?php echo htmlspecialchars($_SESSION['email']); ?></p>
        <a href="logout.php">Logout</a>
    </div>
</body>
</html> 