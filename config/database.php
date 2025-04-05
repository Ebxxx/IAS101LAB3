<?php
$db_host = 'localhost:3307';
$db_name = 'user_data';
$db_user = 'root';
$db_pass = '';

try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    $conn = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
    if (!$conn) {
        throw new Exception("mysqli connection failed: " . mysqli_connect_error());
    }
} catch(Exception $e) {
    die("Connection failed: " . $e->getMessage());
}
?>
