<?php
require_once 'database.php';

try {
    // Read the SQL file
    $sql = file_get_contents('user_data.sql');
    
    // Execute the SQL commands
    $pdo->exec($sql);
    
    echo "Database table created successfully!";
} catch(PDOException $e) {
    die("Error initializing database: " . $e->getMessage());
}
?> 