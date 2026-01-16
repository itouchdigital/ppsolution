<?php
session_start();

// Database configuration
$host = 'localhost';
$dbname = 'admin_db';
$username = 'root';
$password = '';

try {
    $conn = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        $username = $_POST['username'];
        $password = $_POST['password'];

        // Prepare statement to prevent SQL injection
        $stmt = $conn->prepare("SELECT * FROM admins WHERE username = :username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();

        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['admin_id'] = $user['id'];
            $_SESSION['admin_name'] = $user['username'];
            header('Location: dashboard.php');
            exit();
        } else {
            $_SESSION['error'] = 'Invalid username or password';
            header('Location: login.html');
            exit();
        }
    }
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}
?>