<?php
// D:\BPT\authentication\login.php

session_start();
require_once('../connect.php');
require_once('../layer/detect-sqli.php');

if (isset($_POST['sub'])) {
   

    
    $username = $_POST['username'];
    $password = $_POST['password'];


    detect_sqli($username);
    
    // Hash the password using SHA-256 algorithm
    $password_hashed = hash('sha256', $password);

    // Prepare and execute the SELECT statement using prepared statements
    $stmt = $mysqli->prepare("SELECT e_id, e_fname, e_lname, e_role FROM Employee WHERE e_password = ? AND e_username = ?");
    $stmt->bind_param("ss", $password_hashed, $username);
    $stmt->execute();
    $stmt->store_result();

    // Check if the SELECT statement returned exactly one row
    if ($stmt->num_rows == 1) {
        $stmt->bind_result($e_id, $e_fname, $e_lname, $e_role);
        $stmt->fetch();

        // Set session variables based on user role
        if ($e_role == 'Admin') {
            $_SESSION["user"] = "Admin";
        } elseif ($e_role == 'Cashier') {
            $_SESSION["user"] = "Cashier";
        }

        // Set session variables for first name, last name, and employee ID
        $_SESSION["fname"] = $e_fname;
        $_SESSION["lname"] = $e_lname;
        $_SESSION["e_id"] = $e_id;

        // Redirect to dashboard page
        header("Location: ../main/dashboard.php");
    } else {
        // Redirect back to login page with error message
        header("Location: login.php?error=1");
    }
} else {
    // Redirect to login page if the form was not submitted
    header("Location: login.php");
}
?>

