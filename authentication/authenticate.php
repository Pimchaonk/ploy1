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

1
<?php
2
// D:\BPT\authentication\login.php
3
​
4
session_start();
5
require_once('../connect.php');
6
require_once('../layer/detect-sqli.php');
7
​
8
if (isset($_POST['sub'])) {
9
​
10
    $username = $_POST['username'];
11
    $password = $_POST['password'];
12
​
13
​
14
    detect_sqli($username);
15
    
16
    // Hash the password using SHA-256 algorithm
17
    $password_hashed = hash('sha256', $password);
18
​
19
    // Prepare and execute the SELECT statement using prepared statements
20
    $stmt = $mysqli->prepare("SELECT e_id, e_fname, e_lname, e_role FROM Employee WHERE e_password = ? AND e_username = ?");
21
    $stmt->bind_param("ss", $password_hashed, $username);
22
    $stmt->execute();
23
    $stmt->store_result();
24
​
25
    // Check if the SELECT statement returned exactly one row
26
    if ($stmt->num_rows == 1) {
27
        $stmt->bind_result($e_id, $e_fname, $e_lname, $e_role);
28
        $stmt->fetch();
29
​
30
        // Set session variables based on user role
31
        if ($e_role == 'Admin') {
32
            $_SESSION["user"] = "Admin";
33
        } elseif ($e_role == 'Cashier') {
34
            $_SESSION["user"] = "Cashier";
35
        }
36
​
37
        // Set session variables for first name, last name, and employee ID
38
        $_SESSION["fname"] = $e_fname;
39
        $_SESSION["lname"] = $e_lname;
40
        $_SESSION["e_id"] = $e_id;
41
​
42
        // Redirect to dashboard page
43
        header("Location: ../main/dashboard.php");
44
    } else {
45
        // Redirect back to login page with error message

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
        header("Location: ../authentication/login.php?error=1");
    }
} else {
    // Redirect to login page if the form was not submitted
    header("Location: ../authentication/login.php");
}
?>

