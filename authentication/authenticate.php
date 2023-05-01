<?php
// D:\BPT\authentication\login.php

session_start();
require_once('../connect.php');
require_once('../layer/detect-sqli.php');

if (isset($_POST['sub'])) {
   
    $username = $_POST['username'];
    $pass = $_POST['password'];


    if((detect_sqli($username) || detect_sqli($pass))== true)
    {
        header("Location: login.php?error=1");
    }

    $password = hash('sha256', $pass);

    $query = "SELECT COUNT(*) as c FROM Employee WHERE e_password = '$password' and e_username = '$username';";

    $result = $mysqli->query($query);

    while($row = $result->fetch_array()) {
        if($row['c'] == 1) {
            $query2 = "SELECT e_id, e_fname, e_lname, e_role FROM Employee WHERE e_password = '$password' and e_username = '$username';";

            $result2 = $mysqli->query($query2);
            $row2 = $result2->fetch_array();
            if ($row2['e_role'] == 'Admin') {
                $_SESSION["user"] = "Admin";
            } elseif ($row2['e_role'] == 'Cashier') {
                $_SESSION["user"] = "Cashier";
            }
            $_SESSION["fname"] = $row2['e_fname'];
            $_SESSION["lname"] = $row2['e_lname'];
            $_SESSION["e_id"] = $row2['e_id'];
            header("Location: ../main/dashboard.php");
        } else {
            header("Location: login.php?error=1");
        }
    }
} else {
    header("Location: login.php");
}
?>

