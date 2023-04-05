<?php
$servername = "pos-system.mysql.database.azure.com";
$username = "bhodi";
$password = "Treebangbang*007";
$dbname = "pos_system";

// Create connection
$mysqli = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($mysqli->connect_error) {
  die("Connection failed: " . $mysqli->connect_error);
}
?>
