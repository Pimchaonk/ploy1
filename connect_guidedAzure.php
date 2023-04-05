<?php
    $host = 'pos-system.mysql.database.azure.com';
    $username = 'bhodi';
    $password = 'Treebangbang*007';
    $db_name = 'pos_system';

    //Initializes MySQLi
    $conn = mysqli_init();

    mysqli_ssl_set($conn,NULL,NULL, "/var/www/html/DigiCertGlobalRootG2.crt.pem", NULL, NULL);

    // Establish the connection
    mysqli_real_connect($conn, 'mydemoserver.mysql.database.azure.com', 'myadmin@mydemoserver', 'yourpassword', 'quickstartdb', 3306, NULL, MYSQLI_CLIENT_SSL);

    //If connection failed, show the error
    if (mysqli_connect_errno())
    {
        die('Failed to connect to MySQL: '.mysqli_connect_error());
    }
?>