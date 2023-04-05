    <?php
    
    // Set the location and name of your log file
    $log_file = '..\layer\myapp.log';

    // Get the IP address and timestamp of the user
    $ip_address = $_SERVER['REMOTE_ADDR'];
    $timestamp = date('Y-m-d H:i:s');

    // Format the log entry
    $log_entry = "[$timestamp] User with IP address $ip_address logged in.\n";

    // Write the log entry to the log file
    error_log($log_entry, 3, $log_file);
    
    ?>