<?php
// D:\BPT\layer\log-sqli.php
date_default_timezone_set('Asia/Bangkok');
function log_sqli($string)
{   
    // Get the IP address of the injector
    $ip = $_SERVER['REMOTE_ADDR'];
    
    $logFile = '..\layer\myapp.log';
    $date = date('Y-m-d H:i:s');
    
    // Write the log to file
    $log = fopen('..\layer\myapp.log', 'a');

    fwrite($log, "$date | IP: $ip | Message: $string |SQL Injection detected\n");
    fclose($log);
    
}
?>