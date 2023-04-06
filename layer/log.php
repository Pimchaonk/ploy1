    <?php
    
    // Set the location and name of your log file
    $log_file = '..\layer\myapp.log';

    function log_sqli($string)
    {   
    date_default_timezone_set('Asia/Bangkok');
   
    $ip = $_SERVER['REMOTE_ADDR'];    
    $date = date('Y-m-d H:i:s');
    
    // Write the log to file
    $log = fopen('..\layer\myapp.log', 'a');

    fwrite($log, "$date | IP: $ip | Message: $string |SQL Injection detected\n");
    fclose($log);
    }
    ?>
