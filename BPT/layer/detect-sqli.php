<?php 
// D:\BPT\layer\detect-sqli.php

function detect_sqli($string)
{
    //require_once('db-creds.php');
    require_once('../connect.php');
    require_once('log-sqli.php');

    
    if (preg_match('/\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|TRUNCATE|ALTER|CREATE)\b/i', $string)) {
        // SQLi detected
        log_sqli($string);
        return true;
    }
    return false;
}

?>