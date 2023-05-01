<?php

    require_once("../connect_mongo.php");
    include("../connect_mongo.php");

    function log_sqli_mongo($string)
    {   
        date_default_timezone_set('Asia/Bangkok');
        global $mongoclient;
    
        $ip = $_SERVER['REMOTE_ADDR'];    
        $date = date('Y-m-d H:i:s');
        
        // Add the log to MongoDB collection
        $collection = $mongoclient->bpt_db->bpt_log;
        $log = [
            'date' => $date,
            'ip' => $ip,
            'message' => $string,
            'type' => 'SQL Injection detected'
        ];
        $collection->insertOne($log);
    }
?>