<?php 
// D:\BPT\layer\detect-sqli.php
require_once('../connect.php');
//require_once('../connect_mongo.php');
//require_once('../layer/log-mongo.php');

function detect_sqli($string)
{
    // Set a score threshold to reduce false positives
    $scoreThreshold = 3;
    $score = 0;

    // Layer 1: Check for commonly used SQL injection characters
    $regex1 = array(
        "/'/",
        '/"/',
        '/^\s*(--|#)/',
    );

    foreach ($regex1 as $pattern) {
        if (preg_match($pattern, $string)) {
            $score++;
        }
    }

    // Layer 2: Check for common SQL injection keywords and operators
    $regex2 = array(
        '/\b(alter|select|union|insert|update|delete|drop|truncate|exec|create|declare)\b/i',
        '/\b(from|into|set|where|and|or|not|like|in|between|is)\b/i',
        '/[\=\>\<]/',
        '/[\%|\_]/',
    );

    foreach ($regex2 as $pattern) {
        if (preg_match($pattern, $string)) {
            $score++;
        }
    }

    // Layer 3: Check for special SQL injection payloads and techniques
    $regex3 = array(
        '/\s*(\ball\b|\bany\b|\bnot\b|\band\b|\bbetween\b|\bin\b|\blike\b|\bor\b|\bsome\b|\bcontains\b|\bcontainsall\b|\bcontainskey\b)\s*.+[\=\>\<]+.+/i',
        '/\s*(\blet\b|\bdeclare\b|\bbegin\b|\bend\b|\bif\b|\belse\b|\bwhile\b|\bfor\b|\bcase\b|\bswitch\b|\binto\b|\bdelay\b)\s*.+[\=\>\<]+.+/i',
        '/\b(select|update).+?(from|set)/i',
        '/\b(?:sleep|benchmark)\b\s*\(/i',
        '/[\)\(\;\,\|\&\-\+]/',
    );

    foreach ($regex3 as $pattern) {
        if (preg_match($pattern, $string)) {
            $score ++;
        }
    }

    // Layer 4: Check for hex encoding and URL encoding
    $regex4 = array(
        '/(?:%[0-9a-f]{2})+/i',
        '/0x[0-9a-f]+/i',
    );

    foreach ($regex4 as $pattern) {
        if (preg_match($pattern, $string)) {
            $score++;
        }
    }

    // Layer 5: Check for escape characters and comment characters
    $regex5 = array(
        '/\\\\/',
        '/#\+/',
        '/;/',
    );

    foreach ($regex5 as $pattern) {
        if (preg_match($pattern, $string)) {
            $score++;
        }
    }

    if ($score >= $scoreThreshold) {
        //log_sqli_mongo($string);
        return true;
    } else {
        header("Location: /authentication/login.php?error=1");
        return false;
    }
}
?>



