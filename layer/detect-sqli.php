<?php 
// D:\BPT\layer\detect-sqli.php
require_once('../connect.php');
require_once('../layer/log-sqli.php');
//require_once('D:\BPT\layer\log.php');
function detect_sqli($string)
{
    $input = preg_replace('/\s+/', '', $string);

    //detect single qutoe
    $sqliRegex1= array (     
      
    "/'/",
        
    // detect double quote
    '/"/',

    // detect long comment
    '/\/\*/',

    "/=/",

    '/^\s*(--|#|\/\*)/',
    
    "/;+/",);

    $sqliRegex2 = '~
    ( # start of SQL injection pattern group
      \s* # match any leading whitespace
      ( # start of SQL injection type group
        [\0\b\'\"\n\r\t\%\_\\\\]* # match any escape characters
        \s* # match any leading whitespace
        ( # start of sub-patterns group
          (select\s*.+\s*from\s*.+) # pattern for SELECT statements
          |(insert\s*.+\s*into\s*.+) # pattern for INSERT statements
          |(update\s*.+\s*set\s*.+) # pattern for UPDATE statements
          |(delete\s*.+\s*from\s*.+) # pattern for DELETE statements
          |(drop\s*.+) # pattern for DROP statements
          |(truncate\s*.+) # pattern for TRUNCATE statements
          |(alter\s*.+) # pattern for ALTER statements
          |(exec\s*.+) # pattern for EXEC statements
          |(\s*(all|any|not|and|between|in|like|or|some|contains|containsall|containskey)\s*.+[\=\>\<=\!\~]+.+) # pattern for conditional expressions
          |(let\s+.+[\=]\s*.*) # pattern for LET statements
          |(begin\s*.*\s*end) # pattern for BEGIN/END statements
          |(\s*[\/\*]+\s*.*\s*[\*\/]+) # pattern for comments
          |(\s*(\-\-)\s*.*\s+) # pattern for single-line comments
          |(\s*(contains|containsall|containskey)\s+.*) # pattern for CONTAINS expressions
          |(xp_cmdshell\s) # pattern for xp_cmdshell
          |(sp_executesql\s) # pattern for sp_executesql
          |(create\s.+\sprocedure\s) # pattern for CREATE PROCEDURE statements
          |(declare\s.+\s@\w+\s) # pattern for DECLARE statements
          |(xp_regwrite\s) # pattern for xp_regwrite
          |(xp_regdelete\s) # pattern for xp_regdelete
          |(\bunion\b\s+(?:all\s+)?\bselect\b) # pattern for UNION-based attacks
          |(\b(?:select|update)\b.+?\b(?:from|set)\b\s*\(?\s*(?:select\b|\(?\s*select)) # pattern for error-based attacks
          |(\b(?:sleep|benchmark)\b\s*\() # pattern for time-based attacks
          |/(;WAITFOR\s+DELAY\s+\'\\\d{1,2}:\\\d{1,2}:\\\d{1,2}\'\s*;\s*--)/
        ) # end of sub-patterns group
        (\s*[\;]\s*)* # match any trailing semicolon and whitespace
      ) # end of SQL injection type group
    ) # end of SQL injection pattern group
  ~ix';

  foreach ($sqliRegex1 as $pattern) {
    if (preg_match($pattern, $input)) {
        log_sqli($string);
        return true;
    }
  }
  // if input string doesn't match the first set of regex patterns, check the second set
  if (preg_match($sqliRegex2, $input)) {
    // SQL injection attempt detected, log the attempt and take appropriate action
    //$logMessage = "Potential SQL injection attempt detected: $inputString";
    //file_put_contents("sql_injection_log.txt", $logMessage . PHP_EOL, FILE_APPEND);
    // take appropriate action (e.g. reject the request, redirect to an error page, etc.)
    log_sqli($input);
    return true;
  }
  // if input string doesn't match either set of regex patterns, the input is considered safe
  else {
    //else_sqli($input);
    // input is safe to use in SQL query
    // continue with normal processing (e.g. execute the query, render the page, etc.)
    return false;
  }
/*
if (preg_match($patterns, $input)) {
  // SQL injection detected, handle the error
  log_sqli($input);
  return true;
} else {
  // input is safe to use
  return false;
}*/
}    /***                  
    if (preg_match($pattern, $string)) {
        // SQLi detected
        log_sqli($string);
        return true;
    }


    return false;
} ***/




?>



