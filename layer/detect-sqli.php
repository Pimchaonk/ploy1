<?php 
// D:\BPT\layer\detect-sqli.php
require_once('../connect.php');
require_once('../layer/log-sqli.php');
function detect_sqli($string)
{
    //$input = preg_replace('/\s+/', '', $string);
    //$input =  ;
    //detect single qutoe
    $sqliRegex1= array (
           
      
    "/'/",
        
    // detect double quote
    '/"/',

    // detect long comment
    '/\/\*/',

    "/=/",

    '/^\s*(--|#|\/\*)/',
    
    //"/;+/"
    
    );

    $sqliRegex2 = '~
    ( # start of SQL injection pattern group
      \s* # match any leading whitespace
      ( # start of SQL injection type group
        [\0\b\'\"\n\r\t\%\_\\\\]* # match any escape characters
        \s* # match any leading whitespace
        ( # start of sub-patterns group
          (\bselect\b\s*.+\s*\bfrom\b\s*.+) # pattern for SELECT statements
          |(\binsert\b\s*.+\s*\binto\b\s*.+) # pattern for INSERT statements
          |(\bupdate\b\s*.+\s*\bset\b\s*.+) # pattern for UPDATE statements
          |(\bdelete\b\s*.+\s*\bfrom\b\s*.+) # pattern for DELETE statements
          |(\bdrop\b\s*.+) # pattern for DROP statements
          |(\btruncate\b\s*.+) # pattern for TRUNCATE statements
          |(\balter\b\s*.+) # pattern for ALTER statements
          |(\bexec\b\s*.+) # pattern for EXEC statements
          |(\s*(\ball\b|\bany\b|\bnot\b|\band\b|\bbetween\b|\bin\b|\blike\b|\bor\b|\bsome\b|\bcontains\b|\bcontainsall\b|\bcontainskey\b)\s*.+[\=\>\<=\!\~]+.+) # pattern for conditional expressions
          |(\blet\b\s+.+[\=]\s*.*) # pattern for LET statements
          |(\bbegin\b\s*.*\s*\bend\b) # pattern for BEGIN/END statements
          |(\s*[\/\*]+\s*.*\s*[\*\/]+) # pattern for comments
          |(\s*(\-\-)\s*.*\s+) # pattern for single-line comments
          |(\s*(\bcontains\b|\bcontainsall\b|\bcontainskey\b)\s+.*) # pattern for CONTAINS expressions
          |(\bxp_cmdshell\b\s) # pattern for xp_cmdshell
          |(\bsp_executesql\b\s) # pattern for sp_executesql
          |(\bcreate\b\s*.+\s*\bprocedure\b\s) # pattern for CREATE PROCEDURE statements
          |(\bdeclare\b\s*.+\s*\@\w+\s) # pattern for DECLARE statements
          |(\bxp_regwrite\b\s) # pattern for xp_regwrite
          |(\bxp_regdelete\b\s) # pattern for xp_regdelete
          |(\bunion\b\s+(?:\ball\b\s+)?\bselect\b) # pattern for UNION-based attacks
          |(\b(?:select|update)\b.+?\b(?:from|set)\b\s*\(?(\s*select\b|\(?\s*select)) # pattern for error-based attacks
          |(\b(?:sleep|benchmark)\b\s*\() # pattern for time-based attacks
          |/(;\s*\bWAITFOR\b\s+\bDELAY\b\s+\'\\\d{1,2}:\\\d{1,2}:\\\d{1,2}\'\s*;\s*--)/
        ) # end of sub-patterns group
        (\s*[\;]\s*)* # match any trailing semicolon and whitespace
      ) # end of SQL injection type group
    ) # end of SQL injection pattern group
  ~ix';

  foreach ($sqliRegex1 as $pattern) {
    if (preg_match($pattern, $string)) {
        log_sqli($string);
        return true;
    }
  }
  // if input string doesn't match the first set of regex patterns, check the second set
  if (preg_match($sqliRegex2, $string)) {
    log_sqli($string);
    return true;
  }
  
  else {
    // input is safe to use in SQL query
    return false;
  }
}

?>



