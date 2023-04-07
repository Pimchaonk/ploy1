<?php 
// D:\BPT\layer\detect-sqli.php
require_once('../connect.php');
require_once('log-sqli.php');
//require_once('D:\BPT\layer\log.php');
function detect_sqli($string)
{
    $input = preg_replace('/\s+/', '', $string);
 
    
    $patterns = '~
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
        ) # end of sub-patterns group
        (\s*[\;]\s*)* # match any trailing semicolon and whitespace
      ) # end of SQL injection type group
    ) # end of SQL injection pattern group
  ~ix';



if (preg_match($patterns, $input)) {
  // SQL injection detected, handle the error
  log_sqli($input);
  return true;
} else {
  //else_sqli($input);
  // input is safe to use
  return false;
}
} 

?>



