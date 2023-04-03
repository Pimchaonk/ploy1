<?php 
// D:\BPT\layer\detect-sqli.php

function detect_sqli($string)
{
    //require_once('db-creds.php');
    require_once('../connect.php');
    require_once('log-sqli.php');
    $input=remove_whitespace($string);
    //$pattern = '/((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))|\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|TRUNCATE|ALTER|CREATE)\b/i';
    $patterns = array(
        //single quote or double quote, followed by the word OR, followed by optional spaces, followed by the number 5 (or any other digit), followed by an equal sign, followed by optional spaces, followed by the same number (or any other digit), followed by optional spaces and an optional double dash (--).
        // password' OR 5=5
        //"/('|\")[\s]*OR[\s]*\d*=[\s]*\d*([\s]*--)?/i",
      
        //This regular expression will match any string that starts with any number of characters other than a single quote ('), followed by a single quote ('), followed by any number of characters other than a single quote ('), followed by the string ' OR (with optional whitespace), followed by any number of digits, followed by the string =, followed by any number of digits, followed by any number of characters (including quotes) until the end of the string.
        //"/^[^']*'[^']*OR\s*[0-9]+=[0-9]+.*$/i",
        // detect comment short comment and long comment (/* */)
        //'/(--[^\r\n]*)|(\/\*[\w\W]*?(?<=\*\/))/i',
        //starting with /* and ending with */ 
        //'/\/\*.*?\*\//s'

        // detect PASSWORD' OR '1'='1
        //'/[value]+(\s+OR\s+|\s+|\t)+[^-;()\'"]+(;|\-\-|\#|\/\*)?/',


        //detect single qutoe
        "/'/",
        
        // detect double quote
        '/"/',

        // detect long comment
        '/\/\*/',

        //SELECT, INSERT, UPDATE, DELETE, DROP, UNION, TRUNCATE, ALTER, and CREATE surrounded by word boundaries (\b) to ensure that the matched word is not part of a larger word. The /i flag makes the match case-insensitive.
        '/\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|TRUNCATE|ALTER|CREATE)\b/i',




        //This pattern matches SQL keywords, functions and operators followed by any number of characters that are not line breaks, and then /*. Note that this pattern assumes that the /* occurs after the SQL keywords and before any line breaks. This pattern can be used to detect SQL injections that use long comments in the middle of the query to bypass filters or to obfuscate the injection.
        //'/\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|ORDER BY|GROUP BY|JOIN|AND|OR|\*|COUNT\(|SUM\(|AVG\(|MAX\(|MIN\()([^\r\n]*)\/\*/i'
    /***'/select\s.*?\sfrom\s/i', 
        '/insert\sinto\s/i',
        '/update\s.*?\sset\s/i',
        '/delete\sfrom\s/i',
        '/or\s.+/i',
        '/and\s.+/i',
        '/union\s.+/i',
        '/exec\s.+/i',
        '/xp_cmdshell\s/i',
        '/sp_executesql\s/i',
        '/create\s.+\sprocedure\s/i',
        '/declare\s.+\s@\w+\s/i',
        '/xp_regwrite\s/i',
        '/xp_regdelete\s/i',
        "/('\s*OR\s+1\s*=\s*1\s*--)/i"
    */  
    );


    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $input)) {
            log_sqli($string);
            return true;
        }
    }

    return false;
}    /***                  
    if (preg_match($pattern, $string)) {
        // SQLi detected
        log_sqli($string);
        return true;
    }


    return false;
} ***/
function remove_whitespace($text) {
    // Removes all whitespace characters from a string
    return preg_replace('/\s+/', '', $text);
    //print($text);
}

// note server side
?>
