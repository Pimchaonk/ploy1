<?php
// D:\BPT\layer\detect-sqli.php
// Define a list of suspicious words and phrases
//This code is optimize
//simple word base tokenization with tire algorithm
require_once('../connect.php');
require_once('log-sqli.php');
$suspicious_words = array(
    "SELECT", "FROM", "WHERE", "DROP", "TABLE", "INSERT", "UPDATE",
    "DELETE", "OR", "AND", "UNION", "ALL", "EXEC", "INTO", "VALUES",
    "DECLARE", "EXECUTE", "DECLARE", "CURSOR", "FETCH", "FOR", "OPEN",
    "CLOSE", "COMMIT", "ROLLBACK", "BEGIN", "TRANSACTION", "COMPUTE",
    "BACKUP", "RESTORE",
);

// Convert the suspicious words into a trie data structure
function build_trie($suspicious_words) {
    $trie = array();
    foreach ($suspicious_words as $word) {
        $node = &$trie;
        $length = strlen($word);
        for ($i = 0; $i < $length; $i++) {
            $char = $word[$i];
            if (!isset($node[$char])) {
                $node[$char] = array();
            }
            $node = &$node[$char];
        }
        $node['end'] = true;
    }
    return $trie;
}

// Check for SQL injection attacks in the input using a trie data structure
function detect_sqli_trie($input_string, $trie) {
    $input_string = strtoupper($input_string);
    $length = strlen($input_string);
    $node = &$trie;
    for ($i = 0; $i < $length; $i++) {
        $char = $input_string[$i];
        if (!isset($node[$char])) {
            return false;
        }
        $node = &$node[$char];
        if (isset($node['end'])) {
            log_sqli($input_string);
            return true;
        }
    }
    return false;
}

// Build the trie data structure
$trie = build_trie($suspicious_words);

// Check for SQL injection attacks in the input
function detect_sqli($input_string) {
    global $trie;
    if( detect_sqli_trie($input_string, $trie)==true);
    {
        log_sqli($input_string);
        return true;
    }
    return false;
}
/*** 
Yes, there are other ways to perform word-based tokenization without relying on pre-defined suspicious words. Here are a few approaches:

    1)Use machine learning: You can train a machine learning model on a large dataset of SQL queries, where some queries are labeled as safe and some as malicious. The model can then learn to classify new queries as safe or malicious based on their patterns and features.
    
    2)Use statistical analysis: You can analyze the statistical properties of SQL queries to detect anomalies that may indicate a malicious query. For example, a malicious query may have an unusually high frequency of certain keywords or characters.
    
    3)Use syntax analysis: You can parse the syntax of SQL queries to detect anomalies that may indicate a malicious query. For example, a malicious query may have a syntactically incorrect WHERE clause or an incorrect number of arguments in a function call.
    
    4)Use semantic analysis: You can analyze the meaning of SQL queries to detect anomalies that may indicate a malicious query. For example, a malicious query may have a WHERE clause that is logically inconsistent or that violates the data schema.
    
    These approaches may require more advanced techniques and may be more computationally expensive than simple word-based tokenization, but they can be more accurate and flexible in detecting various types of SQL injection attacks.
    */
?>

