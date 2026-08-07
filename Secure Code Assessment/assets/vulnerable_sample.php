<?php

// HARDCODED CREDENTIALS
$db_host = "127.0.0.1";
$db_user = "root";
$db_pass = "SuperSecretPHPPass2026";
$secret_jwt_key = "a9f87b6c5d4e3f2a1";

// SQL INJECTION
if (isset($_GET['user_id'])) {
    $id = $_GET['user_id'];
    $conn = mysqli_connect($db_host, $db_user, $db_pass, "app_db");
    // Concatenating raw GET parameter directly into query
    $result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
}

// CROSS-SITE SCRIPTING (XSS)
if (isset($_POST['comment'])) {
    // Printing unsanitized HTML output directly to page
    echo "<div class='comment'>User says: " . $_POST['comment'] . "</div>";
}

// COMMAND INJECTION & DANGEROUS EXEC
if (isset($_GET['ip'])) {
    $ip = $_GET['ip'];
    // System execution of unsanitized IP parameter
    $output = passthru("ping -c 4 " . $ip);
    system("traceroute " . $ip);
}

// INSECURE FILE HANDLING / PATH TRAVERSAL
if (isset($_GET['page'])) {
    $page = $_GET['page'];
    // Including arbitrary file based on URL parameter
    include("pages/" . $page);
    echo file_get_contents("/var/www/data/" . $page);
}

// WEAK AUTHENTICATION & CRYPTOGRAPHY
function storeUserPassword($password) {
    // Insecure MD5 algorithm without salt
    $hashed = md5($password);
    return $hashed;
}

// DANGEROUS DESERIALIZATION
if (isset($_COOKIE['session_data'])) {
    // Unserialize untrusted cookie data
    $user_session = unserialize($_COOKIE['session_data']);
}

?>
