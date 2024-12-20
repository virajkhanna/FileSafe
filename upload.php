<?php

// Set error logging to a custom file
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/log.txt'); // Log file location

function log_message($message) {
    error_log($message); // Logs message to log.txt
}

function encrypt($filePath, $passwd) {
    log_message("Starting encryption process...");

    $content = file_get_contents($filePath);
    log_message("Original content length: " . strlen($content));

    $ivLen = openssl_cipher_iv_length('aes-256-cbc');
    $iv = openssl_random_pseudo_bytes($ivLen);
    log_message("Generated IV length: " . strlen($iv));

    $passkey = hash('sha256', $passwd, true);
    log_message("Generated key");

    $enc_content = openssl_encrypt($content, 'aes-256-cbc', $passkey, OPENSSL_RAW_DATA, $iv);
    log_message("Encrypted content length: " . strlen($enc_content));

    return $iv . $enc_content; // Append IV to the beginning
}

function decrypt($enc_file, $passwd) {
    log_message("Starting decryption process...");

    $ivLen = openssl_cipher_iv_length('aes-256-cbc'); 
    $iv = substr($enc_file, 0, $ivLen); // Extract IV
    $encryptedData = substr($enc_file, $ivLen); // Extract encrypted content

    log_message("Extracted IV length: " . strlen($iv));
    log_message("Encrypted data length: " . strlen($encryptedData));

    $key = hash('sha256', $passwd, true);
    log_message("Generated key");

    $decryptedData = openssl_decrypt($encryptedData, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);

    if ($decryptedData === false) {
        log_message("Decryption failed: " . openssl_error_string());
        return false;
    }

    log_message("Decryption successful. Decrypted content length: " . strlen($decryptedData));
    return $decryptedData;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if ($_FILES['file']['size'] > (10 * 1024 * 1024)) {
        die("Error: File exceeds the maximum allowed size of 10 MB! <a href='index.html'>Go back</a>");
    }

    if ($_POST['type'] == "Encrypt") {
        log_message("Received request to encrypt a file.");
        if (isset($_FILES['file']) && isset($_POST['password'])) {
            $file = $_FILES['file'];
            $password = $_POST['password'];
        }

        if ($file['error'] === UPLOAD_ERR_OK) {
            $filePath = $file['tmp_name'];
            $fileName = basename($file['name']);
            $targetDir = 'uploads/';

            if (!is_dir($targetDir)) {
                mkdir($targetDir, 0755, true);
                log_message("Created target directory: $targetDir");
            }

            log_message("Processing file: $filePath");

            $encryptedContent = encrypt($filePath, $password);

            $encryptedFileName = $targetDir . $fileName . '.enc';
            file_put_contents($encryptedFileName, $encryptedContent);
            log_message("Encrypted file saved: $encryptedFileName");

            unlink($filePath); // Delete uploaded file for security purposes
            log_message("Uploaded file deleted: $filePath");

            header('Content-Description: File Transfer'); 
            header('Content-Type: application/octet-stream'); 
            header('Content-Disposition: attachment; filename="' . basename($encryptedFileName) . '"'); 
            header('Expires: 0'); 
            header('Cache-Control: must-revalidate'); 
            header('Pragma: public'); 
            header('Content-Length: ' . filesize($encryptedFileName)); 

            flush();  
            readfile($encryptedFileName); 
            unlink($encryptedFileName); // Delete encrypted file for security purposes
            log_message("Encrypted file deleted: $encryptedFileName");
            exit();
        } else {
            log_message("File upload error: " . $file['error']);
        }
    }

    if ($_POST['type'] == "Decrypt") {
        log_message("Received request to decrypt a file.");
        if (isset($_FILES['file']) && isset($_POST['password'])) {
            $file = $_FILES['file'];
            $password = $_POST['password'];
        }

        if ($file['error'] === UPLOAD_ERR_OK) {
            $filePath = $file['tmp_name'];
            $fileName = basename($file['name']);
            $targetDir = 'uploads/';

            if (!is_dir($targetDir)) {
                mkdir($targetDir, 0755, true);
                log_message("Created target directory: $targetDir");
            }

            log_message("Processing file: $filePath");

            $enc_file_content = file_get_contents($filePath);
            log_message("Encrypted file content length: " . strlen($enc_file_content));

            $decryptedContent = decrypt($enc_file_content, $password);

            unlink($filePath); // Delete uploaded file for security purposes
            log_message("Encrypted file deleted: $filePath");

            if ($decryptedContent === false) {
                log_message("Decryption failed. Exiting.");
                die("Decryption failed. Check your password or file integrity. <a href='index.html'>Go back</a>");
            }

            $fileName = basename($fileName);

            $decryptedFileName = substr($targetDir . $fileName, 0, -4);
            file_put_contents($decryptedFileName, $decryptedContent);
            log_message("Decrypted file saved: $decryptedFileName");

            header('Content-Description: File Transfer'); 
            header('Content-Type: application/octet-stream'); 
            header('Content-Disposition: attachment; filename="' . basename($decryptedFileName) . '"'); 
            header('Expires: 0'); 
            header('Cache-Control: must-revalidate'); 
            header('Pragma: public'); 
            header('Content-Length: ' . filesize($decryptedFileName)); 

            flush();  
            readfile($decryptedFileName); 
            unlink($decryptedFileName); // Delete decrypted file for security purposes
            log_message("Decrypted file deleted: $decryptedFileName");
            exit();
        } else {
            log_message("File upload error: " . $file['error']);
        }
    }
}
?>
