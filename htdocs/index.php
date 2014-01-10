<?php
/* 
 * EAP-TLS automatic provision service
 * Main entropy point
 * 
 * Copyright (C) 2013 Wilco Baan Hofman, NIKHEF
 * 
 * This file is part of Nikhef Provision
 *
 * Nikhef Provision is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Nikhef Provision is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Nikhef Provision.  If not, see <http://www.gnu.org/licenses/>.
 *
 * TODO:
 * - Rate-limiting authentications 
 */

require("config.inc.php");
require("include/ldap.inc.php");
require("include/certificatestore.inc.php");

function exit_error($string) {
    global $file;
    fprintf($file, "%s\n", $string);
    fclose($file);
    header("200 OK");
    header("Content-Type: application/json");
    print json_encode(array(
        'status' => 'error',
        'error' => $string));
    die($string);
}

$file = fopen(LOG_FILE, "a");

/* Configuration checks */
$stat = stat(PRIVATE_KEY);
if ($stat['mode'] & 066) {
    fprintf($file, "Incorrect private key file permissions. Too permissive.\n");
    exit_error("Sanity check failed.");
}
if (strpos(PRIVATE_KEY, "/var/www") !== false) {
    fprintf($file, "Incorrect private key path. Probably public.\n");
    exit_error("Sanity check failed.");
}


/* Check incoming variables */
if (!array_key_exists('username', $_POST) ||
        !array_key_exists('password', $_POST) ||
        !array_key_exists('device_serial', $_POST) ||
        !array_key_exists('device_id', $_POST) ||
        !array_key_exists('device_description', $_POST) ||
        !array_key_exists('csr', $_POST)) {
    fprintf($file, "Missing fields.\n");
    exit_error("Sanity check failed.");
}

/* Log username */
if ($_POST['username']) {
    fprintf($file, "Got username: %s\n", $_POST['username']);
}

/* We can't check the CSR, so we sign it first with validity of 1 day, in memory only.. */
$tmpcrt = openssl_csr_sign($_POST['csr'], 
        "file://".CACERT, 
        "file://".PRIVATE_KEY, 
        1 /* 1 day */, 
        array("x509_extensions" => "usr_cert"));
$parsed = openssl_x509_parse($tmpcrt);
unset($tmpcrt);
if (array_key_exists('subjectAltName', $parsed['extensions'])) {
    fprintf($file, "subjectAltName exists.\n");
    exit_error("Sanity check failed.");
}
if (array_key_exists('basicConstraints', $parsed['extensions']) &&
        $parsed['extensions']['basicConstraints'] != "CA:FALSE") {
    fprintf($file, "basicConstraints invalid: %s\n", $parsed['extensions']['basicConstraints']);
    exit_error("Sanity check failed.");
}
$expected_cn = sprintf(CN_MATCH, $_POST['username']);
if ($parsed['subject']['CN'] != $expected_cn) {
    fprintf($file, "Subject mismatch: %s != %s\n", $parsed['subject']['CN'], $expected_cn);
    fprintf($file, "X509: %s\n", print_r($parsed, true));
    exit_error("Sanity check failed.");
}

/* Authenticate the user */
$user = new LdapAuthenticatedUser($_POST['username'], $_POST['password']);
if (!$user->authenticated) {
    fprintf($file, "Authentication failure for user %s from %s: %s\n", 
            $_POST['username'], 
            $_SERVER['REMOTE_ADDR'],
            $user->error);
    exit_error("Authentication failed.");
}


/* Make sure the certificate expires when the user expires, with a maximum of 3 years. */
$days = min(365 * 3, floor(($user->expiry_date - time()) / 86400));

/* Do Serial administration in database. */
$cs = new CertificateStore();
$serial = $cs->assign_serial($_POST['username'], 
                             $_POST['device_serial'], 
                             $_POST['device_id'], 
                             $_POST['device_description']);
if (!$serial) {
    exit_error("Certificate store couldn't assign serial.");
}

/* Sign the certificate */
$cert = openssl_csr_sign($_POST['csr'], 
        "file://".CACERT, 
        "file://".PRIVATE_KEY, 
        $days, 
        array('private_key_bits' => 2048, 
              'private_key_type' => OPENSSL_KEYTYPE_RSA,
              'x509_extensions' => 'usr_cert',
              'digest_alg' => 'sha256'),
        $serial);
if (!$cert) exit_error("Certificate signing failed.");

openssl_x509_export($cert, $certificate);
$rv = $cs->store($certificate, $user->expiry_date);

fprintf($file, "Signed Certificate:\n%s\n", $certificate);

/* Serialize a response in JSON */
header("Content-Type: application/json");
print json_encode(array(
    'status' => 'ok',
    'certificate' => $certificate,
    'ca_name' => CA_NAME,
    'ca' => CA,
    'subject_match' => SUBJECT_MATCH,
    'ssid' => SSID,
    'realm' => REALM));

fclose($file);
