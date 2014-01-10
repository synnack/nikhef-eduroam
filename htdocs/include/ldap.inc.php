<?php
/* 
 * EAP-TLS automatic provision service
 * LDAPAuthenticatedUser class
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
 */
class LdapAuthenticatedUser {
    public static $authenticated;
    public static $expiry_date;
    public static $error;

    private function ldap_escape ($str = '') {

        $metaChars = array ("\x00", "\\", "(", ")", "*");
        $quotedMetaChars = array ();
        foreach ($metaChars as $key => $value) {
            $quotedMetaChars[$key] = '\\'. dechex (ord ($value));
        }
        $str = str_replace (
            $metaChars, $quotedMetaChars, $str
        );
        return ($str);
    }

    function __construct($username, $password) {
        $this->authenticated = false;
        $this->expirydate = 0;
        $this->error = null;

        /* Connect to LDAP */
        $ldap = ldap_connect(LDAP_HOST, LDAP_PORT);
        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);

        /* Retry bind up to 10 times. */
        for ($i = 0; $i < 10 && !($rv = @ldap_bind($ldap)); $i++) sleep(1);
        if (!$rv) {
			$this->error ="Anonymous bind failed";
            return;
        }

        /* Look for the user */
        $res = ldap_search($ldap, LDAP_BASE, "(&(objectclass=posixAccount)(uid=".$this->ldap_escape($_POST['username'])."))");
        $entries = ldap_get_entries($ldap, $res);
        if ($entries['count'] != 1) {
			$this->error ="Incorrect entry count";
            return;
        }

        /* Close the old LDAP connection */
        ldap_close($ldap);
        unset($ldap);

        /* Reconnect and bind as supplied user */
        $ldap = ldap_connect(LDAP_HOST, LDAP_PORT);
        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
        for ($i = 0; $i < 10 && !($rv = @ldap_bind($ldap, $entries[0]['dn'], $_POST['password'])); $i++) sleep(1);
        if (!$rv) {
    		$this->error ="Failed to bind as user.";
            return;
        }

        /* Check if the user has the right attributes */
        $res = ldap_search($ldap, LDAP_BASE, 
                "(&(objectclass=posixAccount)(uid=".$this->ldap_escape($_POST['username'])."))");
        $entries = ldap_get_entries($ldap, $res);
        if ($entries['count'] != 1) {
			$this->error ="Incorrect entry count";
            return;
        }
        if (!in_array("schacuserstatus", $entries[0]) || 
                !in_array("urn:mace:terena.org:schac:userStatus:nikhef.nl:affiliation:active", 
                        $entries[0]['schacuserstatus'])) {
            $this->error = "User is not active.";
            return;
        }
        if (!in_array("edupersonaffiliation", $entries[0]) || 
                !in_array("member", $entries[0]['edupersonaffiliation'])) {
            $this->error = "User is not a member.";
            return;
        }
        if (!in_array("schacexpirydate", $entries[0]) || 
                !($ts = strptime($entries[0]['schacexpirydate'][0], "%Y%m%d%H%M%SZ")) ||
                !($expiry_date = gmmktime($ts['tm_hour'], $ts['tm_min'], $ts['tm_sec'], 
                        $ts['tm_mon'] + 1, $ts['tm_mday'], $ts['tm_year'] + 1900))) {
            $this->error = "User has invalid expiry date";
            return;
        }
        $this->authenticated = true;
        $this->expiry_date = $expiry_date;
    }    
}
