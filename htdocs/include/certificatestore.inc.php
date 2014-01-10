<?php
/* 
 * EAP-TLS automatic provision service
 * CertificateStore class
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
class CertificateStore extends PDO { 
	
	private $dsn; 
	private $user; 
	private $pass; 
    private $assigned_serial;

	public function __construct() { 
        $in_transaction = false;

		$this->user = SQL_USER; 
		$this->pass = SQL_PASS; 
		$this->dsn = SQL_DSN; 
		parent::__construct($this->dsn, $this->user, $this->pass); 
	} 

    public function assign_serial($username, $device_serial, $device_id, $device_description) {
        if (!$this->inTransaction()) {
            $this->beginTransaction();
        }
        $stm = $this->prepare("INSERT INTO certificates ".
                              "(id, username, device_serial, device_id, device_description, timestamp) VALUES ".
                               "(NULL, :username, :device_serial, :device_id, :device_description, NOW())");
        $stm->execute(array(":username" => $username, 
                            ":device_serial" => $device_serial,
                            ":device_id" => $device_id,
                            ":device_description" => $device_description));
        $this->assigned_serial = $this->lastInsertId();
        return $this->assigned_serial;
    }

    public function store($certificate, $expiry_date) {
        $stm = $this->prepare("UPDATE certificates SET certificate=:certificate, expires=:expiry_date WHERE id=:serial");
        $stm->execute(array(":certificate" => $certificate,
                            ":expiry_date" => gmstrftime("%Y-%m-%d %H:%M:%S", $expiry_date),
                            ":serial" => $this->assigned_serial));


        if ($this->inTransaction()) {
            $this->commit();
        }
    }

    public function __destruct() {
        if ($this->inTransaction()) {
            $this->rollBack();
        }
    }

}
?>
