<?php

namespace Models\src\Brokers;

use Models\src\Entities\PasswordSharing;
use Zephyrus\Database\DatabaseBroker;

class SharingBroker extends DatabaseBroker
{
    public function insertSharing(array $data): PasswordSharing
    {
        $row = $this->selectSingle(
            "INSERT INTO password_sharing (
                encrypted_password,
                owner_id,
                shared_id,
                public_key_hash,
                status,
                expires_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            RETURNING *;",
            [
                $data['encrypted_password'],
                $data['owner_id'],
                $data['shared_id'],
                $data['public_key_hash'],
                $data['status'] ?? 'pending',
                $data['expires_at']
            ]
        );

        return PasswordSharing::build($row);
    }

    public function isAlreadyShared(string $ownerId, string $sharedId, string $descriptionHash): bool
    {
        return $this->selectSingle(
                "SELECT ps.*
             FROM password_sharing ps
             JOIN user_password up ON up.user_id = ps.owner_id
             WHERE ps.owner_id = ? 
               AND ps.shared_id = ? 
               AND up.description_hash = ?;",
                [$ownerId, $sharedId, $descriptionHash]
            ) !== null;
    }
}
