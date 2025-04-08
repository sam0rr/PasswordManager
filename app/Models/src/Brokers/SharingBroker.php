<?php

namespace Models\src\Brokers;

use Models\src\Entities\PasswordSharing;
use Zephyrus\Database\DatabaseBroker;

class SharingBroker extends DatabaseBroker
{
    public function insertSharing(array $data): PasswordSharing
    {
        $sql = "
        INSERT INTO password_sharing (
            encrypted_password,
            encrypted_description,
            encrypted_email_from,
            owner_id,
            shared_id,
            status,
            expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        RETURNING *;
    ";

        $row = $this->selectSingle($sql, [
            $data['encrypted_password'],
            $data['encrypted_description'],
            $data['encrypted_email_from'],
            $data['owner_id'],
            $data['shared_id'],
            $data['status'] ?? 'pending',
            $data['expires_at']
        ]);

        return PasswordSharing::build($row);
    }

    public function findById(string $id): ?PasswordSharing
    {
        $row = $this->selectSingle("SELECT * FROM password_sharing WHERE id = ?", [$id]);
        return $row ? PasswordSharing::build($row) : null;
    }

    public function isAlreadyShared(string $ownerId, string $sharedId, string $descriptionHash): bool
    {
        $sql = "
            SELECT ps.*
            FROM password_sharing ps
            JOIN user_password up ON up.user_id = ps.owner_id
            WHERE ps.owner_id = ?
              AND ps.shared_id = ?
              AND up.description_hash = ?
        ";

        return $this->selectSingle($sql, [$ownerId, $sharedId, $descriptionHash]) !== null;
    }

    public function findPendingSharesForUser(string $userId): array
    {
        $sql = "SELECT * FROM password_sharing WHERE shared_id = ? AND status = 'pending'";
        $rows = $this->select($sql, [$userId]);

        return array_map(fn($row) => PasswordSharing::build($row), $rows);
    }

    public function findAllSharesByOwner(string $ownerId, ?string $status = null): array
    {
        if ($status !== null) {
            $sql = "SELECT * FROM password_sharing WHERE owner_id = ? AND status = ? ORDER BY created_at DESC";
            $rows = $this->select($sql, [$ownerId, $status]);
        } else {
            $sql = "SELECT * FROM password_sharing WHERE owner_id = ? ORDER BY created_at DESC";
            $rows = $this->select($sql, [$ownerId]);
        }

        return array_map(fn($row) => PasswordSharing::build($row), $rows);
    }

    public function markAsSuccess(string $shareId): ?PasswordSharing
    {
        $sql = "UPDATE password_sharing SET status = 'success' WHERE id = ? RETURNING *";
        $row = $this->selectSingle($sql, [$shareId]);
        return PasswordSharing::build($row);
    }

    public function markAsFailed(string $shareId): ?PasswordSharing
    {
        $sql = "UPDATE password_sharing SET status = 'fail' WHERE id = ? RETURNING *";
        $row = $this->selectSingle($sql, [$shareId]);
        return PasswordSharing::build($row);
    }

    public function deleteShare(string $shareId): bool
    {
        $sql = "DELETE FROM password_sharing WHERE id = ?";
        $rowCount = $this->selectSingle($sql, [$shareId]);
        return $rowCount > 0;
    }
}
