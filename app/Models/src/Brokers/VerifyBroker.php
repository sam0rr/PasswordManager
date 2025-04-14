<?php

namespace Models\src\Brokers;

use Models\src\Entities\UserVerify;
use Zephyrus\Database\DatabaseBroker;

class VerifyBroker extends DatabaseBroker
{
    public function findActiveByUser(string $userId): array
    {
        $rows = $this->select("SELECT * FROM user_verify WHERE user_id = ? AND is_active = true", [$userId]);
        return array_map(fn($row) => UserVerify::build($row), $rows);
    }

    public function findByMethod(string $userId, string $method): ?UserVerify
    {
        $row = $this->selectSingle(
            "SELECT * FROM user_verify WHERE user_id = ? AND method = ?",
            [$userId, $method]
        );
        return $row ? UserVerify::build($row) : null;
    }

    public function createMethod(array $data): UserVerify
    {
        $sql = "
            INSERT INTO user_verify (user_id, method, otp_secret, is_active, last_verified)
            VALUES (?, ?, ?, true, CURRENT_TIMESTAMP)
            RETURNING *;
        ";

        $row = $this->selectSingle($sql, [
            $data['user_id'],
            $data['method'],
            $data['otp_secret']
        ]);

        return UserVerify::build($row);
    }

    public function updateSecret(string $userId, string $method, string $otp): void
    {
        $this->query(
            "UPDATE user_verify SET otp_secret = ? WHERE user_id = ? AND method = ?",
            [$otp, $userId, $method]
        );
    }

    public function updateLastVerified(string $userId, string $method): ?UserVerify
    {
        $row = $this->selectSingle(
            "UPDATE user_verify SET last_verified = CURRENT_TIMESTAMP WHERE user_id = ? AND method = ? RETURNING *",
            [$userId, $method]
        );
        return $row ? UserVerify::build($row) : null;
    }

    public function activate(string $userId, string $method): ?UserVerify
    {
        $row = $this->selectSingle(
            "UPDATE user_verify SET is_active = true WHERE user_id = ? AND method = ? RETURNING *",
            [$userId, $method]
        );
        return $row ? UserVerify::build($row) : null;
    }

    public function deactivate(string $userId, string $method): ?UserVerify
    {
        $row = $this->selectSingle(
            "UPDATE user_verify SET is_active = false WHERE user_id = ? AND method = ? RETURNING *",
            [$userId, $method]
        );
        return $row ? UserVerify::build($row) : null;
    }
}
