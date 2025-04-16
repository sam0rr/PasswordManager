<?php

namespace Models\src\Brokers;

use Models\src\Entities\UserVerify;
use Models\src\Services\EncryptionService;
use Zephyrus\Database\DatabaseBroker;

class VerifyBroker extends DatabaseBroker
{
    private EncryptionService $encryption;

    public function __construct(EncryptionService $encryption)
    {
        parent::__construct();
        $this->encryption = $encryption;
    }

    public function findAllByUser(string $userId, string $userKey): array
    {
        $rows = $this->select("SELECT * FROM user_verify WHERE user_id = ?", [$userId]);
        return array_map(fn($row) => $this->decryptVerify(UserVerify::build($row), $userKey), $rows);
    }

    public function findByMethod(string $userId, string $method, string $userKey): ?UserVerify
    {
        $row = $this->selectSingle(
            "SELECT * FROM user_verify WHERE user_id = ? AND method = ?",
            [$userId, $method]
        );

        return $row ? $this->decryptVerify(UserVerify::build($row), $userKey) : null;
    }

    public function createMethod(array $data, string $userKey): ?UserVerify
    {
        $sql = "
        INSERT INTO user_verify (user_id, method, otp_secret, is_active, is_first_verified, otp_created_at, last_verified)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        RETURNING *;
    ";

        $row = $this->selectSingle($sql, [
            $data['user_id'],
            $data['method'],
            $data['otp_secret'],
            $data['is_active'],
            $data['is_first_verified'] ?? false,
            $data['otp_created_at'],
            $data['last_verified']
        ]);

        return $row ? $this->decryptVerify(UserVerify::build($row), $userKey) : null;
    }

    public function updateSecret(string $userId, string $method, string $otp): void
    {
        $this->query(
            "UPDATE user_verify SET otp_secret = ?, otp_created_at = CURRENT_TIMESTAMP WHERE user_id = ? AND method = ?",
            [$otp, $userId, $method]
        );
    }

    public function updateLastVerified(string $userId, string $method, string $userKey): ?UserVerify
    {
        $row = $this->selectSingle(
            "UPDATE user_verify SET last_verified = CURRENT_TIMESTAMP WHERE user_id = ? AND method = ? RETURNING *",
            [$userId, $method]
        );

        return $row ? $this->decryptVerify(UserVerify::build($row), $userKey) : null;
    }

    public function markFirstVerificationDone(string $userId, string $userKey): void
    {
        $this->query(
            "UPDATE user_verify SET is_first_verified = true WHERE user_id = ? AND method = 'authenticator'",
            [$userId]
        );
    }

    public function activate(string $userId, string $method, string $userKey): ?UserVerify
    {
        $row = $this->selectSingle(
            "UPDATE user_verify SET is_active = true WHERE user_id = ? AND method = ? RETURNING *",
            [$userId, $method]
        );

        return $row ? $this->decryptVerify(UserVerify::build($row), $userKey) : null;
    }

    public function deactivate(string $userId, string $method, string $userKey): ?UserVerify
    {
        if ($method === 'authenticator') {
            $row = $this->selectSingle(
                "UPDATE user_verify SET is_active = false, is_first_verified = false WHERE user_id = ? AND method = ? RETURNING *",
                [$userId, $method]
            );
        } else {
            $row = $this->selectSingle(
                "UPDATE user_verify SET is_active = false WHERE user_id = ? AND method = ? RETURNING *",
                [$userId, $method]
            );
        }

        return $row ? $this->decryptVerify(UserVerify::build($row), $userKey) : null;
    }

    private function decryptVerify(UserVerify $verify, string $userKey): UserVerify
    {
        $verify->otp_secret = $this->encryption->decryptWithUserKey($verify->otp_secret, $userKey);
        return $verify;
    }
}
