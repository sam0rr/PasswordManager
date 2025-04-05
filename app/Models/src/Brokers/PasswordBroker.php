<?php

namespace Models\src\Brokers;

use Models\src\Entities\UserPassword;
use Models\src\Services\EncryptionService;
use Zephyrus\Database\DatabaseBroker;

class PasswordBroker extends DatabaseBroker
{
    private EncryptionService $encryption;

    public function __construct()
    {
        parent::__construct();
        $this->encryption = new EncryptionService();
    }

    public function findAllByUser(string $userId, ?string $userKey = null): array
    {
        $rows = $this->select(
            "SELECT * FROM user_passwords WHERE user_id = ? ORDER BY updated_at DESC",
            [$userId]
        );

        $passwords = array_map(fn($row) => UserPassword::build($row), $rows);

        if ($userKey) {
            $passwords = array_map(fn(UserPassword $password) => $this->decryptPassword($password, $userKey), $passwords);
        }

        return $passwords;
    }

    public function createPassword(array $data, ?string $userKey = null): ?UserPassword
    {
        $sql = "
            INSERT INTO user_passwords (user_id, description, description_hash, note, encrypted_password)
            VALUES (?, ?, ?, ?, ?)
            RETURNING *;
        ";

        $row = $this->selectSingle($sql, [
            $data['user_id'],
            $data['description'],
            $data['description_hash'],
            $data['note'],
            $data['encrypted_password']
        ]);

        $password = UserPassword::build($row);
        return ($userKey) ? $this->decryptPassword($password, $userKey) : $password;
    }

    public function descriptionExistsForUser(string $userId, string $description): bool
    {
        $hash = $this->encryption->hash256($description);
        $sql = "SELECT 1 FROM user_passwords WHERE user_id = ? AND description_hash = ?";
        return (bool) $this->selectSingle($sql, [$userId, $hash]);
    }

    private function decryptPassword(UserPassword $password, string $userKey): UserPassword
    {
        $password->description = $this->encryption->decryptWithUserKey($password->description, $userKey);
        $password->note = $this->encryption->decryptWithUserKey($password->note, $userKey);
        $password->encrypted_password = $this->encryption->decryptWithUserKey($password->encrypted_password, $userKey);
        return $password;
    }
}
