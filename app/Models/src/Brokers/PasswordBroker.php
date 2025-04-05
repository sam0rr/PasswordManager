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

    public function findAllByUser(string $userId, string $userKey): array
    {
        $rows = $this->select(
            "SELECT * FROM user_passwords WHERE user_id = ? ORDER BY updated_at DESC",
            [$userId]
        );

        return array_map(fn($row) =>
        $this->decryptPassword(UserPassword::build($row), $userKey), $rows
        );
    }

    public function createPassword(array $data, string $userKey): ?UserPassword
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
        return $this->decryptPassword($password, $userKey);
    }

    public function updatePassword(string $passwordId, array $updates): ?UserPassword
    {
        if (empty($updates)) {
            return null;
        }

        $columns = [];
        $values = [];

        foreach ($updates as $column => $value) {
            $columns[] = "$column = ?";
            $values[] = $value;
        }

        $values[] = $passwordId;

        $sql = "UPDATE user_passwords SET " . implode(", ", $columns) . " WHERE id = ? RETURNING *";
        $result = $this->selectSingle($sql, $values);

        if (!$result) return null;

        return UserPassword::build($result);
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
