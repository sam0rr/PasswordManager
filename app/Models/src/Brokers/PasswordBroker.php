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
            "SELECT * FROM user_password WHERE user_id = ? ORDER BY updated_at DESC",
            [$userId]
        );

        return array_map(fn($row) =>
        $this->decryptPassword(UserPassword::build($row), $userKey), $rows
        );
    }

    public function findById(string $id, string $userKey): ?UserPassword
    {
        $row = $this->selectSingle("SELECT * FROM user_password WHERE id = ?", [$id]);
        if (!$row) return null;

        $password = UserPassword::build($row);
        return $this->decryptPassword($password, $userKey);
    }

    public function createPassword(array $data, string $userKey): ?UserPassword
    {
        $sql = "
            INSERT INTO user_password (user_id, description, description_hash, note, password)
            VALUES (?, ?, ?, ?, ?)
            RETURNING *;
        ";

        $row = $this->selectSingle($sql, [
            $data['user_id'],
            $data['description'],
            $data['description_hash'],
            $data['note'],
            $data['password']
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

        $sql = "UPDATE user_password SET " . implode(", ", $columns) . " WHERE id = ? RETURNING *";
        $result = $this->selectSingle($sql, $values);

        if (!$result) return null;

        return UserPassword::build($result);
    }

    public function deletePassword(string $passwordId): bool
    {
        $sql = "DELETE FROM user_password WHERE id = ?";
        $rowCount = $this->selectSingle($sql, [$passwordId]);
        return $rowCount > 0;
    }

    public function descriptionExistsForUser(string $userId, string $description): bool
    {
        $hash = $this->encryption->hash256($description);
        $sql = "SELECT 1 FROM user_password WHERE user_id = ? AND description_hash = ?";
        return (bool) $this->selectSingle($sql, [$userId, $hash]);
    }

    private function decryptPassword(UserPassword $password, string $userKey): UserPassword
    {
        $password->description = $this->encryption->decryptWithUserKey($password->description, $userKey);
        $password->note = $this->encryption->decryptWithUserKey($password->note, $userKey);
        $password->password = $this->encryption->decryptWithUserKey($password->password, $userKey);

        return $password;
    }
}
