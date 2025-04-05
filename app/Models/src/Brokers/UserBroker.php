<?php

namespace Models\src\Brokers;

use DateTime;
use Models\src\Entities\User;
use Models\src\Services\EncryptionService;
use Zephyrus\Database\DatabaseBroker;

class UserBroker extends DatabaseBroker
{
    private EncryptionService $encryptionService;

    public function __construct()
    {
        parent::__construct();
        $this->encryptionService = new EncryptionService();
    }

    public function createUser(array $data): ?User
    {
        $sql = "
            INSERT INTO users (
                first_name,
                last_name,
                email,
                phone,
                image_url,
                email_hash,
                password_hash,
                salt,
                mfa_end
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING *";

        $result = $this->selectSingle($sql, [
            $data['first_name'],
            $data['last_name'],
            $data['email'],
            $data['phone'],
            $data['image_url'],
            $data['email_hash'],
            $data['password_hash'],
            $data['salt'],
            $data['mfa_end'] ?? new DateTime()->format('c')
        ]);

        return User::build($result);
    }

    public function updateUser(string $userId, array $updates): ?User
    {
        if (empty($updates)) {
            return $this->findById($userId);
        }

        $columns = [];
        $values = [];

        foreach ($updates as $column => $value) {
            $columns[] = "$column = ?";
            $values[] = $value;
        }

        $values[] = $userId;

        $sql = "UPDATE users SET " . implode(", ", $columns) . " WHERE id = ? RETURNING *";
        $result = $this->selectSingle($sql, $values);

        return User::build($result);
    }

    public function findByEmail(string $email, ?string $userKey = null): ?User
    {
        $emailHash = $this->encryptionService->hash256($email);
        $result = $this->selectSingle("SELECT * FROM users WHERE email_hash = ?", [$emailHash]);

        if (!$result) return null;

        $user = User::build($result);
        return $userKey ? $this->decryptUser($user, $userKey) : $user;
    }

    public function findById(string $id, ?string $userKey = null): ?User
    {
        $result = $this->selectSingle("SELECT * FROM users WHERE id = ?", [$id]);

        if (!$result) return null;

        $user = User::build($result);
        return $userKey ? $this->decryptUser($user, $userKey) : $user;
    }

    public function emailExists(string $email): bool
    {
        $emailHash = $this->encryptionService->hash256($email);
        return (bool) $this->selectSingle("SELECT 1 FROM users WHERE email_hash = ?", [$emailHash]);
    }

    private function decryptUser(User $user, string $userKey): User
    {
        $user->first_name = $this->encryptionService->decryptWithUserKey($user->first_name, $userKey);
        $user->last_name = $this->encryptionService->decryptWithUserKey($user->last_name, $userKey);
        $user->email = $this->encryptionService->decryptWithUserKey($user->email, $userKey);
        $user->phone = $this->encryptionService->decryptWithUserKey($user->phone, $userKey);
        $user->image_url = $this->encryptionService->decryptWithUserKey($user->image_url, $userKey);
        return $user;
    }

}
