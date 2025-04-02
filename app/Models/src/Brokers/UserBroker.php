<?php

namespace Models\src\Brokers;

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
            $data['mfa_end'] ?? new \DateTime()->format('c')
        ]);

        return User::build($result);
    }

    public function findByEmail(string $email): ?User
    {
        $emailHash = $this->encryptionService->hash256($email);
        $result = $this->selectSingle("SELECT * FROM users WHERE email_hash = ?", [$emailHash]);
        return User::build($result);
    }

    public function emailExists(string $email): bool
    {
        $emailHash = $this->encryptionService->hash256($email);
        return (bool) $this->selectSingle("SELECT 1 FROM users WHERE email_hash = ?", [$emailHash]);
    }
}
