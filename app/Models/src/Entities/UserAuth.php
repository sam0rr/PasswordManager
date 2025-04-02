<?php

namespace Models\src\Entities;

use Models\Core\Entity;

class UserAuth extends Entity
{
    public string $id;
    public string $userId;
    public string $method;
    public bool $isActive;
    public string $otpSecret;
    public string $lastVerified;
    public string $createdAt;
    public string $updatedAt;
}
