<?php

namespace Models\src\Entities;

use Models\Core\Entity;

class EmailToken extends Entity
{
    public string $id;
    public string $userId;
    public string $token;
    public string $expiresAt;
    public bool $isUsed;
    public string $createdAt;
}
