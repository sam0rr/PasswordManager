<?php

namespace Models\src\Entities;

use Models\Core\Entity;

class UserPassword extends Entity
{
    public string $id;
    public string $userId;
    public string $description;
    public string $note;
    public string $encryptedPassword;
    public string $lastUse;
    public string $createdAt;
    public string $updatedAt;
}
