<?php

namespace Models\src\Entities;

use Models\Core\Entity;

class User extends Entity
{
    public string $id;
    public string $firstName;
    public string $lastName;
    public string $email;
    public string $phone;
    public string $imageUrl;
    public string $emailHash;
    public string $passwordHash;
    public string $salt;
    public int $mfa;
    public string $mfaEnd;
    public string $createdAt;
    public string $updatedAt;
}
