<?php

namespace Models\src\Entities;

use Models\Core\Entity;

class User extends Entity
{
    public string $id;
    public string $first_name;
    public string $last_name;
    public string $email;
    public string $phone;
    public string $image_url;
    public string $email_hash;
    public string $password_hash;
    public string $salt;
    public int $mfa;
    public string $mfa_end;
    public string $created_at;
    public string $updated_at;
}
