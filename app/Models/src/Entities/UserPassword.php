<?php

namespace Models\src\Entities;

use Models\Core\Entity;

class UserPassword extends Entity
{
    public string $id;
    public string $user_id;
    public string $description;
    public string $note;
    public string $password;
    public string $description_hash;
    public string $last_use;
    public string $created_at;
    public string $updated_at;
    public bool $verified;
}
