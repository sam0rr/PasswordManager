<?php

namespace Models\src\Entities;

use Models\Core\Entity;

class CredidentialSharing extends Entity
{
    public string $id;
    public string $credentialId;
    public string $ownerId;
    public string $sharedId;
    public string $status;
    public string $expiresAt;
    public string $createdAt;
    public string $updatedAt;
}
