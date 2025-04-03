<?php

namespace Controllers;

use Zephyrus\Application\Controller;
use Zephyrus\Network\Response;
use Models\src\Services\EncryptionService;

abstract class SecureController extends Controller
{
    protected ?string $currentUserId = null;
    protected ?string $currentUserKey = null;

    public function before(): ?Response
    {
        $encryptionService = new EncryptionService();

        $this->currentUserKey = $encryptionService->getUserKeyFromContext();
        $this->currentUserId = $encryptionService->getUserIdFromContext();

        if (is_null($this->currentUserKey) || is_null($this->currentUserId)) {
            return $this->abortUnauthorized("Session invalide ou expirée.");
        }

        return parent::before();
    }
}
