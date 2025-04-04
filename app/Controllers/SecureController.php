<?php

namespace Controllers;

use Zephyrus\Application\Controller;
use Zephyrus\Network\Response;
use Models\src\Services\EncryptionService;

abstract class SecureController extends Controller
{
    protected ?string $currentUserId = null;
    protected ?string $currentUserKey = null;

    public function getAuth(): array
    {
        return ["user_id" => $this->currentUserId, "user_key" => $this->currentUserKey];
    }

    public function before(): ?Response
    {
        $encryptionService = new EncryptionService();

        $this->currentUserKey = $encryptionService->getUserKeyFromContext();
        $this->currentUserId = $encryptionService->getUserIdFromContext();

        if (is_null($this->currentUserKey) || is_null($this->currentUserId)) {
            return $this->redirect("/login");
        }

        return parent::before();
    }
}
