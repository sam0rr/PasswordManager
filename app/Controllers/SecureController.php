<?php

namespace Controllers;

use Models\src\Services\AuthHistoryService;
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
        $authHistoryService = new AuthHistoryService($this->getAuth());

        $this->currentUserKey = EncryptionService::getUserKeyFromContext();
        $this->currentUserId = EncryptionService::getUserIdFromContext();

        if (is_null($this->currentUserKey) || is_null($this->currentUserId)) {
            return $this->redirect("/login");
        }

        if ($authHistoryService->hasTooManyAttempts($this->currentUserId)) {
            EncryptionService::destroySession();
            return $this->redirect("/login?error=too_many_attempts");
        }

        return parent::before();
    }

}
