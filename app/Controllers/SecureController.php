<?php

namespace Controllers;

use Controllers\src\Utils\SessionHelper;
use Models\src\Services\AuthHistoryService;
use Models\src\Services\Utils\BaseService;
use Zephyrus\Network\Response;
use Models\src\Services\EncryptionService;

abstract class SecureController extends Controller
{
    private ?string $currentUserId = null;
    private ?string $currentUserKey = null;

    protected ?BaseService $base = null;
    private ?AuthHistoryService $authHistoryService = null {
        get {
            return $this->authHistoryService ??= new AuthHistoryService($this->getAuth());
        }
    }

    public function getAuth(): array
    {
        return ["user_id" => $this->currentUserId, "user_key" => $this->currentUserKey];
    }

    public function before(): ?Response
    {
        $this->currentUserKey = EncryptionService::getUserKeyFromContext();
        $this->currentUserId = EncryptionService::getUserIdFromContext();

        if (is_null($this->currentUserKey) || is_null($this->currentUserId)) {
            return $this->redirect("/login");
        }

        if ($this->authHistoryService->hasTooManyAttempts($this->currentUserId)) {
            EncryptionService::destroySession();
            return $this->redirect("/login?error=too_many_attempts");
        }

        $this->base = new BaseService($this->getAuth());

        if (!SessionHelper::get('mfa_validated') && !$this->base->verify->areAllMethodsVerified()) {
            return $this->redirect('/verify-mfa');
        }

        return parent::before();
    }

}
