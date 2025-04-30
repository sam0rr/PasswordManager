<?php

namespace Controllers;

use Controllers\src\Utils\SessionHelper;
use Models\src\Services\AuthHistoryService;
use Models\src\Services\Utils\BaseService;
use Models\src\Services\Utils\Session\SessionContextService;
use Zephyrus\Network\Response;

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
        $this->currentUserKey = SessionContextService::getUserKey();
        $this->currentUserId = SessionContextService::getUserId();

        $this->base = new BaseService($this->getAuth());

        if (is_null($this->currentUserKey) || is_null($this->currentUserId)) {
            return $this->redirect("/login");
        }

        if ($this->authHistoryService->hasTooManyAttempts($this->currentUserId)) {
            SessionContextService::destroy();
            return $this->redirect("/login?error=too_many_attempts");
        }

        if (!SessionHelper::get('mfa_validated') && !$this->isOnVerifyRoute()) {
            return $this->redirect('/verify-mfa');
        }

        return parent::before();
    }

    private function isOnVerifyRoute(): bool
    {
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        return str_starts_with($uri, '/verify');
    }

}
