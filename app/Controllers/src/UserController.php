<?php

namespace Controllers\src;

use Controllers\SecureController;
use Models\src\Services\EncryptionService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Get;
use Zephyrus\Network\Router\Post;
use Models\src\Brokers\AuthBroker;

class UserController extends SecureController
{
    #[Get('/me')]
    public function me(): Response
    {
        $auth = $this->getAuth();
        $user = new AuthBroker()->findById($auth['user_id'], $auth['user_key']);

        return $user
            ? $this->json($user)
            : $this->abortNotFound("Utilisateur introuvable.");
    }

    #[Post('/logout')]
    public function logout(): Response
    {
        EncryptionService::destroySession();

        return $this->json([
            "message" => "Déconnexion réussie"
        ]);
    }
}
