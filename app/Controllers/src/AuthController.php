<?php

namespace Controllers\src;

use Controllers\SecureController;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Get;
use Zephyrus\Network\Router\Post;
use Zephyrus\Core\Session;
use Models\src\Brokers\UserBroker;
use Models\src\Services\EncryptionService;

class AuthController extends SecureController
{
    #[Get('/me')]
    public function me(): Response
    {
        $encryptionService = new EncryptionService();
        $userKey = $encryptionService->getUserKeyFromContext();
        $userId = $encryptionService->getUserIdFromContext();

        if (is_null($userKey) || is_null($userId)) {
            return $this->abortUnauthorized("Session invalide.");
        }

        $userBroker = new UserBroker();
        $user = $userBroker->findById($userId);

        if (!$user) {
            return $this->abortNotFound("Utilisateur introuvable.");
        }

        return $this->json([
            'id' => $user->id,
            'email' => $encryptionService->decryptWithUserKey($user->email, $userKey),
            'first_name' => $encryptionService->decryptWithUserKey($user->first_name, $userKey),
            'last_name' => $encryptionService->decryptWithUserKey($user->last_name, $userKey),
            'phone' => $encryptionService->decryptWithUserKey($user->phone, $userKey),
            'image_url' => $encryptionService->decryptWithUserKey($user->image_url, $userKey),
        ]);
    }

    #[Post('/logout')]
    public function logout(): Response
    {
        Session::remove('user_context');

        return $this->json([
            "message" => "Déconnexion réussie"
        ]);
    }
}
