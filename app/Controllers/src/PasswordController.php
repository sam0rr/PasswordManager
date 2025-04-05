<?php

namespace Controllers\src;

use Controllers\SecureController;
use Models\src\Services\PasswordService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Post;
use Zephyrus\Network\Router\Put;

class PasswordController extends SecureController
{
    private ?PasswordService $passwordService = null;

    public function before(): ?Response
    {
        $parentResponse = parent::before();
        if (!is_null($parentResponse)) {
            return $parentResponse;
        }

        $auth = $this->getAuth();
        $this->passwordService = new PasswordService($auth);
        return null;
    }

    #[Post('/passwords')]
    public function getPasswords(): Response
    {
        $form = $this->buildForm();
        $result = $this->passwordService->getPasswords($form);
        return $this->json($result);
    }

    #[Post('/addpassword')]
    public function addPassword(): Response
    {
        $form = $this->buildForm();
        $result = $this->passwordService->addPassword($form);
        return $this->json($result);
    }

    #[Put('/password/{id}')]
    public function updatePassword(string $id): Response
    {
        $form = $this->buildForm();
        $result = $this->passwordService->updatePassword($form, $id);
        return $this->json($result);
    }

    #[Post('/password/{id}/delete')]
    public function deletePassword(string $id): Response
    {
        $form = $this->buildForm();
        $result = $this->passwordService->deletePassword($form, $id);
        return $this->json($result);
    }
}
