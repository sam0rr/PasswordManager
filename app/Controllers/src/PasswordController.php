<?php

namespace Controllers\src;

use Controllers\SecureController;
use Models\src\Services\PasswordService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Post;

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
}
