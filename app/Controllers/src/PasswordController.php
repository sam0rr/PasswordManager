<?php

namespace Controllers\src;

use Controllers\SecureController;
use Controllers\src\Utils\SessionHelper;
use Models\src\Services\PasswordService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Delete;
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
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();

        $result = $this->passwordService->getPasswords($form, $isHtmx);

        SessionHelper::appendContext(['passwords' => $result]);
        return $this->json($result);
    }

    #[Post('/addpassword')]
    public function addPassword(): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();

        $result = $this->passwordService->addPassword($form, $isHtmx);

        $updated = $this->passwordService->getAllUserPasswords($form);
        SessionHelper::appendContext(['passwords' => $updated]);

        return $this->json($result);
    }

    #[Post('/password/{id}')]
    public function updatePassword(string $id): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();

        $result = $this->passwordService->updatePassword($form, $id, $isHtmx);

        $updated = $this->passwordService->getAllUserPasswords($form);
        SessionHelper::appendContext(['passwords' => $updated]);

        return $this->json($result);
    }

    #[Delete('/password/{id}/delete')]
    public function deletePassword(string $id): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();

        $result = $this->passwordService->deletePassword($form, $id, $isHtmx);

        $updated = $this->passwordService->getAllUserPasswords($form);
        SessionHelper::appendContext(['passwords' => $updated]);

        return $this->json($result);
    }
}
