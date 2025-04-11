<?php

namespace Controllers\src;

use Controllers\SecureController;
use Controllers\src\Utils\SessionHelper;
use Models\src\Services\PasswordService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Get;
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

        if ($isHtmx) {
            return $this->render("fragments/passwords/passwordUnlockForm", [
                'form' => $result['form'],
                'isHtmx' => true,
                'passwordsUnlocked' => false
            ]);
        }

        if (isset($result['errors'])) {
            return $this->render("secure/dashboard", [
                'form' => $result['form'],
                'passwords' => [],
                'passwordsUnlocked' => false,
                'activeSection' => 'passwords',
                'tab' => 'list'
            ]);
        }

        SessionHelper::appendContext([
            'passwords' => $result['passwords'],
            'passwordsUnlocked' => true,
            'activeSection' => 'passwords',
            'tab' => 'list'
        ]);

        return $this->redirect("/dashboard?section=passwords");
    }

    #[Post('/addpassword')]
    public function addPassword(): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();
        $result = $this->passwordService->addPassword($form, $isHtmx);

        if ($isHtmx) {
            return $this->render("fragments/passwords/passwordAddForm", [
                'form' => $result['form'],
                'isHtmx' => true
            ]);
        }

        if (isset($result['errors'])) {
            SessionHelper::appendContext([
                'form' => $result['form'],
                'activeSection' => 'passwords',
                'tab' => 'add'
            ]);
            return $this->render("secure/dashboard", SessionHelper::getContext());
        }

        SessionHelper::appendContext([
            'passwords' => $result['passwords'],
            'passwordsUnlocked' => true,
            'activeSection' => 'passwords',
            'tab' => 'list'
        ]);

        return $this->redirect("/dashboard?section=passwords");
    }

    #[Post('/password/{id}')]
    public function updatePassword(string $id): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();
        $result = $this->passwordService->updatePassword($form, $id, $isHtmx);

        if ($isHtmx) {
            return $this->render("fragments/passwords/passwordUpdateForm", [
                'form' => $result['form'],
                'password' => $result['password'],
                'isHtmx' => true
            ]);
        }

        if (isset($result['errors'])) {
            SessionHelper::appendContext([
                'form' => $result['form'],
                'activeSection' => 'passwords',
                'tab' => 'list'
            ]);
            return $this->render("secure/dashboard", SessionHelper::getContext());
        }

        SessionHelper::appendContext([
            'passwords' => $result['passwords'],
            'passwordsUnlocked' => true,
            'activeSection' => 'passwords',
            'tab' => 'list'
        ]);

        return $this->redirect("/dashboard?section=passwords");
    }

    #[Post('/password/{id}/delete')]
    public function deletePassword(string $id): Response
    {
        $form = $this->buildForm();
        $result = $this->passwordService->deletePassword($form, $id);

        SessionHelper::appendContext([
            'passwords' => $result['passwords'],
            'passwordsUnlocked' => true,
            'activeSection' => 'passwords',
            'tab' => 'list'
        ]);

        return $this->redirect("/dashboard?section=passwords");
    }

}
