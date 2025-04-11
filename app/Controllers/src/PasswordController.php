<?php

namespace Controllers\src;

use Controllers\SecureController;
use Controllers\src\Utils\SessionHelper;
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
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();
        $result = $this->passwordService->getPasswords($form, $isHtmx);

        SessionHelper::setForm('password_unlock', $result['form']);

        if ($isHtmx) {
            return $this->render("fragments/passwords/passwordUnlockForm", [
                'form' => $result['form'],
                'isHtmx' => true,
                'passwordsUnlocked' => false
            ]);
        }

        if (isset($result['errors'])) {
            $this->setPasswordContext([], false);
            return $this->redirect("/dashboard?section=passwords&tab=list");
        }

        $this->setPasswordContext($result['passwords']);
        SessionHelper::clearForm('password_unlock');
        return $this->redirect("/dashboard?section=passwords&tab=list");
    }

    #[Post('/addpassword')]
    public function addPassword(): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();
        $result = $this->passwordService->addPassword($form, $isHtmx);

        SessionHelper::setForm('password_add', $result['form']);

        if ($isHtmx) {
            return $this->render("fragments/passwords/passwordAddForm", [
                'form' => $result['form'],
                'isHtmx' => true
            ]);
        }

        if (isset($result['errors'])) {
            SessionHelper::appendContext([
                'passwordsUnlocked' => false,
                'activeSection' => 'passwords',
                'tab' => 'add'
            ]);
            return $this->redirect("/dashboard?section=passwords&tab=add");
        }

        $passwords = $this->passwordService->getAllUserPasswords($form);
        $this->setPasswordContext($passwords);
        SessionHelper::clearForm('password_add');
        return $this->redirect("/dashboard?section=passwords&tab=list");
    }

    #[Post('/password/{id}')]
    public function updatePassword(string $id): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();
        $result = $this->passwordService->updatePassword($form, $id, $isHtmx);

        SessionHelper::setForm("password_update_$id", $result['form']);

        if ($isHtmx) {
            return $this->render("fragments/passwords/passwordUpdateForm", [
                'form' => $result['form'],
                'password' => $result['password'],
                'isHtmx' => true
            ]);
        }

        if (isset($result['errors'])) {
            SessionHelper::appendContext([
                'passwordsUnlocked' => true,
                'password' => $result['password'] ?? null,
                'activeSection' => 'passwords',
                'tab' => 'list'
            ]);
            return $this->redirect("/dashboard?section=passwords&tab=list");
        }

        $passwords = $this->passwordService->getAllUserPasswords($form);
        $this->setPasswordContext($passwords);
        SessionHelper::clearForm("password_update_$id");
        return $this->redirect("/dashboard?section=passwords&tab=list");
    }

    #[Post('/password/{id}/delete')]
    public function deletePassword(string $id): Response
    {
        $form = $this->buildForm();
        $this->passwordService->deletePassword($form, $id);

        $passwords = $this->passwordService->getAllUserPasswords($form);
        $this->setPasswordContext($passwords);
        return $this->redirect("/dashboard?section=passwords&tab=list");
    }

    private function setPasswordContext(array $passwords, bool $unlocked = true): void
    {
        SessionHelper::appendContext([
            'passwords' => $passwords,
            'passwordsUnlocked' => $unlocked,
            'activeSection' => 'passwords',
            'tab' => 'list'
        ]);
    }
}
