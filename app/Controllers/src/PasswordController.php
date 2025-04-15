<?php

namespace Controllers\src;

use Controllers\SecureController;
use Controllers\src\Utils\SessionHelper;
use Models\src\Services\Utils\SecurityService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Post;

class PasswordController extends SecureController
{
    #[Post('/addpassword')]
    public function addPassword(): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();
        $result = $this->base->passwordService->addPassword($form, $isHtmx);

        SessionHelper::setForm('password_add', $result['form']);

        if ($isHtmx) {
            return $this->render("fragments/passwords/passwordAddForm", [
                'form' => $result['form'],
                'isHtmx' => true
            ]);
        }

        if (isset($result['errors'])) {
            SessionHelper::append([
                'activeSection' => 'passwords',
                'tab' => 'add'
            ]);
            return $this->redirect("/dashboard?section=passwords&tab=add");
        }

        $passwords = $this->base->passwordService->getAllUserPasswords($form);
        $this->setPasswordContext($passwords);
        SessionHelper::clearForm('password_add');
        return $this->redirect("/dashboard?section=passwords&tab=list");
    }

    #[Post('/password/{id}')]
    public function updatePassword(string $id): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();
        $result = $this->base->passwordService->updatePassword($form, $id, $isHtmx);

        SessionHelper::setForm("password_update_$id", $result['form']);

        if ($isHtmx) {
            return $this->render("fragments/passwords/passwordUpdateForm", [
                'form' => $result['form'],
                'password' => $result['password'],
                'isHtmx' => true
            ]);
        }

        if (isset($result['errors'])) {
            SessionHelper::append([
                'password' => $result['password'] ?? null,
                'activeSection' => 'passwords',
                'tab' => 'list'
            ]);
            return $this->redirect("/dashboard?section=passwords&tab=list");
        }

        $passwords = $this->base->passwordService->getAllUserPasswords($form);
        $this->setPasswordContext($passwords);
        SessionHelper::clearForm("password_update_$id");
        return $this->redirect("/dashboard?section=passwords&tab=list");
    }

    #[Post('/password/{id}/delete')]
    public function deletePassword(string $id): Response
    {
        $form = $this->buildForm();
        $this->base->passwordService->deletePassword($form, $id);

        $passwords = $this->base->passwordService->getAllUserPasswords($form);
        $this->setPasswordContext($passwords);

        $analysis = SessionHelper::get('security_analysis', []);
        $fingerprints = SessionHelper::get('security_password_fingerprint', []);

        $filtered = SecurityService::filterOutPasswordFromAnalysis($id, $analysis, $fingerprints);

        SessionHelper::append([
            'security_analysis' => $filtered['analysis'],
            'security_password_fingerprint' => $filtered['fingerprintMap']
        ]);

        return $this->redirect("/dashboard?section=passwords&tab=list");
    }

    private function setPasswordContext(array $passwords): void
    {
        SessionHelper::append([
            'passwords' => $passwords,
            'activeSection' => 'passwords',
            'tab' => 'list'
        ]);
    }

}
