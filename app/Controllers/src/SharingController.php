<?php

namespace Controllers\src;

use Controllers\SecureController;
use Controllers\src\Utils\SessionHelper;
use Models\src\Services\SharingService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Post;
use Zephyrus\Network\Router\Get;

class SharingController extends SecureController
{
    private ?SharingService $sharingService = null;

    public function before(): ?Response
    {
        $parentResponse = parent::before();
        if (!is_null($parentResponse)) {
            return $parentResponse;
        }

        $auth = $this->getAuth();
        $this->sharingService = new SharingService($auth);
        return null;
    }

    #[Post('/share/{id}')]
    public function sharePassword(string $id): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();
        $result = $this->sharingService->sharePassword($form, $id, $isHtmx);

        SessionHelper::setForm("share_$id", $result['form']);

        if ($isHtmx) {
            return $this->render("fragments/passwords/passwordShareForm", [
                'form' => $result['form'],
                'password' => $result['password'],
                'isHtmx' => true
            ]);
        }

        if (isset($result['errors'])) {
            SessionHelper::appendContext([
                'activeSection' => 'shares',
                'tab' => 'send'
            ]);
            return $this->redirect("/dashboard?section=shares");
        }

        $shares = $this->sharingService->getAllShares($form);
        $this->setSharingContext($shares);
        SessionHelper::clearForm("share_$id");
        return $this->redirect("/dashboard?section=shares");
    }

    #[Post('/share/{id}/delete')]
    public function deleteShare(string $id): Response
    {
        $form = $this->buildForm();
        $this->sharingService->deleteShare($id, $form);

        $shares = $this->sharingService->getAllShares($form);
        $this->setSharingContext($shares);
        return $this->redirect("/dashboard?section=shares");
    }

    private function setSharingContext(array $shares): void
    {
        SessionHelper::appendContext([
            'shared_credentials' => $shares,
            'activeSection' => 'shares',
            'tab' => 'list'
        ]);
    }
}
