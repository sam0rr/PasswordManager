<?php

namespace Controllers\src;

use Controllers\SecureController;
use Controllers\src\Utils\SessionHelper;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Post;

class SharingController extends SecureController
{
    #[Post('/share/{id}')]
    public function sharePassword(string $id): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();
        $result = $this->base->sharing->sharePassword($form, $id, $isHtmx);

        SessionHelper::setForm("share_$id", $result['form']);

        if ($isHtmx) {
            return $this->render("fragments/passwords/passwordShareForm", [
                'form' => $result['form'],
                'password' => $result['password'],
                'isHtmx' => true
            ]);
        }

        if (isset($result['errors'])) {
            SessionHelper::append([
                'activeSection' => 'shares',
                'tab' => 'send'
            ]);
            return $this->redirect("/dashboard?section=shares");
        }

        $shares = $this->base->sharing->getAllShares($form);
        $this->setSharingContext($shares);
        SessionHelper::clearForm("share_$id");
        return $this->redirect("/dashboard?section=shares");
    }

    #[Post('/share/{id}/delete')]
    public function deleteShare(string $id): Response
    {
        $form = $this->buildForm();
        $this->base->sharing->deleteShare($id, $form);

        $shares = $this->base->sharing->getAllShares($form);
        $this->setSharingContext($shares);
        return $this->redirect("/dashboard?section=shares");
    }

    private function setSharingContext(array $shares): void
    {
        SessionHelper::append([
            'shared_credentials' => $shares,
            'activeSection' => 'shares',
            'tab' => 'list'
        ]);
    }

}
