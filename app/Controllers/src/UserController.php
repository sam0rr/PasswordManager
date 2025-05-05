<?php

namespace Controllers\src;

use Controllers\SecureController;
use Controllers\src\Utils\SessionHelper;
use Models\src\Services\Utils\Session\SessionContextService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Get;
use Zephyrus\Network\Router\Post;

final class UserController extends SecureController
{
    #[Post('/user/update')]
    public function update(): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();
        $result = $this->base->userService->updateUser($form, $isHtmx);

        SessionHelper::setForm('user_update', $result['form']);

        if ($isHtmx) {
            return $this->render("fragments/profile/updateProfileForm", [
                'form' => $result['form'],
                'isHtmx' => true
            ]);
        }

        if (isset($result["errors"])) {
            return $this->redirect("/dashboard?section=profile&tab=info");
        }

        SessionHelper::clearForm('user_update');
        return $this->redirect("/dashboard?section=profile&tab=info");
    }

    #[Post('/update-avatar')]
    public function updateAvatar(): Response
    {
        $form = $this->buildForm();
        $files = $this->request->getFiles();
        $avatarFile = $files['avatar'] ?? null;

        $result = $this->base->userService->updateAvatar($form, $avatarFile);

        SessionHelper::setForm('user_avatar', $result['form']);

        if (isset($result["errors"])) {
            return $this->redirect("/dashboard?section=profile&tab=info");
        }

        SessionHelper::clearForm('user_avatar');
        return $this->redirect("/dashboard?section=profile&tab=info");
    }

    #[Post('/user/password')]
    public function updatePassword(): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();
        $result = $this->base->userService->updatePassword($form, $isHtmx);

        SessionHelper::setForm('user_password', $result['form']);

        if ($isHtmx) {
            return $this->render("fragments/profile/updatePasswordForm", [
                'form' => $result["form"],
                'isHtmx' => true
            ]);
        }

        if (isset($result["errors"])) {
            return $this->redirect("/dashboard?section=profile&tab=password");
        }

        SessionHelper::clearForm('user_password');
        return $this->redirect("/dashboard?section=profile&tab=info");
    }

    #[Get('/logout')]
    public function logout(): Response
    {
        SessionContextService::destroy();
        return $this->redirect("/login");
    }

}
