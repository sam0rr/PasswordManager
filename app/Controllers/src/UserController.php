<?php

namespace Controllers\src;

use Controllers\SecureController;
use Controllers\src\Utils\SessionHelper;
use Models\src\Services\EncryptionService;
use Models\src\Services\UserService;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router\Get;
use Zephyrus\Network\Router\Post;

class UserController extends SecureController
{
    private UserService $userService;

    public function before(): ?Response
    {
        $parentResponse = parent::before();
        if (!is_null($parentResponse)) {
            return $parentResponse;
        }

        $auth = $this->getAuth();
        $this->userService = new UserService($auth);

        return null;
    }

    #[Post('/user/update')]
    public function update(): Response
    {
        $isHtmx = $this->isHtmx();
        $form = $this->buildForm();
        $result = $this->userService->updateUser($form, $isHtmx);

        SessionHelper::setForm('user_update', $result['form']);

        if ($isHtmx) {
            return $this->render("fragments/profile/updateProfileForm", [
                'form' => $result['form'],
                'user' => $result['user'] ?? null,
                'isHtmx' => true
            ]);
        }

        if (isset($result["errors"])) {
            SessionHelper::appendContext([
                'user' => $result["user"] ?? null,
                'activeSection' => 'profile',
                'tab' => 'info'
            ]);
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

        $result = $this->userService->updateAvatar($form, $avatarFile);

        SessionHelper::setForm('user_avatar', $result['form']);

        if (isset($result["errors"])) {
            SessionHelper::appendContext([
                'user' => $this->userService->getCurrentUserEntity(),
                'activeSection' => 'profile',
                'tab' => 'info',
                'avatarError' => true
            ]);
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
        $result = $this->userService->updatePassword($form, $isHtmx);

        SessionHelper::setForm('user_password', $result['form']);

        if ($isHtmx) {
            return $this->render("fragments/profile/updatePasswordForm", [
                'form' => $result["form"],
                'isHtmx' => true
            ]);
        }

        if (isset($result["errors"])) {
            SessionHelper::appendContext([
                'user' => $result["user"] ?? null,
                'activeSection' => 'profile',
                'tab' => 'password'
            ]);
            return $this->redirect("/dashboard?section=profile&tab=password");
        }

        SessionHelper::clearForm('user_password');
        return $this->redirect("/dashboard?section=profile&tab=info");
    }

    #[Get('/logout')]
    public function logout(): Response
    {
        EncryptionService::destroySession();
        return $this->redirect("/login");
    }

}
