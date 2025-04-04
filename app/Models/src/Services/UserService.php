<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Brokers\UserBroker;
use Models\src\Entities\User;
use Models\src\Validators\UserValidator;
use Zephyrus\Application\Form;

class UserService extends BaseService
{
    private UserBroker $userBroker;
    private array $auth;
    private EncryptionService $encryption;

    public function __construct(array $auth)
    {
        $this->auth = $auth;
        $this->userBroker = new UserBroker();
        $this->encryption = new EncryptionService();
    }

    public function getCurrentUserEntity(): ?User
    {
        return $this->userBroker->findById($this->auth['user_id'], $this->auth['user_key']);
    }

    public function getCurrentUser(): ?array
    {
        $user = $this->getCurrentUserEntity();
        return $user ? $this->buildUserResponse($user) : null;
    }

    public function updateUser(Form $form): array
    {
        try {
            UserValidator::assertUpdate($form, $this->userBroker, $this->auth['user_id']);

            $updates = $this->buildEncryptedUpdateData($form);
            $this->userBroker->updateUser($this->auth['user_id'], $updates);
            $user = $this->getCurrentUserEntity();

            return $this->buildSuccessUpdateResponse($user);
        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    // Helpers

    private function buildEncryptedUpdateData(Form $form): array
    {
        $data = [];
        $key = $this->auth['user_key'];

        foreach (['first_name', 'last_name', 'email', 'phone', 'image_url'] as $field) {
            if ($form->getValue($field)) {
                $data[$field] = $this->encryption->encryptWithUserKey($form->getValue($field), $key);
                if ($field === 'email') {
                    $data['email_hash'] = $this->encryption->hash256($form->getValue('email'));
                }
            }
        }

        if ($form->getValue('password')) {
            $data['password_hash'] = $this->encryption->hash256($form->getValue('password'));
        }

        return $data;
    }

    private function buildSuccessUpdateResponse(User $user): array
    {
        return [
            "status" => 200,
            "message" => "Profil mis à jour avec succès.",
            "user" => $this->buildUserResponse($user)
        ];
    }

    private function buildUserResponse(User $user): array
    {
        return [
            "id" => $user->id,
            "email" => $user->email,
            "first_name" => $user->first_name,
            "last_name" => $user->last_name,
            "phone" => $user->phone,
            "image_url" => $user->image_url,
            "mfa" => $user->mfa,
            "mfa_end" => $user->mfa_end,
            "created_at" => $user->created_at,
            "updated_at" => $user->updated_at
        ];
    }
}
