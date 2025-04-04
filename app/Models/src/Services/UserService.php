<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Brokers\UserBroker;
use Models\src\Entities\User;
use Models\src\Validators\UserValidator;
use Zephyrus\Application\Form;

class UserService
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
        $userId = $this->auth['user_id'];
        $userKey = $this->auth['user_key'];

        return $this->userBroker->findById($userId, $userKey);
    }

    public function getCurrentUser(): ?array
    {
        $userId = $this->auth['user_id'];
        $userKey = $this->auth['user_key'];

        $user = $this->userBroker->findById($userId, $userKey);
        if (!$user) {
            return null;
        }

        return [
            'id'          => $user->id,
            'email'       => $user->email,
            'first_name'  => $user->first_name,
            'last_name'   => $user->last_name,
            'phone'       => $user->phone,
            'image_url'   => $user->image_url,
            'mfa'         => $user->mfa,
            'mfa_end'     => $user->mfa_end,
            'created_at'  => $user->created_at,
            'updated_at'  => $user->updated_at
        ];
    }

    public function updateUser(Form $form): array
    {
        try {
            UserValidator::assertUpdate($form, $this->userBroker, $this->auth['user_id']);

            $userId = $this->auth['user_id'];
            $userKey = $this->auth['user_key'];

            $updates = [];

            foreach (['first_name', 'last_name', 'email', 'phone', 'image_url'] as $field) {
                if ($form->getValue($field)) {
                    $updates[$field] = $this->encryption->encryptWithUserKey($form->getValue($field), $userKey);

                    if ($field === 'email') {
                        $updates['email_hash'] = $this->encryption->hash256($form->getValue('email'));
                    }
                }
            }

            if ($form->getValue('password')) {
                $updates['password_hash'] = $this->encryption->hash256($form->getValue('password'));
            }

            $user = $this->userBroker->findById($userId, $userKey);

            return [
                "status" => 200,
                "message" => "Profil mis à jour avec succès.",
                "user" => [
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
                ]
            ];
        } catch (FormException) {
            return [
                "status" => 400,
                "errors" => $form->getErrorMessages(),
                "form" => $form
            ];
        }
    }

}
