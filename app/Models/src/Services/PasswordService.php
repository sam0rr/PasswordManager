<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Brokers\PasswordBroker;
use Models\src\Brokers\UserBroker;
use Models\src\Entities\User;
use Models\src\Services\Utils\BaseService;
use Models\src\Validators\PasswordValidator;
use Zephyrus\Application\Form;

class PasswordService extends BaseService
{
    protected PasswordBroker $passwordBroker;
    protected UserBroker $userBroker;
    protected EncryptionService $encryption;

    public function __construct(array $auth)
    {
        $this->auth = $auth;
        $this->encryption = new EncryptionService();
        $this->passwordBroker = new PasswordBroker();
        $this->userBroker = new UserBroker();
    }

    public function getPasswords(Form $form, $isHtmx): array
    {
        try {
            PasswordValidator::assertPasswordVerification($form, $isHtmx);
            $user = $this->getVerifiedUser($form);

            if ($isHtmx) {
                return [
                    "form" => $form
                ];
            }

            $passwords = $this->passwordBroker->findAllByUser($user->id, $this->auth['user_key']);
            return [
                "form" => $form,
                "passwords" => $passwords
            ];

        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    public function getAllUserPasswords($form): array
    {
        try {
            return $this->passwordBroker->findAllByUser(
                $this->auth['user_id'],
                $this->auth['user_key']
            );
        } catch (FormException) {
            $form->addError("global", "Erreur lors du fetch des mots de passe.");
            throw new FormException($form);
        }
    }

    public function addPassword(Form $form, bool $isHtmx): array
    {
        try {
            PasswordValidator::assertAdd($form, $this->passwordBroker, $this->auth['user_id'], $isHtmx);

            if ($isHtmx) {
                return [
                    "form" => $form
                ];
            }

            $data = $this->buildEncryptedPasswordData($form);
            $this->passwordBroker->createPassword($data, $this->auth['user_key']);

            return [
                "form" => $form,
                "passwords" => $this->getAllUserPasswords($form)
            ];

        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    public function updatePassword(Form $form, string $id, bool $isHtmx): array
    {
        try {
            $password = $this->getPassword($id, $form);
            PasswordValidator::assertUpdate($form, $this->passwordBroker, $this->auth['user_id'], $password);

            if ($isHtmx) {
                return [
                    "form" => $form,
                    "passwords" => $this->getAllUserPasswords($form)
                ];
            }

            $updates = $this->buildEncryptedUpdateData($form);
            if (!empty($updates)) {
                $this->passwordBroker->updatePassword($id, $updates);
            }

            return [
                "form" => $form,
                "passwords" => $this->getAllUserPasswords($form)
            ];

        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    public function deletePassword(Form $form, string $id): array
    {
        try {
            $password = $this->getPassword($id, $form);
            $this->passwordBroker->deletePassword($password->id);
            return [
                "form" => $form,
                "passwords" => $this->getAllUserPasswords($form)
            ];
        } catch (FormException) {
            $form->addError("global", "Erreur lors de la suppression.");
            throw new FormException($form);
        }
    }

    // Helpers

    private function getVerifiedUser(Form $form): User
    {
        $submittedPassword = $form->getValue("password");
        return $this->getAuthenticatedUser($submittedPassword, $form);
    }

    private function buildEncryptedPasswordData(Form $form): array
    {
        $key = $this->auth['user_key'];
        $description = $form->getValue('description');
        $user = $this->userBroker->findById($this->auth['user_id'], $key);

        return [
            'user_id' => $this->auth['user_id'],
            'description' => $this->encryption->encryptWithUserKey($description, $key),
            'description_hash' => $this->encryption->hash256($description),
            'email_from' => $this->encryption->encryptWithUserKey($user->email, $key),
            'note' => $this->encryption->encryptWithUserKey($form->getValue('note'), $key),
            'password' => $this->encryption->encryptWithUserKey($form->getValue('password'), $key),
            'verified' => true
        ];
    }

    private function buildEncryptedUpdateData(Form $form): array
    {
        $key = $this->auth['user_key'];
        $updates = [];

        foreach (['description', 'note', 'password'] as $field) {
            $value = $form->getValue($field);
            if (!empty($value)) {
                $updates[$field] = $this->encryption->encryptWithUserKey($value, $key);
                if ($field === 'description') {
                    $updates['description_hash'] = $this->encryption->hash256($value);
                }
            }
        }

        $updates['verified'] = $form->getValue('verified') === '1';

        return $updates;
    }

    public function updatePasswordsWithNewKey(string $userId, string $oldKey, string $newKey): void
    {
        $passwords = $this->passwordBroker->findAllByUser($userId, $oldKey);

        foreach ($passwords as $p) {
            $this->passwordBroker->updatePassword($p->id, [
                'description' => $this->encryption->encryptWithUserKey($p->description, $newKey),
                'description_hash' => $this->encryption->hash256($p->description),
                'email_from' => $this->encryption->encryptWithUserKey($p->email_from, $newKey),
                'note' => $this->encryption->encryptWithUserKey($p->note, $newKey),
                'password' => $this->encryption->encryptWithUserKey($p->password, $newKey)
            ]);
        }
    }

}
