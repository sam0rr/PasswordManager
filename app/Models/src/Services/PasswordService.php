<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Services\Utils\BaseService;
use Models\src\Validators\PasswordValidator;
use Zephyrus\Application\Form;

final class PasswordService extends BaseService
{
    public function getAllUserPasswords($form): array
    {
        try {
            return $this->passwordBroker->findAllByUser(
                $this->auth['user_id'],
                $this->auth['user_key']
            );
        } catch (FormException) {
            $form->addError("global", "Failed To Fetch Passwords.");
            throw new FormException($form);
        }
    }

    public function addPassword(Form $form, bool $isHtmx): array
    {
        try {
            $userId = $this->auth['user_id'];

            PasswordValidator::assertAdd($form, $this->passwordBroker, $userId, $isHtmx);

            if ($isHtmx) {
                return [
                    "form" => $form
                ];
            }

            $data = $this->buildEncryptedPasswordData($form);
            $this->passwordBroker->createPassword($data, $this->auth['user_key']);

            return [
                "form" => $form
            ];

        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    public function updatePassword(Form $form, string $id, bool $isHtmx): array
    {
        try {
            $userId = $this->auth['user_id'];
            $userKey = $this->auth['user_key'];

            $password = $this->getPassword($id, $form);
            PasswordValidator::assertUpdate($form, $this->passwordBroker, $userId, $password, $userKey);

            if ($isHtmx) {
                return [
                    "form" => $form,
                    "password" => $password
                ];
            }

            $updates = $this->buildEncryptedUpdateData($form);
            if (!empty($updates)) {
                $this->passwordBroker->updatePassword($id, $updates);
            }

            return [
                "form" => $form
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
                "form" => $form
            ];
        } catch (FormException) {
            $form->addError("global", "Failed To Delete Password.");
            throw new FormException($form);
        }
    }

    // Helpers

    private function buildEncryptedPasswordData(Form $form): array
    {
        $key = $this->auth['user_key'];
        $description = $form->getValue('description');
        $user = $this->userBroker->findById($this->auth['user_id'], $key);

        return [
            'user_id' => $this->auth['user_id'],
            'description' => $this->encryption->encryptWithUserKey($description, $key),
            'description_hash' => $this->encryption->hash256(strtolower($description)),
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
                    $updates['description_hash'] = $this->encryption->hash256(strtolower($value));
                }
            }
        }

        $updates['verified'] = $form->getValue('verified') === '1';

        return $updates;
    }

    public function updatePasswordsWithNewKey(string $userId, string $oldKey, string $newKey): void
    {
        $passwords = $this->passwordBroker->findAllRawByUser($userId);

        foreach ($passwords as $pw) {
            $updates = [
                'description'      => $this->encryption->rewrapEnvelope($pw->description,  $oldKey, $newKey),
                'email_from'       => $this->encryption->rewrapEnvelope($pw->email_from,   $oldKey, $newKey),
                'note'             => $this->encryption->rewrapEnvelope($pw->note,         $oldKey, $newKey),
                'password'         => $this->encryption->rewrapEnvelope($pw->password,     $oldKey, $newKey),
                'description_hash' => $pw->description_hash
            ];
            $this->passwordBroker->updatePassword($pw->id, $updates);
        }
    }

}
