<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Brokers\PasswordBroker;
use Models\src\Brokers\SharingBroker;
use Models\src\Brokers\UserBroker;
use Models\src\Entities\User;
use Models\src\Validators\SharingValidator;
use Zephyrus\Application\Form;

class SharingService extends BaseService
{
    private SharingBroker $sharingBroker;

    public function __construct(array $auth)
    {
        $this->auth = $auth;
        $this->passwordBroker = new PasswordBroker();
        $this->userBroker = new UserBroker();
        $this->sharingBroker = new SharingBroker();
        $this->encryption = new EncryptionService();
    }

    public function sharePassword(Form $form, string $passwordId): array
    {
        try {
            $ownerId = $this->auth['user_id'];
            $userKey = $this->auth['user_key'];

            $this->assertValidPasswordId($passwordId, $form);

            SharingValidator::assertShare($form, $this->userBroker);

            $password = $this->getPassword($passwordId, $form);
            $recipient = $this->fetchRecipient($form);

            $this->assertNotAlreadyShared($form, $ownerId, $recipient->id, $password->description_hash);

            $this->getAuthenticatedUser($form->getValue("password"), $form);

            $password = $this->passwordBroker->findById($passwordId, $userKey);
            $decrypted = $password->password;
            $description = $password->description;

            $encPassword = $this->encryption->encryptWithPublicKey($decrypted, $recipient->public_key);
            $encDescription = $this->encryption->encryptWithPublicKey($description, $recipient->public_key);

            $this->insertSharingRecord($recipient->id, $recipient->public_key, $encPassword, $encDescription);

            return $this->buildSuccessResponse();
        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    // Helpers

    private function fetchRecipient(Form $form): User
    {
        return $this->userBroker->findByEmail($form->getValue("email"));
    }

    private function assertNotAlreadyShared(Form $form, string $ownerId, string $recipientId, string $descriptionHash): void
    {
        if ($this->sharingBroker->isAlreadyShared($ownerId, $recipientId, $descriptionHash)) {
            $form->addError("email", "Ce mot de passe est déjà partagé avec cet utilisateur.");
            throw new FormException($form);
        }
    }

    private function insertSharingRecord(string $recipientId, string $publicKey, string $encPassword, string $encDescription): void
    {
        $this->sharingBroker->insertSharing([
            'encrypted_password' => $encPassword,
            'encrypted_description' => $encDescription,
            'owner_id' => $this->auth['user_id'],
            'shared_id' => $recipientId,
            'public_key_hash' => $this->encryption->hash256($publicKey),
            'status' => 'pending',
            'expires_at' => date('Y-m-d H:i:s', strtotime('+7 days'))
        ]);
    }



    private function buildSuccessResponse(): array
    {
        return [
            "success" => true,
            "message" => "Mot de passe partagé avec succès."
        ];
    }

}
