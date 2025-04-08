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

    public function sharePassword(Form $form): array
    {
        try {
            $ownerId = $this->auth['user_id'];
            $userKey = $this->auth['user_key'];
            $passwordId = $form->getValue("password_id");

            $this->assertValidPasswordId($passwordId, $form);

            SharingValidator::assertShare($form, $this->sharingBroker, $this->userBroker,
                                            $this->passwordBroker, $ownerId, $userKey);

            $this->getAuthenticatedUser($form->getValue("password"), $form);

            $recipient = $this->fetchRecipient($form);

            $decrypted = $this->decryptSharedPassword($passwordId, $userKey);

            $encrypted = $this->encryption->encryptWithPublicKey($decrypted, $recipient->public_key);

            $this->insertSharingRecord($recipient->id, $recipient->public_key, $encrypted);

            return $this->buildSuccessResponse();
        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    // Helpers

    private function fetchRecipient(Form $form): User
    {
        return $this->userBroker->findByEmail($form->getValue("recipient_email"));
    }

    private function decryptSharedPassword(string $passwordId, string $userKey): string
    {
        $password = $this->passwordBroker->findById($passwordId, $userKey);
        return $this->encryption->decryptWithUserKey($password->password, $userKey);
    }

    private function insertSharingRecord(string $recipientId, string $publicKey, string $encryptedPassword): void
    {
        $this->sharingBroker->insertSharing([
            'encrypted_password' => $encryptedPassword,
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
