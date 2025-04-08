<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Brokers\PasswordBroker;
use Models\src\Brokers\SharingBroker;
use Models\src\Brokers\UserBroker;
use Models\src\Entities\User;
use Models\src\Entities\PasswordSharing;
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

    public function acceptPendingShares(): void
    {
        $userId = $this->auth['user_id'];
        $userKey = $this->auth['user_key'];
        $shares = $this->sharingBroker->findPendingSharesForUser($userId);

        foreach ($shares as $share) {
            if ($this->isExpired($share)) {
                continue;
            }

            try {
                $this->acceptShare($share, $userKey);
                $this->sharingBroker->markAsSuccess($share->id);
            } catch (\Throwable $e) {
                $this->sharingBroker->markAsFailed($share->id);

                // TEMP : log ou affichage pour debug
                error_log("Échec du partage #{$share->id} : " . $e->getMessage());
            }

        }
    }

    public function sharePassword(Form $form, string $passwordId): array
    {
        try {
            $ownerId = $this->auth['user_id'];

            $this->assertValidPasswordId($passwordId, $form);
            SharingValidator::assertShare($form, $this->userBroker, $ownerId);

            $password = $this->getPassword($passwordId, $form);
            $recipient = $this->fetchRecipient($form);

            $this->assertNotAlreadyShared($form, $ownerId, $recipient->id, $password->description_hash);
            $this->getAuthenticatedUser($form->getValue("password"), $form);

            $encPassword = $this->encryptFromPublicKey($password->password, $recipient->public_key);
            $encDescription = $this->encryptFromPublicKey($password->description, $recipient->public_key);

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

    private function encryptFromPublicKey(string $value, string $recipientPublicKey): string
    {
        return $this->encryption->encryptWithPublicKey($value, $recipientPublicKey);
    }

    private function decryptFromPublicKey(string $encrypted, string $senderPublicKey, string $userKey): string
    {
        return $this->encryption->decryptFromPublicKey($encrypted, $senderPublicKey, $userKey);
    }

    private function insertSharingRecord(string $recipientId, string $publicKey, string $encPassword, string $encDescription): void
    {
        $this->sharingBroker->insertSharing([
            'encrypted_password'    => $encPassword,
            'encrypted_description' => $encDescription,
            'owner_id'              => $this->auth['user_id'],
            'shared_id'             => $recipientId,
            'public_key_hash'       => $this->encryption->hash256($publicKey),
            'status'                => 'pending',
            'expires_at'            => date('Y-m-d H:i:s', strtotime('+7 days'))
        ]);
    }

    private function isExpired(PasswordSharing $share): bool
    {
        return strtotime($share->expires_at) < time();
    }

    private function acceptShare(PasswordSharing $share, string $userKey): void
    {
        $owner = $this->userBroker->findById($share->owner_id);

        $description = $this->decryptFromPublicKey($share->encrypted_description, $owner->public_key, $userKey);
        $password = $this->decryptFromPublicKey($share->encrypted_password, $owner->public_key, $userKey);

        $this->passwordBroker->createPassword([
            'user_id'          => $this->auth['user_id'],
            'description'      => $this->encryption->encryptWithUserKey($description, $userKey),
            'description_hash' => $this->encryption->hash256($description),
            'note'             => $this->encryption->encryptWithUserKey('', $userKey),
            'password'         => $this->encryption->encryptWithUserKey($password, $userKey),
            'verified'         => false
        ], $userKey);
    }

    private function buildSuccessResponse(): array
    {
        return [
            "success" => true,
            "message" => "Mot de passe partagé avec succès."
        ];
    }
}
