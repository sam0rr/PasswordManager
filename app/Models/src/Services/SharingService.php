<?php

namespace Models\src\Services;

use Models\Exceptions\FormException;
use Models\src\Brokers\SharingBroker;
use Models\src\Entities\PasswordSharing;
use Models\src\Entities\User;
use Models\src\Entities\UserPassword;
use Models\src\Services\Utils\BaseService;
use Models\src\Services\Utils\PasswordSharingUtils;
use Models\src\Validators\SharingValidator;
use RuntimeException;
use Throwable as ThrowableAlias;
use Zephyrus\Application\Form;

final class SharingService extends BaseService
{
    private ?SharingBroker $sharingBroker = null {
        get {
            return $this->sharingBroker ??= new SharingBroker();
        }
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
            } catch (ThrowableAlias $e) {
                $this->sharingBroker->markAsFailed($share->id);
                error_log("Sharing Failed #$share->id : " . $e->getMessage());
            }
        }
    }

    public function getAllShares($form): array
    {
        try {
            $userId = $this->auth['user_id'] ?? null;

            return $this->sharingBroker->findAllSharesByOwner($userId);

        } catch (FormException) {
            $form->addError("global", "Failed To Get All Shares.");
            throw new FormException($form);
        }
    }

    public function deleteShare(string $shareId, $form): array
    {
        try {
            $share = $this->sharingBroker->findById($shareId);
            $this->sharingBroker->deleteShare($share->id);

            return [
                "form" => $form
            ];

        } catch (FormException) {
            $form->addError("global", "Failed To Delete Share.");
            throw new FormException($form);
        }
    }

    public function sharePassword(Form $form, string $passwordId, $isHtmx): array
    {
        try {
            $ownerId = $this->auth['user_id'];

            $password = $this->getPassword($passwordId, $form);
            SharingValidator::assertShare($form, $this->userBroker, $ownerId, $isHtmx);

            $recipient = $this->fetchRecipient($form);

            $this->assertRecipientHasNotThisDescription($form, $recipient->id, $password->description_hash);

            $this->assertNotAlreadyShared($form, $ownerId, $recipient->id, $password->description_hash);

            if ($isHtmx) {
                return [
                    "form" => $form,
                    "password" => $password
                ];
            }

            $this->encryptShareInfo($password, $recipient);

            return [
                "form" => $form
            ];

        } catch (FormException) {
            return $this->buildErrorResponse($form);
        }
    }

    // Helpers

    private function fetchRecipient(Form $form): User
    {
        return $this->userBroker->findByEmail($form->getValue("email"));
    }

    private function encryptFromPublicKey(string $value, string $recipientPublicKey): string
    {
        return $this->encryption->encryptWithPublicKey($value, $recipientPublicKey);
    }

    private function decryptFromPublicKey(string $encrypted, string $userKey): string
    {
        return $this->encryption->decryptFromPublicKey($encrypted, $userKey);
    }

    public function encryptShareInfo(UserPassword $password, User $recipient): void
    {
        // 1. Create JSON
        $jsonInfo = PasswordSharingUtils::encodeInfo(
            $password->email_from,
            $password->password,
            $password->description,
            $password->note
        );

        // 2. Encrypt JSON
        $encInfo = $this->encryptFromPublicKey($jsonInfo, $recipient->public_key);

        // 3. Insert one field
        $this->insertSharingRecord(
            $recipient->id,
            $encInfo,
            $password->description_hash
        );
    }

    private function insertSharingRecord(
        string $recipientId,
        string $encInfo,
        string $descriptionHash
    ): void {
        $this->sharingBroker->insertSharing([
            'encrypted_info'   => $encInfo,
            'description_hash' => $descriptionHash,
            'owner_id'         => $this->auth['user_id'],
            'shared_id'        => $recipientId,
            'status'           => 'pending',
            'expires_at'       => date('Y-m-d H:i:s', strtotime('+7 days'))
        ]);
    }

    private function isExpired(PasswordSharing $share): bool
    {
        return strtotime($share->expires_at) < time();
    }

    private function acceptShare(PasswordSharing $share, string $userKey): void
    {
        $decryptedJson = $this->decryptFromPublicKey($share->encrypted_info, $userKey);

        $info = PasswordSharingUtils::decodeInfo($decryptedJson);

        $emailFrom = $info['email_from'];
        $password = $info['password'];
        $description = $info['description'];
        $note = $info['note'];

        $this->assertUniqueDescription($share->description_hash);

        $this->storeSharedPassword($description, $password, $emailFrom, $note, $userKey);
    }

    private function assertRecipientHasNotThisDescription(Form $form, string $recipientId, string $descriptionHash): void
    {
        if ($this->passwordBroker->descriptionHashExistsForUser($recipientId, $descriptionHash)) {
            $form->addError("email", "The Recipient Already Has This Password.");
            throw new FormException($form);
        }
    }

    private function assertNotAlreadyShared(Form $form, string $ownerId, string $recipientId, string $descriptionHash): void
    {
        if ($this->sharingBroker->isAlreadyShared($ownerId, $recipientId, $descriptionHash)) {
            $form->addError("email", "This Password Is Already Shared With This Recipient.");
            throw new FormException($form);
        }
    }

    private function assertUniqueDescription(string $descriptionHash): void
    {
        if ($this->passwordBroker->descriptionHashExistsForUser($this->auth['user_id'], $descriptionHash)) {
            throw new RuntimeException("Conflit : A Password With This Description Already Exists.");
        }
    }

    private function storeSharedPassword(string $description, string $password, string $emailFrom, string $note, string $userKey): void
    {
        $descriptionHash = $this->encryption->hash256($description);

        $this->passwordBroker->createPassword([
            'user_id'          => $this->auth['user_id'],
            'description'      => $this->encryption->encryptWithUserKey($description, $userKey),
            'description_hash' => $descriptionHash,
            'email_from'       => $this->encryption->encryptWithUserKey($emailFrom, $userKey),
            'note'             => $this->encryption->encryptWithUserKey($note, $userKey),
            'password'         => $this->encryption->encryptWithUserKey($password, $userKey),
            'verified'         => false
        ], $userKey);
    }

}
