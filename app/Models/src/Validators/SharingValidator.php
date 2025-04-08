<?php

namespace Models\src\Validators;

use Models\Exceptions\FormException;
use Models\src\Brokers\PasswordBroker;
use Models\src\Brokers\SharingBroker;
use Models\src\Brokers\UserBroker;
use Zephyrus\Application\Form;
use Zephyrus\Application\Rule;

class SharingValidator
{
    public static function assertShare(Form $form, SharingBroker $sharingBroker, UserBroker $userBroker, PasswordBroker $passwordBroker, string $ownerId, string $userKey): void
    {
        $form->field("email", [
            Rule::required("L’adresse courriel du destinataire est requise."),
            Rule::email("L’adresse courriel du destinataire est invalide.")
        ]);

        $form->field("password", [
            Rule::required("Le mot de passe maître est requis.")
        ]);

        $recipient = $userBroker->findByEmail($form->getValue("email"));
        if (!$recipient) {
            $form->addError("email", "Aucun utilisateur trouvé avec cette adresse courriel.");
        }

        $passwordId = $form->getValue("password_id");
        $password = $passwordBroker->findById($passwordId, $userKey);
        if (!$password || $password->user_id !== $ownerId) {
            $form->addError("password_id", "Le mot de passe est introuvable ou ne vous appartient pas.");
        }

        if ($recipient && $password && $sharingBroker->isAlreadyShared($ownerId, $recipient->id, $password->description_hash)) {
            $form->addError("recipient_email", "Ce mot de passe est déjà partagé avec cet utilisateur.");
        }

        $form->verify();

        if ($form->hasError()) {
            throw new FormException($form);
        }
    }
}
