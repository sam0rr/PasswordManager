<?php

namespace Models\src\Validators;

use Models\Exceptions\FormException;
use Models\src\Brokers\UserBroker;
use Models\src\Validators\Utils\BaseValidator;
use Zephyrus\Application\Form;
use Zephyrus\Application\Rule;

class SharingValidator extends BaseValidator
{
    public static function assertShare(Form $form, UserBroker $userBroker, $ownerId): void
    {
        $form->field("email", [
            Rule::required("L’adresse courriel du destinataire est requise."),
            Rule::email("L’adresse courriel du destinataire est invalide.")
        ]);

        $form->field("password", [
            Rule::required("Le mot de passe maître est requis.")
        ]);

        $recipientEmail = $form->getValue("email");
        $recipient = $userBroker->findByEmail($recipientEmail);
        $currentUser = $userBroker->findById($ownerId);

        if (!$recipient) {
            $form->addError("email", "Aucun utilisateur trouvé avec cette adresse courriel.");
        } elseif ($recipient->id === $currentUser->id) {
            $form->addError("email", "Vous ne pouvez pas partager un mot de passe avec vous-même.");
        }

        $form->verify();

        if ($form->hasError()) {
            throw new FormException($form);
        }
    }
}
