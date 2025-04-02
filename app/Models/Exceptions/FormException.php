<?php namespace Models\Exceptions;

use Zephyrus\Application\Form;

class FormException extends \RuntimeException
{
    private ?Form $failedForm;
    private ?string $redirectPath = null;

    public function __construct(?Form $form, ?string $message = null)
    {
        parent::__construct($message ?? localize("errors.generic"));
        $this->failedForm = $form;
    }

    public function setRedirectPath(string $redirectPath)
    {
        $this->redirectPath = $redirectPath;
    }

    public function getRedirectPath(): ?string
    {
        return $this->redirectPath;
    }

    public function getForm(): ?Form
    {
        return $this->failedForm;
    }
}
