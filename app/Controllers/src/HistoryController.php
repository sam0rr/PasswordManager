<?php

namespace Controllers\src;

use Controllers\SecureController;
use Controllers\src\Utils\SessionHelper;
use Zephyrus\Network\Router\Post;
use Zephyrus\Network\Response;

final class HistoryController extends SecureController
{
    #[Post('/history/deleteAll')]
    public function deleteAll(): Response
    {
        $form = $this->buildForm();

        $this->base->history->deleteAll($form);
        $history = $this->base->history->getHistoryForUser($form);

        $this->setHistoryContext($history);
        return $this->redirect('/dashboard?section=history');
    }

    #[Post('/history/{id}/delete')]
    public function deleteSingle(string $id): Response
    {
        $form = $this->buildForm();

        $this->base->history->deleteSingle($id, $form);
        $history = $this->base->history->getHistoryForUser($form);
        $this->setHistoryContext($history);

        return $this->redirect('/dashboard?section=history');
    }

    private function setHistoryContext(array $history): void
    {
        SessionHelper::append([
            'auth_history'   => $history,
            'activeSection'  => 'history',
            'tab'            => 'list'
        ]);
    }
    
}
