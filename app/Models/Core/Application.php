<?php namespace Models\Core;

use Zephyrus\Core\Application as BaseApplication;

use Zephyrus\Database\Core\Database;
use Zephyrus\Network\Request;
use Zephyrus\Network\Router;

final class Application extends BaseApplication
{
    public static function initiate(Request $request): Router
    {
        $router = parent::initiate($request);
        CustomErrorHandler::initializeFormExceptions();
        return $router;
    }

    public function getDatabase(): Database
    {
        return DatabaseSession::getInstance()->getDatabase();
    }
}
