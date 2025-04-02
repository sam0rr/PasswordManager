<?php namespace Models\Core;

use Dotenv\Dotenv;
use Tracy\Debugger;
use Zephyrus\Application\Configuration;
use Zephyrus\Application\Flash;
use Zephyrus\Exceptions\RouteMethodUnsupportedException;
use Zephyrus\Exceptions\RouteNotAcceptedException;
use Zephyrus\Exceptions\RouteNotFoundException;
use Zephyrus\Exceptions\Security\IntrusionDetectionException;
use Zephyrus\Exceptions\Security\InvalidCsrfException;
use Zephyrus\Exceptions\Security\UnauthorizedAccessException;
use Zephyrus\Network\Request;
use Zephyrus\Network\Response;
use Zephyrus\Network\Router;
use Zephyrus\Network\ServerEnvironnement;
use Zephyrus\Security\AuthorizationRepository;

class Kernel
{
    private ServerEnvironnement $serverEnvironnement;
    private Request $request;
    private Router $router;

    public function __construct()
    {
        $this->initializeEnvironnement();
        if (Configuration::getApplication('env') == 'dev') {
            Debugger::enable(Debugger::Development);
            Debugger::$logDirectory = ROOT_DIR . '/temp';
        }
        DatabaseSession::initiate(Configuration::getDatabase());
        $this->serverEnvironnement = new ServerEnvironnement($_SERVER);
        $this->request = new Request($this->serverEnvironnement);
        $this->router = Application::initiate($this->request);
        $this->initializeBaseAuthorizations();
        require ROOT_DIR . "/app/formats.php";
        require ROOT_DIR . "/app/functions.php";
    }

    public function run(): Response
    {
        try {
            return $this->router->resolve($this->request);
        } catch (RouteMethodUnsupportedException $exception) {
            return $this->handleUnsupportedMethod($exception);
        } catch (RouteNotAcceptedException $exception) {
            return $this->handleUnacceptedRoute($exception);
        } catch (RouteNotFoundException $exception) {
            return $this->handleRouteNotFound($exception);
        } catch (IntrusionDetectionException $exception) {
            return $this->handleDetectedIntrusion($exception);
        } catch (InvalidCsrfException $exception) {
            return $this->handleInvalidCsrf($exception);
        } catch (UnauthorizedAccessException $exception) {
            return $this->handleUnauthorizedException($exception);
        }
    }

    /**
     * Default handling for unauthorized access exception. Meaning the current user is not authorized to view a specific
     * route or do a specific action. Can be overridden if needed for a more specific behavior. By default, it returns
     * the user to its profile or login depending on if they are logged. Also tries to keep in session the route to
     * return to it once they are log (in case they don't have access simply because they have been disconnected).
     *
     * @param UnauthorizedAccessException $exception
     * @return Response|null
     */
    protected function handleUnauthorizedException(UnauthorizedAccessException $exception): ?Response
    {
        Flash::warning(localize("errors.unauthorized"));
        return Response::builder()->redirect("/");
    }

    /**
     * Default handling of intrusion detection. This method is triggered when the IDS is active and detects an intrusion
     * equals or greater than the configured impact_threshold (default to 0, meaning any detection is registered). Can
     * be overridden if needed for a more specific behavior.
     *
     * @param IntrusionDetectionException $exception
     * @return Response|null
     */
    protected function handleDetectedIntrusion(IntrusionDetectionException $exception): ?Response
    {
        $referer = $this->request->getReferer();
        if (empty($referer)) {
            $referer = "/";
        }
        Flash::warning(localize("errors.intrusion_detected"));
        return Response::builder()->redirect($referer);
    }

    /**
     * Defines the actions to take when an invalid CSRF exception occurs in the system. Meaning that a form was not
     * properly sent or used. If the method returns a Response, it will end the processing of the route immediately and
     * give this response back to the client. Can be overridden if needed for a more specific behavior. By default, it
     * tries to return to the previous page and register the error.
     *
     * @param InvalidCsrfException $exception
     * @return Response|null
     */
    protected function handleInvalidCsrf(InvalidCsrfException $exception): ?Response
    {
        Flash::error(localize("errors.csrf_invalid"));
        return Response::builder()->redirect(!empty($this->request->getReferer()) ? $this->request->getReferer() : "/");
    }

    protected function handleRouteNotFound(RouteNotFoundException $exception): ?Response
    {
        Flash::warning(localize("errors.not_found", $exception->getMethod() . ' ' . $exception->getUri()));
        $referer = $this->request->getReferer();
        if (empty($referer) || $referer == $exception->getUri()) {
            $referer = "/";
        }
        return Response::builder()->redirect($referer);
    }

    protected function handleUnsupportedMethod(RouteMethodUnsupportedException $exception): ?Response
    {
        return Response::builder()->abortMethodNotAllowed();
    }

    protected function handleUnacceptedRoute(RouteNotAcceptedException $exception): ?Response
    {
        return Response::builder()->abortNotAcceptable();
    }

    private function initializeBaseAuthorizations(): void
    {
        // Allows everyone to access
        AuthorizationRepository::getInstance()->addRule('everyone', function () {
            return true;
        });

        // Allows only an authenticated user
        AuthorizationRepository::getInstance()->addSessionRule('authenticated', 'user');
    }

    /**
     * Loads the configurations within .env file into the $_ENV super global. Seeks the .env file at the root directory
     * defined with the « ROOT_DIR » constant. Creates CONSTANTS automatically with the env variables.
     */
    private function initializeEnvironnement(): void
    {
        $dotenv = Dotenv::createImmutable(ROOT_DIR);
        $env = $dotenv->load();
        foreach ($env as $item => $value) {
            define($item, $value);
        }
    }
}
