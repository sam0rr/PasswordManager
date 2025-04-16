<?php namespace Controllers;

use Controllers\src\Utils\SessionHelper;
use Models\Core\Entities\Now;
use Zephyrus\Application\Controller as BaseController;
use Models\Core\Application;
use Zephyrus\Application\Configuration;
use Zephyrus\Application\Flash;
use Zephyrus\Network\Response;
use Zephyrus\Security\ContentSecurityPolicy;
use Zephyrus\Security\SecureHeader;

abstract class Controller extends BaseController
{
    public function before(): ?Response
    {
        error_log("Session ID: " . session_id());
        error_log("CSRF token from request: " . $this->request->getParameter('CSRFToken'));
        return parent::before();
    }

    public function render(string $page, array $args = []): Response
    {
        $projectName = Configuration::getApplication('project');
        $arguments = array_merge($args, [

            /**
             * Previous page the user accessed.
             */
            "referer" => $this->request->getReferer(),

            /**
             * Keep the defined controller Root attribute (for easier navigation).
             */
            "route_root" => $this->request->getRouteDefinition()->getRouteRoot(),

            /**
             * Keep the csrf alive cause i use htmx it can't kill itself.
             */
            "csrf_keep_alive" => '<input type="hidden" name="CSRF_KEEP_ALIVE" value="1"/>',

            /**
             * Token for script execution.
             */
            "nonce" => nonce(),

            /**
             * All flash messages (necessary for zf-flash() component).
             */
            "flash" => Flash::readAll(),

            /**
             * Current date values.
             */
            "now" => new Now(),

            /**
             * Name of the application that should be used within every page as browser title.
             */
            "project_name" => $projectName
        ]);
        return parent::render($page, $arguments);
    }

    protected function setupSecurityHeaders(SecureHeader $secureHeader): void
    {
        $csp = new ContentSecurityPolicy();
        $csp->setFontSources(["'self'", 'https://fonts.googleapis.com', 'https://fonts.gstatic.com']);
        $csp->setStyleSources(["'self'", 'https://fonts.googleapis.com', ContentSecurityPolicy::UNSAFE_INLINE]);
        $csp->setScriptSources(["'self'", 'https://ajax.googleapis.com', 'https://maps.googleapis.com',
            'https://www.google-analytics.com', 'https://cdn.jsdelivr.net']);
        $csp->setChildSources(["'self'"]);
        $csp->setWorkerSources(["blob:"]);
        $csp->setConnectSources(["'self'", 'https://api.mapbox.com', 'https://events.mapbox.com']);
        $csp->addImageSource("https://yourdomain.com/uploads/");

        $csp->setImageSources([
            "'self'",
            'blob:',
            'data:',
            'https:'
        ]);

        $csp->setBaseUri([$this->request->getUrl()->getBaseUrl()]);

        $secureHeader->setContentSecurityPolicy($csp);
    }

    protected function isHtmx(): bool
    {
        return $this->request->getHeader('HX-Request') !== null;
    }

    protected function flashMessage(string $message): void
    {
        SessionHelper::append([
            'flash_message' => $message
        ]);
    }

}
