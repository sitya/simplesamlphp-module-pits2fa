<?php

declare(strict_types=1);

namespace SimpleSAML\Module\totp\Controller;

use SimpleSAML\Configuration;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Module\totp\Auth\Process\TOTP;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Controller for TOTP verification.
 */
class Verify
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;


    /**
     * Constructor
     *
     * @param \SimpleSAML\Configuration $config The configuration to use.
     */
    public function __construct(Configuration $config)
    {
        $this->config = $config;
    }


    /**
     * Display and handle the TOTP verification form.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request The current request.
     * @return \Symfony\Component\HttpFoundation\Response
     *
     * @throws \SimpleSAML\Error\BadRequest If the StateId parameter is missing.
     */
    public function main(Request $request): Response
    {
        $stateId = $request->query->get('StateId') ?? $request->request->get('StateId');
        
        if ($stateId === null) {
            throw new BadRequest('Missing required StateId query parameter.');
        }
        
        // Delegate to the static handler in TOTP class
        TOTP::handleVerification($stateId);
        
        // Note: handleVerification will either redirect or show a template and exit,
        // so this line should never be reached. But for type safety:
        return new Response('', Response::HTTP_NO_CONTENT);
    }
}
