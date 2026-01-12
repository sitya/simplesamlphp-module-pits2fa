<?php

declare(strict_types=1);

namespace SimpleSAML\Module\totp\Auth\Process;

use PDO;
use PDOException;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Error\Error as SspError;
use SimpleSAML\Error\Exception as SspException;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\totp\Error\ErrorCodes;
use SimpleSAML\Utils\HTTP;

/**
 * TOTP authentication processing filter using PITS.
 *
 * This filter implements TOTP-based second-factor authentication
 * after successful username/password authentication.
 */
class TOTP extends ProcessingFilter
{
    private const MAX_ATTEMPTS = 3;
    private const SERVICE_NAME = 'eduid';

    private bool $mandatory;
    private string $usernameAttribute;
    private string $pitsDsn;
    private string $pitsUsername;
    private string $pitsPassword;
    private array $pitsOptions;
    private string $pitsUrl;
    private string $pitsToken;
    private string $pitsRegistrationUrl;
    private string $authnContextClassRef;

    /**
     * Initialize the filter.
     *
     * @param array $config Configuration array
     * @param mixed $reserved Reserved parameter
     */
    public function __construct(array $config, $reserved)
    {
        parent::__construct($config, $reserved);

        $this->mandatory = $config['2fa_mandatory'] ?? false;

        if (!isset($config['username_attribute'])) {
            throw new SspException('Missing required configuration parameter: username_attribute');
        }
        $this->usernameAttribute = $config['username_attribute'];

        if (!isset($config['pits_dsn'])) {
            throw new SspException('Missing required configuration parameter: pits_dsn');
        }
        $this->pitsDsn = $config['pits_dsn'];

        if (!isset($config['pits_username'])) {
            throw new SspException('Missing required configuration parameter: pits_username');
        }
        $this->pitsUsername = $config['pits_username'];

        if (!isset($config['pits_password'])) {
            throw new SspException('Missing required configuration parameter: pits_password');
        }
        $this->pitsPassword = $config['pits_password'];

        $this->pitsOptions = $config['pits_options'] ?? [];

        if (!isset($config['pits_url'])) {
            throw new SspException('Missing required configuration parameter: pits_url');
        }
        $this->pitsUrl = $config['pits_url'];

        if (!isset($config['pits_token'])) {
            throw new SspException('Missing required configuration parameter: pits_token');
        }
        $this->pitsToken = $config['pits_token'];

        if (!isset($config['pits_registration_url'])) {
            throw new SspException('Missing required configuration parameter: pits_registration_url');
        }
        $this->pitsRegistrationUrl = $config['pits_registration_url'];

        // Default to REFEDS MFA Profile identifier
        $this->authnContextClassRef = $config['authncontextclassref'] ?? 'https://refeds.org/profile/mfa';
    }

    /**
     * Process authentication.
     *
     * @param array &$state The authentication state
     */
    public function process(array &$state): void
    {
        assert(isset($state['Attributes']));

        Logger::info('TOTP: Starting 2FA processing');

        // Get username from configured attribute
        $attributes = $state['Attributes'];
        if (!isset($attributes[$this->usernameAttribute][0]) || empty($attributes[$this->usernameAttribute][0])) {
            throw new SspException('Username attribute "' . $this->usernameAttribute . '" not found or empty in state');
        }
        $username = $attributes[$this->usernameAttribute][0];
        Logger::info('TOTP: Processing authentication for user: ' . $username);
        
        // Check if TOTP was already completed in this session (SSO)
        $session = \SimpleSAML\Session::getSessionFromRequest();
        $totpTimestamp = $session->getData('totp:completed', $username);
        
        if ($totpTimestamp !== null) {
            // TOTP was completed earlier in this session
            $sessionDuration = \SimpleSAML\Configuration::getInstance()->getOptionalInteger('session.duration', 8 * 60 * 60);
            $elapsed = time() - $totpTimestamp;
            
            if ($elapsed < $sessionDuration) {
                Logger::info('TOTP: Bypassing TOTP verification for user ' . $username . ' - already verified in this session (elapsed: ' . $elapsed . 's)');
                return;  // Skip TOTP, continue authentication
            } else {
                Logger::debug('TOTP: Session TOTP marker expired for user ' . $username . ' (elapsed: ' . $elapsed . 's)');
            }
        }
        
        // Check if user has TOTP registered
        Logger::debug('TOTP: Checking TOTP registration status in PITS database');
        $hasTOTP = $this->checkTOTPRegistration($username);
        Logger::info('TOTP: User ' . $username . ' TOTP registration status: ' . ($hasTOTP ? 'registered' : 'not registered'));

        if (!$hasTOTP) {
            if ($this->mandatory) {
                Logger::warning('TOTP: User ' . $username . ' does not have TOTP registered (mandatory mode)');
                // Save registration URL to state before showing page
                $state['totp:registration_url'] = $this->pitsRegistrationUrl;
                // User must register TOTP - show informational page
                self::showRegisterRequiredPage($state);
            }
            Logger::info('TOTP: User ' . $username . ' does not have TOTP, continuing (optional mode)');
            // 2FA not mandatory, allow continuation
            return;
        }

        Logger::info('TOTP: Requiring TOTP verification for user: ' . $username);
        // User has TOTP, require verification
        $state['totp:username'] = $username;
        $state['totp:attempts'] = 0;
        
        // Save configuration to state so we can reconstruct the filter later
        $state['totp:config'] = [
            '2fa_mandatory' => $this->mandatory,
            'username_attribute' => $this->usernameAttribute,
            'pits_dsn' => $this->pitsDsn,
            'pits_username' => $this->pitsUsername,
            'pits_password' => $this->pitsPassword,
            'pits_options' => $this->pitsOptions,
            'pits_url' => $this->pitsUrl,
            'pits_token' => $this->pitsToken,
            'pits_registration_url' => $this->pitsRegistrationUrl,
            'authncontextclassref' => $this->authnContextClassRef,
        ];

        $id = State::saveState($state, 'totp:request');
        Logger::debug('TOTP: Saved state with ID: ' . substr($id, 0, 8) . '...');
        
        $url = Module::getModuleURL('totp/verify.php');
        Logger::debug('TOTP: Redirecting to verification form: ' . $url);
        
        $httpUtils = new HTTP();
        $httpUtils->redirectTrustedURL($url, ['StateId' => $id]);
    }

    /**
     * Check if user has TOTP registered in PITS database.
     *
     * @param string $username The username to check
     * @return bool True if TOTP is registered, false otherwise
     * @throws SspError On database connection or query errors
     */
    private function checkTOTPRegistration(string $username): bool
    {
        try {
            Logger::debug('TOTP: Connecting to PITS database');
            //
            // Merge default options with user-provided options
            $defaultOptions = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            ];
            $options = array_merge($defaultOptions, $this->pitsOptions);

            $pdo = new PDO(
                $this->pitsDsn,
                $this->pitsUsername,
                $this->pitsPassword,
                $options
            );
            Logger::debug('TOTP: Database connection established');

            Logger::debug('TOTP: Executing stored procedure: eduid_2fa_required');
            $stmt = $pdo->prepare('CALL eduid_2fa_required(:username)');
            $stmt->bindParam(':username', $username, PDO::PARAM_STR);
            $stmt->execute();

            $result = $stmt->fetch(PDO::FETCH_NUM);
            Logger::debug('TOTP: Stored procedure result: ' . var_export($result, true));

            if ($result === false || !isset($result[0])) {
                Logger::error('TOTP: Database query returned unexpected result');
                throw new SspError(ErrorCodes::DBQUERYERROR, null, null, new ErrorCodes());
            }

            $status = (int)$result[0] === 1;
            Logger::debug('TOTP: Registration check complete, status: ' . ($status ? 'TRUE' : 'FALSE'));
            return $status;
        } catch (PDOException $e) {
            Logger::error('TOTP: Database error: ' . $e->getMessage());
            throw new SspError(ErrorCodes::DBERROR, $e, null, new ErrorCodes());
        }
    }

    /**
     * Verify TOTP code with PITS service.
     *
     * @param string $username The username
     * @param string $code The TOTP code to verify
     * @return bool True if verification succeeds, false otherwise
     * @throws SspError On network or HTTP errors
     */
    public function verifyTOTP(string $username, string $code): bool
    {
        Logger::info('TOTP: Verifying code for user: ' . $username);
        Logger::debug('TOTP: Calling PITS API at: ' . $this->pitsUrl);
        
        $postData = [
            'token' => $this->pitsToken,
            'username' => $username,
            'code' => $code, // Note: code not logged for security
            'service' => self::SERVICE_NAME,
        ];

        $options = [
            'http' => [
                'method' => 'POST',
                'header' => 'Content-Type: application/x-www-form-urlencoded',
                'content' => http_build_query($postData),
                'timeout' => 10,
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ];

        $context = stream_context_create($options);
        
        Logger::debug('TOTP: Sending verification request to PITS API');
        $response = @file_get_contents($this->pitsUrl, false, $context);
        
        if ($response === false) {
            Logger::error('TOTP: Failed to connect to PITS verification service at: ' . $this->pitsUrl);
            throw new SspError(ErrorCodes::NETWORKERROR, null, null, new ErrorCodes());
        }

        Logger::debug('TOTP: Received response from PITS API');
        $data = json_decode($response, true);
        
        if (!is_array($data) || !isset($data['result'])) {
            Logger::error('TOTP: Invalid response format from PITS service: ' . substr($response, 0, 100));
            throw new SspError(ErrorCodes::INVALIDRESPONSE, null, null, new ErrorCodes());
        }

        $verified = $data['result'] === 'OK';
        Logger::info('TOTP: Verification result for user ' . $username . ': ' . ($verified ? 'SUCCESS' : 'FAILED'));

        return $verified;
    }

    /**
     * Handle TOTP verification result.
     *
     * @param string $stateId The state identifier
     */
    public static function handleVerification(string $stateId): void
    {
        Logger::debug('TOTP: handleVerification called with state ID: ' . substr($stateId, 0, 8) . '...');
        $state = State::loadState($stateId, 'totp:request');

        $username = $state['totp:username'] ?? 'unknown';
        $currentAttempt = ($state['totp:attempts'] ?? 0) + 1;

        Logger::info('TOTP: Processing verification attempt ' . $currentAttempt . '/' . self::MAX_ATTEMPTS . ' for user: ' . $username);

        if (!isset($_POST['totp_code'])) {
            Logger::debug('TOTP: No code submitted, showing verification form');
            // Show form again
            self::showVerificationForm($state);
            return;
        }

        $code = trim($_POST['totp_code']);
        Logger::debug('TOTP: Code submitted (length: ' . strlen($code) . ')');

        // Don't log the actual TOTP code for security reasons

        $filter = new self($state['totp:config'] ?? [], null);

        try {
            $verified = $filter->verifyTOTP($username, $code);

            if ($verified) {
                Logger::info('TOTP: Verification SUCCESSFUL for user: ' . $username);
                
                // Store TOTP completion marker in session for SSO
                $session = \SimpleSAML\Session::getSessionFromRequest();
                $session->setData(
                    'totp:completed',
                    $username,
                    time(),
                    \SimpleSAML\Session::DATA_TIMEOUT_SESSION_END
                );
                Logger::debug('TOTP: Stored TOTP completion marker in session for user: ' . $username);

                // Add MFA assurance attribute
                $state['Attributes']['eduPersonAssurance'] = ['https://refeds.org/profile/mfa'];
                Logger::debug('TOTP: Added eduPersonAssurance attribute for user: ' . $username);

                // Set SAML AuthnContextClassRef
                $state['saml:AuthnContextClassRef'] = $filter->authnContextClassRef;
                Logger::debug('TOTP: Set AuthnContextClassRef to: ' . $filter->authnContextClassRef);

                // Success - continue authentication, clean up TOTP state
                unset($state['totp:username']);
                unset($state['totp:attempts']);
                unset($state['totp:error']);
                unset($state['totp:config']);
                Logger::info('TOTP: Continuing authentication flow for user: ' . $username);
                ProcessingChain::resumeProcessing($state);
                return;
            }
        } catch (SspError $e) {
            Logger::error('TOTP: Verification error for user ' . $username . ': ' . $e->getMessage());
            // Network/service error
            throw $e;
        }

        // Verification failed
        $state['totp:attempts']++;
        Logger::warning('TOTP: Verification FAILED for user: ' . $username . ' (attempt ' . $state['totp:attempts'] . '/' . self::MAX_ATTEMPTS . ')');

        if ($state['totp:attempts'] >= self::MAX_ATTEMPTS) {
            // Maximum attempts exceeded - show informational page instead of error
            Logger::error('TOTP: Maximum attempts (' . self::MAX_ATTEMPTS . ') exceeded for user: ' . $username);
            
            // Clear session TOTP marker to force re-verification on next login
            $session = \SimpleSAML\Session::getSessionFromRequest();
            $session->deleteData('totp:completed', $username);
            Logger::debug('TOTP: Cleared TOTP session marker for user: ' . $username);
            
            // Clean up TOTP-specific state data
            unset($state['totp:username']);
            unset($state['totp:attempts']);
            unset($state['totp:error']);
            unset($state['totp:config']);
            
            // Show max attempts page
            self::showMaxAttemptsPage($state);
        }

        // Show form again with error
        Logger::debug('TOTP: Showing verification form again with error message');
        $state['totp:error'] = true;
        State::saveState($state, 'totp:request');
        self::showVerificationForm($state);
    }

    /**
     * Show TOTP verification form.
     *
     * @param array $state Authentication state
     */
    private static function showVerificationForm(array $state): void
    {
        $globalConfig = Configuration::getInstance();
        $t = new \SimpleSAML\XHTML\Template($globalConfig, 'totp:verify.twig');

        $t->data['stateId'] = State::saveState($state, 'totp:request');
        $t->data['error'] = $state['totp:error'] ?? false;
        $t->data['attempts'] = $state['totp:attempts'] ?? 0;
        $t->data['maxAttempts'] = self::MAX_ATTEMPTS;

        $t->send();
        exit();
    }

    /**
     * Show max attempts exceeded page.
     *
     * @param array $state Authentication state
     */
    private static function showMaxAttemptsPage(array $state): void
    {
        $globalConfig = Configuration::getInstance();
        $t = new \SimpleSAML\XHTML\Template($globalConfig, 'totp:max_attempts.twig');

        // Don't provide any URL - user should close the page and start fresh
        // The template will handle this by showing instructions only

        $t->send();
        exit();
    }

    /**
     * Show TOTP registration required page.
     *
     * @param array $state Authentication state
     */
    private static function showRegisterRequiredPage(array $state): void
    {
        $globalConfig = Configuration::getInstance();
        $t = new \SimpleSAML\XHTML\Template($globalConfig, 'totp:register_required.twig');

        // Pass the registration URL from state
        $t->data['registrationUrl'] = $state['totp:registration_url'] ?? 'https://pits.example.com';

        $t->send();
        exit();
    }
}
