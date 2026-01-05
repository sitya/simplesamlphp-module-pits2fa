<?php

declare(strict_types=1);

namespace SimpleSAML\Module\totp\Auth\Process;

use PDO;
use PDOException;
use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSAML\Error\Error as SspError;
use SimpleSAML\Error\Exception as SspException;
use SimpleSAML\Logger;
use SimpleSAML\Module;
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
    private const TOTP_REGISTRATION_URL = 'https://pits.example.com';

    private bool $mandatory;
    private string $pitsDsn;
    private string $pitsUrl;
    private string $pitsToken;

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
        
        if (!isset($config['pits_dsn'])) {
            throw new SspException('Missing required configuration parameter: pits_dsn');
        }
        $this->pitsDsn = $config['pits_dsn'];

        if (!isset($config['pits_url'])) {
            throw new SspException('Missing required configuration parameter: pits_url');
        }
        $this->pitsUrl = $config['pits_url'];

        if (!isset($config['pits_token'])) {
            throw new SspException('Missing required configuration parameter: pits_token');
        }
        $this->pitsToken = $config['pits_token'];
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

        // Get username from attributes
        $username = $this->getUsername($state);
        Logger::info('TOTP: Processing authentication for user: ' . $username);
        
        // Check if user has TOTP registered
        Logger::debug('TOTP: Checking TOTP registration status in PITS database');
        $hasTOTP = $this->checkTOTPRegistration($username);
        Logger::info('TOTP: User ' . $username . ' TOTP registration status: ' . ($hasTOTP ? 'registered' : 'not registered'));

        if (!$hasTOTP) {
            if ($this->mandatory) {
                Logger::warning('TOTP: User ' . $username . ' does not have TOTP registered (mandatory mode)');
                // User must register TOTP
                throw new SspError(
                    'NOTOTPREGISTERED',
                    'Please register TOTP at ' . self::TOTP_REGISTRATION_URL
                );
            }
            Logger::info('TOTP: User ' . $username . ' does not have TOTP, continuing (optional mode)');
            // 2FA not mandatory, allow continuation
            return;
        }

        Logger::info('TOTP: Requiring TOTP verification for user: ' . $username);
        // User has TOTP, require verification
        $state['totp:username'] = $username;
        $state['totp:attempts'] = 0;

        $id = State::saveState($state, 'totp:request');
        Logger::debug('TOTP: Saved state with ID: ' . substr($id, 0, 8) . '...');
        
        $url = Module::getModuleURL('totp/verify');
        Logger::debug('TOTP: Redirecting to verification form: ' . $url);
        HTTP::redirectTrustedURL($url, ['StateId' => $id]);
    }

    /**
     * Extract username from state attributes.
     *
     * @param array $state Authentication state
     * @return string Username
     * @throws SspException If username cannot be determined
     */
    private function getUsername(array $state): string
    {
        $attributes = $state['Attributes'];

        // Try common username attributes
        $usernameAttrs = ['uid', 'eduPersonPrincipalName', 'mail', 'username'];
        
        foreach ($usernameAttrs as $attr) {
            if (isset($attributes[$attr][0]) && !empty($attributes[$attr][0])) {
                return $attributes[$attr][0];
            }
        }

        throw new SspException('Unable to determine username from attributes');
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
            $pdo = new PDO(
                $this->pitsDsn,
                null,
                null,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => true,
                ]
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
                throw new SspError('DBQUERYERROR', 'Database query returned unexpected result');
            }

            $status = (int)$result[0] === 1;
            Logger::debug('TOTP: Registration check complete, status: ' . ($status ? 'TRUE' : 'FALSE'));
            return $status;
        } catch (PDOException $e) {
            Logger::error('TOTP: Database error: ' . $e->getMessage());
            throw new SspError('DBERROR', 'Database connection or query failed');
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
            throw new SspError('NETWORKERROR', 'Failed to connect to verification service');
        }

        Logger::debug('TOTP: Received response from PITS API');
        $data = json_decode($response, true);
        
        if (!is_array($data) || !isset($data['result'])) {
            Logger::error('TOTP: Invalid response format from PITS service: ' . substr($response, 0, 100));
            throw new SspError('INVALIDRESPONSE', 'Invalid response from verification service');
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
                // Success - continue authentication
                unset($state['totp:username']);
                unset($state['totp:attempts']);
                State::deleteState($state);
                Logger::info('TOTP: Continuing authentication flow for user: ' . $username);
                ProcessingFilter::resumeProcessing($state);
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
            // Maximum attempts exceeded
            Logger::error('TOTP: Maximum attempts (' . self::MAX_ATTEMPTS . ') exceeded for user: ' . $username);
            State::deleteState($state);
            throw new SspError('TOTPFAILED', 'TOTP verification failed after maximum attempts');
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
}
