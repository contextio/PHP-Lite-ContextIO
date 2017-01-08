<?php
/**
 * Context.IO Lite API PHP client library
 */

require_once dirname(__FILE__) . '/class.contextioresponse.php';
require_once dirname(__FILE__) . '/OAuth.php';

/**
 * Class to manage Context.IO Lite API access
 */
class ContextIO {

	/** @var array  */
	protected $responseHeaders;

	/** @var array */
	protected $requestHeaders;

	/** @var string  */
	protected $oauthKey;

	/** @var string  */
	protected $oauthSecret;

	/** @var string|null  */
	protected $accessToken;

	/** @var string|null  */
	protected $accessTokenSecret;

	/** @var bool  */
	protected $saveHeaders;

	/** @var bool  */
	protected $ssl;

	/** @var string  */
	protected $endPoint;

	/** @var string  */
	protected $apiVersion;

	/** @var null|ContextIOResponse  */
	protected $lastResponse;

	/** @var bool  */
	protected $authHeaders;

	/** @var array  cURL options */
	protected $curlOptions;

	/**
	 * Instantiate a new ContextIO object. Your OAuth consumer key and secret can be
	 * found under the "settings" tab of the developer console (https://console.context.io/#settings)
	 *
	 * @param string        $key                    Your Context.IO OAuth consumer key
	 * @param string        $secret                 Your Context.IO OAuth consumer secret
	 * @param string|null   $access_token
	 * @param string|null   $access_token_secret
	 * @param array     $curlOptions            cURL options; assoc array: option => value
	 */
	function __construct($key, $secret, $access_token=null, $access_token_secret=null, array $curlOptions=array()) {
		$this->oauthKey = $key;
		$this->oauthSecret = $secret;
		$this->accessToken = $access_token;
		$this->accessTokenSecret = $access_token_secret;
		$this->saveHeaders = false;
		$this->ssl = true;
		$this->endPoint = 'api.context.io';
		$this->apiVersion = 'lite';
		$this->lastResponse = null;
		$this->authHeaders = true;
		$this->curlOptions = $curlOptions;
	}

	/**
	 * Attempts to discover IMAP settings for a given email address
	 *
	 * @param string|array  $params     either a string or assoc array with "email" as its key
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse
	 */
	public function discovery($params) {
		if (is_string($params)) {
			$params = array('email' => $params);
		}
		else {
			$params = $this->_filterParams($params, array('email'), array('email'));
			if ($params === false) {
				throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
			}
		}
		return $this->get(null, 'discovery?source_type=imap&email=' . rawurlencode($params['email']));
	}

	/**
	 * @param string[]|string|null $user
	 *
	 * @return ContextIOResponse|ContextIOResponse[]|false
	 */
	public function listConnectTokens($user=null) {
		return $this->get($user, 'connect_tokens');
	}

	/**
	 *
	 * @param string|array  $params     either a string or assoc array with "token" as its key
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function getConnectToken($params) {
		if (is_string($params)) {
			$params = array('token' => $params);
		}
		else {
			$params = $this->_filterParams($params, array('token'));
			if ($params === false) {
				throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
			}
		}
		$user = null;
		return $this->get($user, 'connect_tokens/' . $params['token']);
	}

	/**
	 *
	 *
	 * @param array $params     required keys: 'callback_url' <br />
	 *                          possible keys: 'service_level', 'email', 'callback_url', 'first_name', 'last_name', 'source_raw_file_list'
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return bool|ContextIOResponse
	 */
	public function addConnectToken(array $params) {
		$params = $this->_filterParams($params, array('service_level','email','callback_url','first_name','last_name','source_raw_file_list'), array('callback_url'));
		if ($params === false) {
			throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
		}
		$user = null;
		return $this->post($user, 'connect_tokens', $params, null, array('Content-Type: application/x-www-form-urlencoded'));
	}

	/**
	 *
	 * @param string|array  $params     either a string or assoc array with "token" as its key
	 *
	 * @return ContextIOResponse|false
	 */
	public function deleteConnectToken($params) {
		if (is_string($params)) {
			$params = array('token' => $params);
		}
		else {
			$params = $this->_filterParams($params, array('token'), array('token'));
			if ($params === false) {
				throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
			}
		}
		$user = null;
		return $this->delete($user, 'connect_tokens/' . $params['token']);
	}

	/**
	 * Returns message information
	 *
	 * @param string    $user       userID of the mailbox you want to query
	 * @param array $params         Query parameters for the API call <br />
	 *                              required keys: 'label', 'folder' <br />
	 *                              possible keys: 'label', 'folder', 'limit', 'offset', 'include_body', 'include_headers', 'include_flags', 'body_type'
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function listMessages($user, array $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('account must be string representing userId');
		}
		$params = $this->_filterParams($params, array('label','folder','limit','offset','include_body','include_headers','include_flags','body_type'), array('label','folder'));
		if ($params === false) {
			throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
		}
		$email_account = $params['label'];
		$folder = $params['folder'];
		unset($params['label']);
		unset($params['folder']);
		$url = "email_accounts/" . rawurlencode($email_account) . "/folders/" . rawurlencode($folder) . "/messages";
		return $this->get($user, $url, $params);
	}

	/**
	 * Returns document and contact information about a message.
	 *
	 * @param string    $user
	 * @param array     $params     Query parameters for the API call <br />
	 *                              required keys: 'label','folder','message_id'
	 *                              possible keys: 'label', 'folder', 'message_id', 'include_body', 'include_headers', 'include_flags', 'body_type'
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function getMessage($user, array $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		$params = $this->_filterParams($params, array('label','folder','message_id','include_body','include_headers','include_flags','body_type'), array('label','folder','message_id'));
		if ($params === false) {
			throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
		}
		$email_account = $params['label'];
		$folder = $params['folder'];
		$messageId = $params['message_id'];
		unset($params['label']);
		unset($params['folder']);
		unset($params['message_id']);
		return $this->get($user, "email_accounts/" . rawurlencode($email_account) . "/folders/" . rawurlencode($folder) . "/messages/" . rawurlencode($messageId), $params);
	}

	/**
	 * Move a message to a different folder.
	 *
	 * @param string    $user
	 * @param array     $params     Query parameters for the API call <br />
	 *                              required keys: 'label', 'folder','message_id', 'new_folder_id' <br />
	 *                              possible keys: 'label', 'folder', 'message_id', 'new_folder_id', 'delimiter'
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function moveMessage($user, array $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		$params = $this->_filterParams($params, array('label','folder','message_id','new_folder_id','delimiter'), array('label','folder','message_id','new_folder_id'));
		if ($params === false) {
			throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
		}
		$email_account = $params['label'];
		$folder = $params['folder'];
		$messageId = $params['message_id'];
		$newFolder = $params['new_folder_id'];
		unset($params['label']);
		unset($params['folder']);
		unset($params['message_id']);
		return $this->put($user, "email_accounts/" . rawurlencode($email_account) . "/folders/" . rawurlencode($folder) . "/messages/" . rawurlencode($messageId) . '?new_folder_id=' . rawurlencode($newFolder));
	}

	/**
	 * Returns a list of files
	 *
	 * @param string    $user
	 * @param array     $params     Query parameters for the API call <br />
	 *                              required keys: 'label', 'folder', 'message_id' <br />
	 *                              possible keys: 'label', 'folder', 'message_id', 'delimiter'
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function listFiles($user, array $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('account must be string representing userId');
		}
		$params = $this->_filterParams($params, array('label','folder','message_id', 'delimiter'), array('label','folder','message_id'));
		if ($params === false) {
			throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
		}
		$email_account = $params['label'];
		$folder = $params['folder'];
		$messageId = $params['message_id'];
		unset($params['label']);
		unset($params['folder']);
		unset($params['message_id']);
		return $this->get($user, "email_accounts/" . rawurlencode($email_account) . "/folders/" . rawurlencode($folder) . "/messages/" . rawurlencode($messageId) . "/attachments", $params);
	}


	/**
	 * Returns the content a given attachment. If you want to save the attachment to
	 * a file, set $saveAs to the destination file name. If $saveAs is left to null,
	 * the function will return the file data.
	 *
	 * @link http://context.io/docs/lite/users/email_accounts/folders/messages/attachments#id-get
	 *
	 * @param string        $user       userID of the mailbox you want to query
	 * @param array $params             Query parameters for the API call <br />
	 *                                  required keys: 'label','folder','message_id', 'attachment_id' <br />
	 *                                  possible keys: 'label','folder','message_id', 'attachment_id', 'delimiter'
	 * @param string|null   $saveAs     Path to local file where the attachment should be saved to.
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return bool|string
	 */
	public function getFileContent($user, array $params, $saveAs=null) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('account must be string representing userId');
		}
		$params = $this->_filterParams($params, array('label','folder','message_id', 'attachment_id', 'delimiter'), array('label','folder','message_id', 'attachment_id'));
		if ($params === false) {
			throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
		}

		$email_account = $params['label'];
		$folder = $params['folder'];
		$messageId = $params['message_id'];
		$attachmentId = $params['attachment_id'];
		unset($params['label']);
		unset($params['folder']);
		unset($params['message_id']);
		unset($params['attachment_id']);

		$consumer = new ContextIOExtLib\OAuthConsumer($this->oauthKey, $this->oauthSecret);
		$baseUrl = $this->build_url("users/" . $user . "/email_accounts/" . rawurlencode($email_account) . "/folders/" . rawurlencode($folder) . "/messages/" . rawurlencode($messageId) . "/attachments/" . rawurlencode($attachmentId));
		$req = ContextIOExtLib\OAuthRequest::from_consumer_and_token($consumer, null, "GET", $baseUrl);
		$sig_method = new ContextIOExtLib\OAuthSignatureMethod_HMAC_SHA1();
		$req->sign_request($sig_method, $consumer, null);

		//get data using signed url
		if ($this->authHeaders) {
			$curl = curl_init($baseUrl);
			curl_setopt($curl, CURLOPT_HTTPHEADER, array($req->to_header()));
		}
		else {
			$curl = curl_init($req->to_url());
		}

		if ($this->ssl) {
			curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		}

		curl_setopt($curl, CURLOPT_USERAGENT, 'ContextIOLibrary/Lite (PHP)');

		if (! is_null($saveAs)) {
			$fp = fopen($saveAs, "w");
			curl_setopt($curl, CURLOPT_FILE, $fp);
			curl_setopt($curl, CURLOPT_HEADER, 0);
			curl_exec($curl);
			curl_close($curl);
			fclose($fp);
			return true;
		}
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
		$result = curl_exec($curl); // CURLOPT_RETURNTRANSFER is set to 1 -> will return a string
		if (curl_getinfo($curl, CURLINFO_HTTP_CODE) != 200) {
			$response = new ContextIOResponse(
				curl_getinfo($curl, CURLINFO_HTTP_CODE),
				null,
				null,
				curl_getinfo($curl, CURLINFO_CONTENT_TYPE),
				$result);
			$this->lastResponse = $response;
			curl_close($curl);
			return false;
		}
		curl_close($curl);
		return $result;
	}


	/**
	 * Returns the message headers of a message.
	 *
	 * @param string    $user
	 * @param array     $params     Query parameters for the API call <br />
	 *                              required keys: 'label', 'folder', 'message_id' <br />
	 *                              possible keys: 'label', 'folder', 'message_id', 'raw', 'delimiter'
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function getMessageHeaders($user, array $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		$params = $this->_filterParams($params, array('label','folder','message_id','raw', 'delimiter'), array('label','folder','message_id'));
		if ($params === false) {
			throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
		}
		$email_account = $params['label'];
		$folder = $params['folder'];
		$messageId = $params['message_id'];
		unset($params['label']);
		unset($params['folder']);
		unset($params['message_id']);
		return $this->get($user, "email_accounts/" . rawurlencode($email_account) . "/folders/" . rawurlencode($folder) . "/messages/" . rawurlencode($messageId) . "/headers", $params);
	}

	/**
	 * Returns the message flags of a message.
	 *
	 * @param string    $user
	 * @param array     $params     Query parameters for the API call <br />
	 *                              required keys: 'label', 'folder', 'message_id' <br />
	 *                              possible keys: 'label', 'folder', 'message_id', 'raw'
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function getMessageFlags($user, array $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		$params = $this->_filterParams($params, array('label','folder','message_id','raw'), array('label','folder','message_id'));
		if ($params === false) {
			throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
		}
		$email_account = $params['label'];
		$folder = $params['folder'];
		$messageId = $params['message_id'];
		return $this->get($user, "email_accounts/" . rawurlencode($email_account) . "/folders/" . rawurlencode($folder) . "/messages/" . rawurlencode($messageId) . "/flags");
	}

	/**
	 * Marks a message as read
	 *
	 * @param string $user
	 * @param array  $params    Query parameters for the API call <br />
	 *                          required keys: 'label', 'folder', 'message_id' <br />
	 *                          possible keys: 'label', 'folder', 'message_id', 'raw'
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function markRead($user, array $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		$params = $this->_filterParams($params, array('label','folder','message_id','raw'), array('label','folder','message_id'));
		if ($params === false) {
			throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
		}
		$email_account = $params['label'];
		$folder = $params['folder'];
		$messageId = $params['message_id'];
		return $this->post($user, "email_accounts/" . rawurlencode($email_account) . "/folders/" . rawurlencode($folder) . "/messages/" . rawurlencode($messageId) . "/read");
	}

	/**
	 * Marks a message as unread
	 *
	 * @param string    $user
	 * @param array     $params     Query parameters for the API call <br />
	 *                              required keys: 'label', 'folder', 'message_id' <br />
	 *                              possible keys: 'label', 'folder', 'message_id', 'raw'
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function markUnread($user, array $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		$params = $this->_filterParams($params, array('label','folder','message_id','raw'), array('label','folder','message_id'));
		if ($params === false) {
			throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
		}
		$email_account = $params['label'];
		$folder = $params['folder'];
		$messageId = $params['message_id'];
		return $this->delete($user, "email_accounts/" . rawurlencode($email_account) . "/folders/" . rawurlencode($folder) . "/messages/" . rawurlencode($messageId) . "/read");
	}

	/**
	 * Returns the message body (excluding attachments) of a message.
	 *
	 * @param string    $user
	 * @param array     $params     Query parameters for the API call <br />
	 *                              required keys: 'label', 'folder', 'message_id' <br />
	 *                              possible keys: 'label', 'folder', 'message_id', 'type', 'delimiter'
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function getMessageBody($user, array $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		$params = $this->_filterParams($params, array('label','folder','message_id','type', 'delimiter'), array('label','folder','message_id'));
		if ($params === false) {
			throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
		}
		$email_account = $params['label'];
		$folder = $params['folder'];
		$messageId = $params['message_id'];
		unset($params['label']);
		unset($params['folder']);
		unset($params['message_id']);
		return $this->get($user, "email_accounts/" . rawurlencode($email_account) . "/folders/" . rawurlencode($folder) . "/messages/" . rawurlencode($messageId) . "/body", $params);
	}

	/**
	 * Returns the message raw source of a message.
	 * A message can be identified by the value of its Message-ID header
	 *
	 * @param string        $user       userID of the mailbox you want to query
	 * @param array         $params     Query parameters for the API call: <br />
	 *                                  required parameters: 'label','folder','message_id'
	 * @param string|null   $saveAs     Path to local file where the attachment should be saved to.
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function getMessageRaw($user, array $params, $saveAs=null) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		$params = $this->_filterParams($params, array('label','folder','message_id'), array('label','folder','message_id'));
		if ($params === false) {
			throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
		}
		$email_account = $params['label'];
		$folder = $params['folder'];
		$messageId = $params['message_id'];
		$url = "email_accounts/" . rawurlencode($email_account) . "/folders/" . rawurlencode($folder) . "/messages/" . rawurlencode($messageId) . "/raw";

		$consumer = new ContextIOExtLib\OAuthConsumer($this->oauthKey, $this->oauthSecret);
		$accessToken = null;
		if (! is_null($this->accessToken) && ! is_null($this->accessTokenSecret)) {
			$accessToken = new ContextIOExtLib\OAuthToken($this->accessToken, $this->accessTokenSecret);
		}
		$baseUrl = $this->build_url('users/' . $user . '/' . $url);
		$req = ContextIOExtLib\OAuthRequest::from_consumer_and_token($consumer, $accessToken, "GET", $baseUrl);
		$sig_method = new ContextIOExtLib\OAuthSignatureMethod_HMAC_SHA1();
		$req->sign_request($sig_method, $consumer, $accessToken);

		//get data using signed url
		if ($this->authHeaders) {
			$curl = curl_init($baseUrl);
			curl_setopt($curl, CURLOPT_HTTPHEADER, array($req->to_header()));
		}
		else {
			$curl = curl_init($req->to_url());
		}

		if ($this->ssl) {
			curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		}

		curl_setopt($curl, CURLOPT_USERAGENT, 'ContextIOLibrary/Lite (PHP)');

		if (! is_null($saveAs)) {
			$fp = fopen($saveAs, "w");
			curl_setopt($curl, CURLOPT_FILE, $fp);
			curl_setopt($curl, CURLOPT_HEADER, 0);
			curl_exec($curl);
			curl_close($curl);
			fclose($fp);
			return true;
		}
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
		$result = curl_exec($curl);
		if (curl_getinfo($curl, CURLINFO_HTTP_CODE) != 200) {
			$response = new ContextIOResponse(
				curl_getinfo($curl, CURLINFO_HTTP_CODE),
				null,
				null,
				curl_getinfo($curl, CURLINFO_CONTENT_TYPE),
				$result);
			$this->lastResponse = $response;
			curl_close($curl);
			return false;
		}
		curl_close($curl);
		return $result;
	}

	/**
	 *
	 * @param array $params     Query parameters for the API call <br />
	 *                          required keys: 'email' <br/>
	 *                          possible keys: 'email', 'first_name', 'last_name', 'type', 'server', 'username', 'provider_consumer_key', 'provider_refresh_token', 'password', 'use_ssl', 'port', 'migrate_account_id', 'status_callback_url'
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function addUser(array $params) {
		$params = $this->_filterParams($params, array('email','first_name','last_name','type','server','username','provider_consumer_key','provider_refresh_token','password','use_ssl','port','migrate_account_id', 'status_callback_url'), array('email'));
		if ($params === false) {
			throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
		}
		return $this->post(null, 'users', $params);
	}

	/**
	 *
	 * @param string    $user
	 * @param array     $params     Query parameters for the API call <br />
	 *                              possible keys: 'first_name', 'last_name'
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function modifyUser($user, array $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		$params = $this->_filterParams($params, array('first_name','last_name'));
		if ($params === false) {
			throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
		}
		return $this->post($user, '', $params);
	}

	/**
	 *
	 * @param string $user
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function getUser($user) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		return $this->get($user);
	}

	/**
	 *
	 * @param string $user
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function deleteUser($user) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		return $this->delete($user);
	}

	/**
	 *
	 * @param array|null $params    Query parameters for the API call <br />
	 *                              possible keys: 'limit','offset','email','status_ok','status'
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function listUsers(array $params=null) {
		if (is_array($params)) {
			$params = $this->_filterParams($params, array('limit','offset','email','status_ok','status'));
			if ($params === false) {
				throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
			}
		}
		return $this->get(null, 'users', $params);
	}

	/**
	 * Modify the IMAP server settings of an already indexed account
	 *
	 * @param string    $user
	 * @param array     $params     Query parameters for the API call <br />
	 *                              required keys: 'label' <br />
	 *                              possible keys 'label', 'provider_token', 'provider_token_secret', 'provider_refresh_token', 'password', 'provider_consumer_key', 'status', 'force_status_check', 'status_callback_url'
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function modifyEmailAccount($user, array $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		$params = $this->_filterParams($params, array('label', 'provider_token', 'provider_token_secret', 'provider_refresh_token', 'password', 'provider_consumer_key', 'status', 'force_status_check', 'status_callback_url'), array('label'));
		if ($params === false) {
			throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
		}
		return $this->post($user, 'email_accounts/' . $params['label'], $params);
	}

	/**
	 * @param string        $user
	 * @param string|array  $params     either a string or assoc array with "label" as its key
	 * @param bool          $force
	 *
	 * @return ContextIOResponse|false
	 */
	public function resetSourceStatus($user, $params, $force=false) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		if (is_string($params)) {
			$params = array('label' => $params);
		}
		else {
			$params = $this->_filterParams($params, array('label'), array('label'));
			if ($params === false) {
				throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
			}
		}
		if ($force) {
			return $this->post($user, 'email_accounts/' . $params['label'], array('force_status_check' => 1));
		}
		return $this->post($user, 'email_accounts/' . $params['label'], array('status' => 1));
	}

	/**
	 *
	 * @param string        $user
	 * @param array|null    $params     Query parameters for the API call <br />
	 *                                  required keys: 'status_ok','status'
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function listEmailAccounts($user, array $params=null) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		if (is_array($params)) {
			$params = $this->_filterParams($params, array('status_ok','status'));
			if ($params === false) {
				throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
			}
		}
		return $this->get($user, 'email_accounts', $params);
	}

	/**
	 *
	 * @param string        $user
	 * @param string|array  $params      either a string or assoc array with "label" as its key
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function getEmailAccount($user, $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		if (is_string($params)) {
			$params = array('label' => $params);
		}
		else {
			$params = $this->_filterParams($params, array('label'), array('label'));
			if ($params === false) {
				throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
			}
		}
		return $this->get($user, 'email_accounts/' . rawurlencode($params['label']));
	}

	/**
	 *
	 * @param string    $user
	 * @param array     $params   Query parameters for the API call <br />
	 *                            required keys: 'server', 'username'<br />
	 *                            possible keys: 'type', 'email', 'server', 'username', 'provider_consumer_key', 'provider_token', 'provider_token_secret', 'provider_refresh_token', 'raw_file_list', 'password', 'use_ssl', 'port'
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function addEmailAccount($user, array $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		$params = $this->_filterParams($params, array('type','email','server','username','provider_consumer_key','provider_token','provider_token_secret','provider_refresh_token','raw_file_list','password','use_ssl','port'), array('server','username'));
		if ($params === false) {
			throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
		}
		if (! array_key_exists('type', $params)) {
			$params['type'] = 'imap';
		}
		return $this->post($user, 'email_accounts/', $params);
	}

	/**
	 * Remove the connection to an IMAP account
	 *
	 * @param string        $user
	 * @param string|array  $params     either a string or assoc array with "label" as its key
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function deleteEmailAccount($user, $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		if (is_string($params)) {
			$params = array('label' => $params);
		}
		else {
			$params = $this->_filterParams($params, array('label'), array('label'));
			if ($params === false) {
				throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
			}
		}
		return $this->delete($user, 'email_accounts/' . $params['label']);
	}

	/**
	 *
	 * @param string        $user
	 * @param string|array  $params     either a string or assoc array with "label" as its key
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function listEmailAccountFolders($user, $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		if (is_string($params)) {
			$params = array('label' => $params);
		}
		else {
			$params = $this->_filterParams($params, array('label'), array('label'));
			if ($params === false) {
				throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
			}
		}
		$email_account = $params['label'];
		unset($params['label']);
		return $this->get($user, 'email_accounts/' . rawurlencode($email_account) . '/folders', $params);
	}

	/**
	 *
	 * @param string    $user
	 * @param array     $params     Query parameters for the API call <br />
	 *                              required keys: 'label', 'folder'
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function getEmailAccountFolder($user, array $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		$params = $this->_filterParams($params, array('label','folder'), array('label','folder'));
		if ($params === false) {
			throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
		}
		return $this->get($user, 'email_accounts/' . rawurlencode($params['label']) . '/folders/' . rawurlencode($params['folder']));
	}

	/**
	 *
	 * @param string $user
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function listWebhooks($user) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		return $this->get($user, 'webhooks');
	}

	/**
	 *
	 * @param string        $user
	 * @param array|string  $params     either a string or assoc array with "webhook_id" as its key
	 *
	 * @return ContextIOResponse|false
	 */
	public function getWebhook($user, $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		if (is_string($params)) {
			$params = array('webhook_id' => $params);
		}
		else {
			$params = $this->_filterParams($params, array('webhook_id'), array('webhook_id'));
			if ($params === false) {
				throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
			}
		}
		return $this->get($user, 'webhooks/' . rawurlencode($params['webhook_id']));
	}

	/**
	 *
	 * @param string    $user
	 * @param array     $params     Query parameters for the API call <br />
	 *                              required keys: 'callback_url', 'failure_notif_url' <br />
	 *                              possible keys: 'filter_to', 'filter_from', 'filter_cc', 'filter_subject', 'filter_thread', 'filter_new_important', 'filter_file_name', 'filter_file_revisions', 'sync_period', 'callback_url', 'failure_notif_url','filter_folder_added', 'filter_folder_removed', 'filter_to_domain', 'filter_from_domain'
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function addWebhook($user, array $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		$params = $this->_filterParams($params, array('include_body','filter_to', 'filter_from', 'filter_cc', 'filter_subject', 'filter_thread', 'filter_new_important', 'filter_file_name', 'filter_file_revisions', 'sync_period', 'callback_url', 'failure_notif_url','filter_folder_added','filter_folder_removed','filter_to_domain','filter_from_domain'), array('callback_url','failure_notif_url'));
		if ($params === false) {
			throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
		}
		return $this->post($user, 'webhooks/', $params);
	}

	/**
	 *
	 * @param string        $user
	 * @param array|string  $params     either a string or assoc array with "webhook_id" as its key
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function deleteWebhook($user, $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		if (is_string($params)) {
			$params = array('webhook_id' => $params);
		}
		else {
			$params = $this->_filterParams($params, array('webhook_id'), array('webhook_id'));
			if ($params === false) {
				throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
			}
		}
		return $this->delete($user, 'webhooks/' . $params['webhook_id']);
	}

	/**
	 *
	 * @param string    $user
	 * @param array     $params     Query parameters for the API call <br />
	 *                              required keys: 'webhook_id', 'active'
	 *
	 * @throws InvalidArgumentException
	 *
	 * @return ContextIOResponse|false
	 */
	public function modifyWebhook($user, array $params) {
		if (is_null($user) || ! is_string($user) || (! strpos($user, '@') === false)) {
			throw new InvalidArgumentException('user must be string representing userId');
		}
		$params = $this->_filterParams($params, array('webhook_id', 'active'), array('webhook_id','active'));
		if ($params === false) {
			throw new InvalidArgumentException("params array contains invalid parameters or misses required parameters");
		}
		return $this->post($user, 'webhooks/' . $params['webhook_id'], $params);
	}

	/**
	 * Specify the API endpoint.
	 *
	 * @param string $endPoint
	 *
	 * @return bool     success
	 */
	public function setEndPoint($endPoint) {
		$this->endPoint = $endPoint;
		return true;
	}

	/**
	 * Specify whether or not API calls should be made over a secure connection.
	 * HTTPS is used on all calls by default.
	 *
	 * @param bool $sslOn   Set to false to make calls over HTTP, true to use HTTPS
	 */
	public function setSSL($sslOn=true) {
		$this->ssl = (is_bool($sslOn)) ? $sslOn : true;
	}

	/**
	 * Specify whether OAuth parameters should be included as URL query parameters
	 * or sent as HTTP Authorization headers. The default is URL query parameters.
	 *
	 * @param bool $authHeadersOn   Set to true to use HTTP Authorization headers, false to use URL query params
	 */
	public function useAuthorizationHeaders($authHeadersOn = true) {
		$this->authHeaders = (is_bool($authHeadersOn)) ? $authHeadersOn : true;
	}

	/**
	 * Returns the ContextIOResponse object for the last API call.
	 *
	 * @return ContextIOResponse|null
	 */
	public function getLastResponse() {
		return $this->lastResponse;
	}


	/**
	 *
	 * @return string
	 */
	protected function build_baseurl() {
		$url = 'http';
		if ($this->ssl) {
			$url = 'https';
		}
		return "$url://" . $this->endPoint . "/" . $this->apiVersion . '/';
	}

	/**
	 *
	 * @param string $action
	 *
	 * @return string
	 */
	protected function build_url($action) {
		return $this->build_baseurl() . $action;
	}

	/**
	 *
	 * @param bool $yes
	 */
	public function saveHeaders($yes=true) {
		$this->saveHeaders = $yes;
	}

	/**
	 *
	 * @param string[]|string|null  $user
	 * @param string                $action
	 * @param string|array|null     $parameters
	 * @param array|null            $acceptableContentTypes
	 *
	 * @return ContextIOResponse[]|ContextIOResponse|false
	 */
	protected function get($user, $action='', $parameters=null, array $acceptableContentTypes=null) {
		if (is_array($user)) {
			$tmp_results = array();
			foreach ($user as $usr) {
				$result = $this->_doCall('GET', $usr, $action, $parameters, null, $acceptableContentTypes);
				if ($result === false) {
					return false;
				}
				$tmp_results[$usr] = $result;
			}
			return $tmp_results;
		}
		else {
			return $this->_doCall('GET', $user, $action, $parameters, null, $acceptableContentTypes);
		}
	}

	/**
	 *
	 * @param string            $user
	 * @param string            $action
	 * @param string|array|null $parameters
	 * @param array             $httpHeadersToSet
	 *
	 * @return ContextIOResponse|false
	 */
	protected function put($user, $action, $parameters=null, array $httpHeadersToSet=array()) {
		return $this->_doCall('PUT', $user, $action, $parameters, null, null, $httpHeadersToSet);
	}

	/**
	 *
	 * @param string            $user
	 * @param string            $action
	 * @param string|array|null $parameters
	 * @param array|null        $file
	 * @param array             $httpHeadersToSet
	 *
	 * @return ContextIOResponse|false
	 */
	protected function post($user, $action='', $parameters=null, $file=null, $httpHeadersToSet=array()) {
		return $this->_doCall('POST', $user, $action, $parameters, $file, null, $httpHeadersToSet);
	}

	/**
	 *
	 * @param string            $user
	 * @param string            $action
	 * @param string|array|null $parameters
	 *
	 * @return ContextIOResponse|false
	 */
	protected function delete($user, $action='', $parameters=null) {
		return $this->_doCall('DELETE', $user, $action, $parameters);
	}

	/**
	 *
	 * @param string            $httpMethod
	 * @param string|null       $user
	 * @param string            $action
	 * @param string|array|null $parameters
	 * @param array|null        $file                       possible keys: "field" , "filename"
	 * @param string[]|null     $acceptableContentTypes
	 * @param array             $httpHeadersToSet
	 *
	 * @return ContextIOResponse|false
	 */
	protected function _doCall($httpMethod, $user, $action, $parameters=null, array $file=null, array $acceptableContentTypes=null, array $httpHeadersToSet=array()) {
		$consumer = new ContextIOExtLib\OAuthConsumer($this->oauthKey, $this->oauthSecret);
		$accessToken = null;
		if (! is_null($user)) {
			$action = 'users/' . $user . '/' . $action;
			if (substr($action,-1) == '/') {
				$action = substr($action,0,-1);
			}
			if (! is_null($this->accessToken) && ! is_null($this->accessTokenSecret)) {
				$accessToken = new ContextIOExtLib\OAuthToken($this->accessToken, $this->accessTokenSecret);
			}
		}
		$baseUrl = $this->build_url($action);
		$isMultiPartPost = (! is_null($file) && array_key_exists('field', $file) && array_key_exists('filename', $file));
		if ($isMultiPartPost || is_string($parameters)) {
			$this->authHeaders = true;
		}
		$signatureParams = $parameters;
		if ($isMultiPartPost) {
			$signatureParams = array();
		}
		if (is_string($parameters)) {
			$signatureParams = array();
		}
		if (($httpMethod != 'GET') && is_array($parameters)) {
			if (!in_array('Content-Type: application/x-www-form-urlencoded', $httpHeadersToSet)) {
				$signatureParams = array();
			}
			else {
				$newParams = '';
				foreach ($parameters as $key => $value) {
					if (!is_array($value)) {
						if ($newParams != '') {
							$newParams .= '&';
						}
						$newParams .= "$key=" . rawurlencode($value);
					}
					else {
						unset($signatureParams[$key]);
						$signatureParams[$key . '[]'] = $value;
						foreach ($value as $currentValue) {
							if ($newParams != '') {
								$newParams .= '&';
							}
							$newParams .= $key . '[]=' . rawurlencode($currentValue);
						}
					}
				}
				$parameters = $newParams;
			}

		}

		$req = ContextIOExtLib\OAuthRequest::from_consumer_and_token($consumer, $accessToken, $httpMethod, $baseUrl, $signatureParams);
		$sig_method = new ContextIOExtLib\OAuthSignatureMethod_HMAC_SHA1();
		$req->sign_request($sig_method, $consumer, $accessToken);

		//get data using signed url
		if ($this->authHeaders) {
			if ($httpMethod != 'POST') {
				$curl = curl_init((is_null($parameters) || is_string($parameters) || (count($parameters) == 0)) ? $baseUrl : $baseUrl. '?' . ContextIOExtLib\OAuthUtil::build_http_query($parameters));
			}
			else {
				$curl = curl_init($baseUrl);
			}
			$httpHeadersToSet[] = $req->to_header();
		}
		else {
			$curl = curl_init($req->to_url());
		}

		curl_setopt_array($curl, $this->curlOptions);

		if ($this->ssl) {
			curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		}

		curl_setopt($curl, CURLOPT_USERAGENT, 'ContextIOLibrary/Lite (PHP)');

		if ($httpMethod != 'GET') {
			if ($httpMethod == 'POST') {
				curl_setopt($curl, CURLOPT_POST, true);
				if (! is_null($parameters)) {
					if (is_null($file)) {
						if (is_string($parameters)) {
							$httpHeadersToSet[] = 'Content-Length: ' . strlen($parameters);
						}
					}
					else {
						$parameters[$file['field']] = $file['filename'];
					}
					curl_setopt($curl, CURLOPT_POSTFIELDS, $parameters);
				}
				elseif (! is_null($file)) {
					curl_setopt($curl, CURLOPT_POSTFIELDS, array($file['field'] => $file['filename']));
				}
				else {
					$httpHeadersToSet[] = 'Content-Length: 0';
				}
			}
			else {
				curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $httpMethod);
				if ($httpMethod == 'PUT') {
					if (is_string($parameters)) {
						$httpHeadersToSet[] = 'Content-Length: ' . strlen($parameters);
					}
					curl_setopt($curl, CURLOPT_POSTFIELDS, $parameters);
				}
			}
		}
		if (count($httpHeadersToSet) > 0) {
			curl_setopt($curl, CURLOPT_HTTPHEADER, $httpHeadersToSet);
		}
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);

		if ($this->saveHeaders) {
			$this->responseHeaders = array();
			$this->requestHeaders = array();
			curl_setopt($curl, CURLOPT_HEADERFUNCTION, array($this,'_setHeader'));
			curl_setopt($curl, CURLINFO_HEADER_OUT, 1);
		}
		$result = curl_exec($curl);

		$httpHeadersIn = ($this->saveHeaders) ? $this->responseHeaders : null;
		$httpHeadersOut = ($this->saveHeaders) ? preg_split('/(\\n|\\r){1,2}/', curl_getinfo($curl, CURLINFO_HEADER_OUT)) : null;

		if (is_null($acceptableContentTypes)) {
			$response = new ContextIOResponse(
				curl_getinfo($curl, CURLINFO_HTTP_CODE),
				$httpHeadersOut,
				$httpHeadersIn,
				curl_getinfo($curl, CURLINFO_CONTENT_TYPE),
				$result);
		}
		else {
			$response = new ContextIOResponse(
				curl_getinfo($curl, CURLINFO_HTTP_CODE),
				$httpHeadersOut,
				$httpHeadersIn,
				curl_getinfo($curl, CURLINFO_CONTENT_TYPE),
				$result,
				$acceptableContentTypes);
		}
		curl_close($curl);
		if ($response->hasError()) {
			$this->lastResponse = $response;
			return false;
		}
		return $response;
	}


	/**
	 * @param           $curl
	 * @param string    $headers
	 *
	 * @return int
	 */
	public function _setHeader($curl,$headers) {
		$this->responseHeaders[] = trim($headers,"\n\r");
		return strlen($headers);
	}

	/**
	 *
	 * @param array     $givenParams
	 * @param string[]  $validParams
	 * @param string[]  $requiredParams
	 *
	 * @return array|false
	 */
	protected function _filterParams(array $givenParams, array $validParams, array $requiredParams=array()) {
		$filteredParams = array();
		foreach ($givenParams as $name => $value) {
			if (in_array(strtolower($name), $validParams)) {
				$filteredParams[strtolower($name)] = $value;
			}
			else {
				return false;
			}
		}
		foreach ($requiredParams as $name) {
			if (! array_key_exists(strtolower($name), $filteredParams)) {
				return false;
			}
		}
		return $filteredParams;
	}

}
