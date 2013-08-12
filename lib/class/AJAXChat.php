<?php
/*
 * @package AJAX_Chat
 * @author Sebastian Tschan
 * @copyright (c) Sebastian Tschan
 * @license GNU Affero General Public License
 * @link https://blueimp.net/ajax/
 */

// Ajax Chat backend logic:
class AJAXChat {

	var $db;
	var $_config;
	var $_requestVars;
	var $_infoMessages;
	var $_channels;
	var $_allChannels;
	var $_view;
	var $_lang;
	var $_invitations;
	var $_customVars;
	var $_sessionNew;
	var $_onlineUsersData;
	var $_bannedUsersData;
	
	function AJAXChat() {
		$this->initialize();
	}

	function initialize() {
		// Initialize configuration settings:
		$this->initConfig();

		// Initialize the DataBase connection:
		$this->initDataBaseConnection();

		// Initialize request variables:
		$this->initRequestVars();
		
		// Initialize the chat session:
		$this->initSession();
		
		// Handle the browser request and send the response content:
		$this->handleRequest();
	}

	function initConfig() {
		$config = null;
		if (!include(AJAX_CHAT_PATH.'lib/config.php')) {
			echo('<strong>Error:</strong> Could not find a config.php file in "'.AJAX_CHAT_PATH.'"lib/". Check to make sure the file exists.');
			die();
		}
		$this->_config = &$config;

		// Initialize custom configuration settings:
		$this->initCustomConfig();
	}
	
	function initRequestVars() {
		$this->_requestVars = array();
		$this->_requestVars['ajax']			= isset($_REQUEST['ajax'])			? true							: false;
		$this->_requestVars['userID']		= isset($_REQUEST['userID'])		? (int)$_REQUEST['userID']		: null;
		$this->_requestVars['userName']		= isset($_REQUEST['userName'])		? $_REQUEST['userName']			: null;
		$this->_requestVars['channelID']	= isset($_REQUEST['channelID'])		? (int)$_REQUEST['channelID']	: null;
		$this->_requestVars['channelName']	= isset($_REQUEST['channelName'])	? $_REQUEST['channelName']		: null;
		$this->_requestVars['text']			= isset($_REQUEST['text'])			? $_REQUEST['text']				: null;
		$this->_requestVars['lastID']		= isset($_REQUEST['lastID'])		? (int)$_REQUEST['lastID']		: 0;
		$this->_requestVars['login']		= isset($_REQUEST['login'])			? true							: false;
		$this->_requestVars['logout']		= isset($_REQUEST['logout'])		? true							: false;
		$this->_requestVars['password']		= isset($_REQUEST['password'])		? $_REQUEST['password']			: null;
		$this->_requestVars['view']			= isset($_REQUEST['view'])			? $_REQUEST['view']				: null;
		$this->_requestVars['year']			= isset($_REQUEST['year'])			? (int)$_REQUEST['year']		: null;
		$this->_requestVars['month']		= isset($_REQUEST['month'])			? (int)$_REQUEST['month']		: null;
		$this->_requestVars['day']			= isset($_REQUEST['day'])			? (int)$_REQUEST['day']			: null;
		$this->_requestVars['hour']			= isset($_REQUEST['hour'])			? (int)$_REQUEST['hour']		: null;
		$this->_requestVars['search']		= isset($_REQUEST['search'])		? $_REQUEST['search']			: null;
		$this->_requestVars['shoutbox']		= isset($_REQUEST['shoutbox'])		? true							: false;
		$this->_requestVars['getInfos']		= isset($_REQUEST['getInfos'])		? $_REQUEST['getInfos']			: null;
		$this->_requestVars['lang']			= isset($_REQUEST['lang'])			? $_REQUEST['lang']				: null;
		$this->_requestVars['delete']		= isset($_REQUEST['delete'])		? (int)$_REQUEST['delete']		: null;
		$this->_requestVars['pay']			= isset($_REQUEST['pay'])			? $_REQUEST['pay']				: null;
		$this->_requestVars['tip']			= isset($_REQUEST['tip'])			? $_REQUEST['tip']				: null;
		$this->_requestVars['tipcomment']	= isset($_REQUEST['tipcomment'])	? $_REQUEST['tipcomment']		: null;
		$this->_requestVars['initInImages']	= isset($_REQUEST['initInImages'])	? true							: false;
		$this->_requestVars['privateMsgCount']	= isset($_REQUEST['privateMsgCount'])? $_REQUEST['privateMsgCount']	: null;
		$this->_requestVars['in_private_msg']	= isset($_REQUEST['in_private_msg'])? $_REQUEST['in_private_msg']	: null;
		$this->_requestVars['get_private_msg']	= isset($_REQUEST['get_private_msg'])? $_REQUEST['get_private_msg']	: null;
		$this->_requestVars['get_private_msg_u2']	= isset($_REQUEST['get_private_msg_u2'])? $_REQUEST['get_private_msg_u2']	: null;
		$this->_requestVars['upd_private_msg']	= isset($_REQUEST['upd_private_msg'])? $_REQUEST['upd_private_msg']	: null;
		$this->_requestVars['upd_private_msg_u2']	= isset($_REQUEST['upd_private_msg_u2'])? $_REQUEST['upd_private_msg_u2']	: null;
		$this->_requestVars['upd_private_msg_last_msg']	= isset($_REQUEST['upd_private_msg_last_msg'])? $_REQUEST['upd_private_msg_last_msg']	: null;
		$this->_requestVars['arr']	= isset($_POST['test'])? $_POST['test']	: null;
		$this->_requestVars['getAvatarID']	= isset($_REQUEST['getAvatarID'])? $_REQUEST['getAvatarID']	: null;
		// Initialize custom request variables:
		$this->initCustomRequestVars();
		
		// Remove slashes which have been added to user input strings if magic_quotes_gpc is On:
		if(get_magic_quotes_gpc()) {
			// It is safe to remove the slashes as we escape user data ourself
			array_walk(
				$this->_requestVars,
				create_function(
					'&$value, $key',
					'if(is_string($value)) $value = stripslashes($value);'
				)
			);
		}
	}
	
	function initDataBaseConnection() {
		// Create a new database object:
		$this->db = new AJAXChatDataBase(
			$this->_config['dbConnection']
		);
		// Use a new database connection if no existing is given:
		if(!$this->_config['dbConnection']['link']) {
			// Connect to the database server:
			$this->db->connect($this->_config['dbConnection']);
			if($this->db->error()) {
				echo $this->db->getError();
				die();
			}
			// Select the database:
			$this->db->select($this->_config['dbConnection']['name']);
			if($this->db->error()) {
				echo $this->db->getError();
				die();
			}
		}
		// Unset the dbConnection array for safety purposes:
		unset($this->_config['dbConnection']);			
	}
	
	function getDataBaseTable($table) {
		return ($this->db->getName() ? $this->db->getName().'.'.$this->getConfig('dbTableNames',$table) : $this->getConfig('dbTableNames',$table));
	}

	function initSession() {
		// Start the PHP session (if not already started):

		$this->startSession();

		if($this->isLoggedIn()) {
			if(isset ($_GET["sessionid"])) {
if ($_SESSION["ajaxChatUserName"] != $this->getJoomUsername()){


$this->logout();
				return;
}
			}

			// Logout if we receive a logout request, the chat has been closed or the userID could not be revalidated:
			if($this->getRequestVar('logout') || !$this->isChatOpen() || !$this->revalidateUserID()) {

				$this->logout();
				return;
			}
			// Logout if the Session IP is not the same when logged in and ipCheck is enabled:
			if($this->getConfig('ipCheck') && ($this->getSessionIP() === null || $this->getSessionIP() != $_SERVER['REMOTE_ADDR'])) {

				$this->logout('IP');
				return;
			}
		} else if(
			// Login if auto-login enabled or a login, userName or shoutbox parameter is given:
			$this->getConfig('forceAutoLogin') ||
			$this->getRequestVar('login') ||
			$this->getRequestVar('userName') ||
			$this->getRequestVar('shoutbox') 
			) {


			$this->login();
		}

		// Initialize the view:
		$this->initView();

		if($this->getView() == 'chat') {
			$this->initChatViewSession();
		} else if($this->getView() == 'logs') {
			$this->initLogsViewSession();
		}

		if(!$this->getRequestVar('ajax') && !headers_sent()) {
			// Set style cookie:
			$this->setStyle();
			// Set langCode cookie:
			$this->setLangCodeCookie();
		}
		
		$this->initCustomSession();
	}

	function initLogsViewSession() {
		if($this->getConfig('socketServerEnabled')) {
			if(!$this->getSessionVar('logsViewSocketAuthenticated')) {
				$this->updateLogsViewSocketAuthentication();
				$this->setSessionVar('logsViewSocketAuthenticated', true);
			}
		}
	}

	function updateLogsViewSocketAuthentication() {
		if($this->getUserRole() != AJAX_CHAT_ADMIN) {
			$channels = array();
			foreach($this->getChannels() as $channel) {
				if($this->getConfig('logsUserAccessChannelList') && !in_array($channel, $this->getConfig('logsUserAccessChannelList'))) {
					continue;
				}
				array_push($channels, $channel);
			}
			array_push($channels, $this->getPrivateMessageID());
			array_push($channels, $this->getPrivateChannelID());
		} else {
			// The channelID "ALL" authenticates for all channels:
			$channels = array('ALL');
		}
		$this->updateSocketAuthentication(
			$this->getUserID(),
			$this->getSocketRegistrationID(),
			$channels
		);
	}

	function initChatViewSession() {
		// If channel is not null we are logged in to the chat view:
		if($this->getChannel() !== null) {
			// Check if the current user has been logged out due to inactivity:
			if(!$this->isUserOnline()) {
				$this->logout();
				return;
			}
			if($this->getRequestVar('ajax')) {
				$this->initChannel();
				$this->updateOnlineStatus();
				$this->checkAndRemoveInactive();
			}
		} else {
			if($this->getRequestVar('ajax')) {
				// Set channel, insert login messages and add to online list on first ajax request in chat view:
				$this->chatViewLogin();
			}
		}
	}

	function isChatOpen() {
		if($this->getUserRole() == AJAX_CHAT_ADMIN)
			return true;
		if($this->getConfig('chatClosed'))
			return false;
		$time = time();
		if($this->getConfig('timeZoneOffset') !== null) {
			// Subtract the server timezone offset and add the config timezone offset:
			$time -= date('Z', $time);
			$time += $this->getConfig('timeZoneOffset');
		}
		// Check the opening hours:
		if($this->getConfig('openingHour') < $this->getConfig('closingHour'))
		{
			if(($this->getConfig('openingHour') > date('G', $time)) || ($this->getConfig('closingHour') <= date('G', $time)))
				return false;
		}
		else
		{
			if(($this->getConfig('openingHour') > date('G', $time)) && ($this->getConfig('closingHour') <= date('G', $time)))
				return false;
		}
		// Check the opening weekdays:
		if(!in_array(date('w', $time), $this->getConfig('openingWeekDays')))
			return false;
		return true;	
	}

	function handleRequest() {
		if($this->getRequestVar('ajax')) {
			if($this->isLoggedIn()) {
				// Parse info requests (for current userName, etc.):
				$this->parseInfoRequests();
	
				// Parse command requests (e.g. message deletion):
				$this->parseCommandRequests();
	
				// Parse message requests:
				$this->initMessageHandling();
			}
			// Send chat messages and online user list in XML format:
			$this->sendXMLMessages();
		} else {
			// Display XHTML content for non-ajax requests:
			$this->sendXHTMLContent();
		}
	}

	function parseCommandRequests() {
		if($this->getRequestVar('delete') !== null) {
			$this->deleteMessage($this->getRequestVar('delete'));
			}
		if($this->getRequestVar('pay') !== null) {
			$this->pay($this->getRequestVar('pay'));
			}
		if($this->getRequestVar('tip') !== null) {
			$this->tip($this->getRequestVar('tip'));
			}
		if($this->getRequestVar('privateMsgCount') !== null) {
			$this->privateMsgCount($this->getRequestVar('privateMsgCount'));
			}
		if($this->getRequestVar('in_private_msg') !== null) {
			$this->in_private_msg($this->getRequestVar('in_private_msg'));
			}
		if(($this->getRequestVar('get_private_msg') !== null) && ($this->getRequestVar('get_private_msg_u2') !== null)) {
			$this->get_private_msg($this->getRequestVar('get_private_msg'),$this->getRequestVar('get_private_msg_u2'));
			}
		if(($this->getRequestVar('upd_private_msg') !== null) && ($this->getRequestVar('upd_private_msg_u2') !== null)&& ($this->getRequestVar('upd_private_msg_last_msg') !== null)) {
			$this->upd_pv_msg($this->getRequestVar('upd_private_msg'),$this->getRequestVar('upd_private_msg_u2'),$this->getRequestVar('upd_private_msg_last_msg'));
			}
		if($this->_requestVars['arr'] !== null) {
			$this->clean_pv_message($this->_requestVars['arr']);
			}
		if($this->_requestVars['getAvatarID'] !== null) {
			$this->getAvatarID($this->_requestVars['getAvatarID']);
			}
		if($this->_requestVars['initInImages'] == true) {
			$this->initInImages($this->_requestVars['initInImages']);
			}
	}

	function parseInfoRequests() {
		if($this->getRequestVar('getInfos')) {
			$infoRequests = explode(',', $this->getRequestVar('getInfos'));			
			foreach($infoRequests as $infoRequest) {
				$this->parseInfoRequest($infoRequest);
			}
		}
	}
	
	function parseInfoRequest($infoRequest) {
		switch($infoRequest) {
			case 'userID':
				$this->addInfoMessage($this->getUserID(), 'userID');
				break;
			case 'userName':
				$this->addInfoMessage($this->getUserName(), 'userName');
				break;
			case 'userRole':
				$this->addInfoMessage($this->getUserRole(), 'userRole');
				break;
			case 'channelID':
				$this->addInfoMessage($this->getChannel(), 'channelID');
				break;
			case 'channelName':
				$this->addInfoMessage($this->getChannelName(), 'channelName');
				break;
			case 'socketRegistrationID':
				$this->addInfoMessage($this->getSocketRegistrationID(), 'socketRegistrationID');
				break;
			default:
				$this->parseCustomInfoRequest($infoRequest);
		}
	}

	function sendXHTMLContent() {
		$httpHeader = new AJAXChatHTTPHeader($this->getConfig('contentEncoding'), $this->getConfig('contentType'));

		$template = new AJAXChatTemplate($this, $this->getTemplateFileName(), $httpHeader->getContentType());

		// Send HTTP header:
		$httpHeader->send();		

		// Send parsed template content:
		echo $template->getParsedContent();
	}

	function getTemplateFileName() {
		switch($this->getView()) {
			case 'chat':
				return AJAX_CHAT_PATH.'lib/template/loggedIn.html';
			case 'logs':
				return AJAX_CHAT_PATH.'lib/template/logs.html';
			default:
				return AJAX_CHAT_PATH.'lib/template/loggedOut.html';
		}
	}

	function initView() {
		$this->_view = null;
		// "chat" is the default view:
		$view = ($this->getRequestVar('view') === null) ? 'chat' : $this->getRequestVar('view');
		if($this->hasAccessTo($view)) {
			$this->_view = $view;
		}
	}

	function getView() {
		return $this->_view;
	}

	function hasAccessTo($view) {
		switch($view) {
			case 'chat':
			case 'teaser':
				if($this->isLoggedIn()) {
					return true;	
				}
				return false;
			case 'logs':
				if($this->isLoggedIn() && ($this->getUserRole() == AJAX_CHAT_ADMIN ||
					($this->getConfig('logsUserAccess') &&
					($this->getUserRole() == AJAX_CHAT_MODERATOR || $this->getUserRole() == AJAX_CHAT_USER))
					)) {
					return true;
				}
				return false;
			default:
				return false;
		}
	}
	
	function login() {
		// Retrieve valid login user data (from request variables or session data):
		$userData = $this->getValidLoginUserData();
		
		if(!$userData) {
			$this->addInfoMessage('errorInvalidUser');
			return false;
		}

		// If the chat is closed, only the admin may login:
		if(!$this->isChatOpen() && $userData['userRole'] != AJAX_CHAT_ADMIN) {
			$this->addInfoMessage('errorChatClosed');
			return false;
		}
		
		if(!$this->getConfig('allowGuestLogins') && $userData['userRole'] == AJAX_CHAT_GUEST) {
			return false;
		}

		// Check if userID or userName are already listed online:
		if($this->isUserOnline($userData['userID']) || $this->isUserNameInUse($userData['userName'])) {
			if($userData['userRole'] == AJAX_CHAT_USER || $userData['userRole'] == AJAX_CHAT_MODERATOR || $userData['userRole'] == AJAX_CHAT_ADMIN) {
				// Set the registered user inactive and remove the inactive users so the user can be logged in again:
				$this->setInactive($userData['userID'], $userData['userName']);
				$this->removeInactive();
			} else {
				$this->addInfoMessage('errorUserInUse');
				return false;
			}
		}
		
		// Check if user is banned:
		if($userData['userRole'] != AJAX_CHAT_ADMIN && $this->isUserBanned($userData['userName'], $userData['userID'], $_SERVER['REMOTE_ADDR'])) {
			$this->addInfoMessage('errorBanned');
			return false;
		}
		
		// Check if the max number of users is logged in (not affecting moderators or admins):
		if(!($userData['userRole'] == AJAX_CHAT_MODERATOR || $userData['userRole'] == AJAX_CHAT_ADMIN) && $this->isMaxUsersLoggedIn()) {
			$this->addInfoMessage('errorMaxUsersLoggedIn');
			return false;
		}

		// Use a new session id (if session has been started by the chat):
		$this->regenerateSessionID();

		// Log in:
		$this->setUserID($userData['userID']);
		$this->setUserName($userData['userName']);
		$this->setLoginUserName($userData['userName']);
		$this->setUserRole($userData['userRole']);
		$this->setLoggedIn(true);	
		$this->setLoginTimeStamp(time());

		// IP Security check variable:
		$this->setSessionIP($_SERVER['REMOTE_ADDR']);

		// The client authenticates to the socket server using a socketRegistrationID:
		if($this->getConfig('socketServerEnabled')) {
			$this->setSocketRegistrationID(
				md5(uniqid(rand(), true))
			);
		}

		// Add userID, userName and userRole to info messages:
		$this->addInfoMessage($this->getUserID(), 'userID');
		$this->addInfoMessage($this->getUserName(), 'userName');
		$this->addInfoMessage($this->getUserRole(), 'userRole');

		// Purge logs:
		if($this->getConfig('logsPurgeLogs')) {
			$this->purgeLogs();
		}

		return true;
	}
	
	function chatViewLogin() {
		$this->setChannel($this->getValidRequestChannelID());
		$this->addToOnlineList();
		
		// Add channelID and channelName to info messages:
		$this->addInfoMessage($this->getChannel(), 'channelID');
		$this->addInfoMessage($this->getChannelName(), 'channelName');
		
		// Login message:
		$text = '/login '.$this->getUserName();
		$this->insertChatBotMessage(
			$this->getChannel(),
			$text,
			null,
			1
		);	
	}

	function getValidRequestChannelID() {
		$channelID = $this->getRequestVar('channelID');
		$channelName = $this->getRequestVar('channelName');		
		// Check the given channelID, or get channelID from channelName:
		if($channelID === null) {
			if($channelName !== null) {
				$channelID = $this->getChannelIDFromChannelName($channelName);
				// channelName might need encoding conversion:
				if($channelID === null) {
					$channelID = $this->getChannelIDFromChannelName(
									$this->trimChannelName($channelName, $this->getConfig('contentEncoding'))
								);
				}
			}
		}
		// Validate the resulting channelID:
		if(!$this->validateChannel($channelID)) {
			if($this->getChannel() !== null) {
				return $this->getChannel();
			}
			return $this->getConfig('defaultChannelID');
		}
		return $channelID;
	}

	function initChannel() {
		$channelID = $this->getRequestVar('channelID');
		$channelName = $this->getRequestVar('channelName');
		if($channelID !== null) {
			$this->switchChannel($this->getChannelNameFromChannelID($channelID));			
		} else if($channelName !== null) {
			if($this->getChannelIDFromChannelName($channelName) === null) {
				// channelName might need encoding conversion:
				$channelName = $this->trimChannelName($channelName, $this->getConfig('contentEncoding'));
			}		
			$this->switchChannel($channelName);	
		}
	}
	
	function logout($type=null) {
		// Update the socket server authentication for the user:
		if($this->getConfig('socketServerEnabled')) {
			$this->updateSocketAuthentication($this->getUserID());
		}
		if($this->isUserOnline()) {
			$this->chatViewLogout($type);
		}	
		$this->setLoggedIn(false);		
		$this->destroySession();

		// Re-initialize the view:
		$this->initView();
	}
	
	function chatViewLogout($type) {
		$this->removeFromOnlineList();
		if($type !== null) {
			$type = ' '.$type;
		}
		// Logout message
		$text = '/logout '.$this->getUserName().$type;
		$this->insertChatBotMessage(
			$this->getChannel(),
			$text,
			null,
			1
		);
	}
	
	function switchChannel($channelName) {
		$channelID = $this->getChannelIDFromChannelName($channelName);

		if($channelID !== null && $this->getChannel() == $channelID) {
			// User is already in the given channel, return:
			return;
		}

		// Check if we have a valid channel:
		if(!$this->validateChannel($channelID)) {
			// Invalid channel:
			$text = '/error InvalidChannelName '.$channelName;
			$this->insertChatBotMessage(
				$this->getPrivateMessageID(),
				$text
			);
			return;
		}

		$oldChannel = $this->getChannel();

		$this->setChannel($channelID);
		$this->updateOnlineList();
		
		// Channel leave message
		$text = '/channelLeave '.$this->getUserName();
		$this->insertChatBotMessage(
			$oldChannel,
			$text,
			null,
			1
		);

		// Channel enter message
		$text = '/channelEnter '.$this->getUserName();
		$this->insertChatBotMessage(
			$this->getChannel(),
			$text,
			null,
			1
		);

		$this->addInfoMessage($channelName, 'channelSwitch');
		$this->addInfoMessage($channelID, 'channelID');
		$this->_requestVars['lastID'] = 0;
	}
	
	function addToOnlineList() {
		$sql = 'INSERT INTO '.$this->getDataBaseTable('online').'(
					userID,
					userName,
					userRole,
					channel,
					dateTime,
					ip
				)
				VALUES (
					'.$this->db->makeSafe($this->getUserID()).',
					'.$this->db->makeSafe($this->getUserName()).',
					'.$this->db->makeSafe($this->getUserRole()).',
					'.$this->db->makeSafe($this->getChannel()).',
					NOW(),
					'.$this->db->makeSafe($this->ipToStorageFormat($_SERVER['REMOTE_ADDR'])).'
				);';	
		
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		
		$this->resetOnlineUsersData();
	}
	
	function removeFromOnlineList() {
		$sql = 'DELETE FROM
					'.$this->getDataBaseTable('online').'
				WHERE
					userID = '.$this->db->makeSafe($this->getUserID()).';';
		
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		
		$this->removeUserFromOnlineUsersData();
	}
	
	function updateOnlineList() {
		$sql = 'UPDATE
					'.$this->getDataBaseTable('online').'
				SET
					userName 	= '.$this->db->makeSafe($this->getUserName()).',
					channel 	= '.$this->db->makeSafe($this->getChannel()).',
					dateTime 	= NOW(),
					ip			= '.$this->db->makeSafe($this->ipToStorageFormat($_SERVER['REMOTE_ADDR'])).'
				WHERE
					userID = '.$this->db->makeSafe($this->getUserID()).';';
					
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		
		$this->resetOnlineUsersData();
	}
	
	function initMessageHandling() {
		// Don't handle messages if we are not in chat view:
		if($this->getView() != 'chat') {
			return;
		}

		// Check if we have been uninvited from a private or restricted channel:
		if(!$this->validateChannel($this->getChannel())) {
			// Switch to the default channel:
			$this->switchChannel($this->getChannelNameFromChannelID($this->getConfig('defaultChannelID')));
			return;
		}
					
		if($this->getRequestVar('text') !== null) {
			$this->insertMessage($this->getRequestVar('text'));
		}

	}
	
	function insertParsedMessage($text) {

		// If a queryUserName is set, sent all messages as private messages to this userName:
		if($this->getQueryUserName() !== null && strpos($text, '/') !== 0) {
			$text = '/msg '.$this->getQueryUserName().' '.$text;
		}
		
		// Parse IRC-style commands:
		if(strpos($text, '/') === 0) {
			$textParts = explode(' ', $text);

			switch($textParts[0]) {
				
				// Channel switch:
				case '/join':
					$this->insertParsedMessageJoin($textParts);
					break;
					
				// Logout:
				case '/quit':
					$this->logout();
					break;
					
				// Private message:
				case '/msg':
				case '/describe':
					$this->insertParsedMessagePrivMsg($textParts);
					break;
				//Start forming group
				case '/startgroup':
					$this->insertParsedMessageStartgroup($textParts);
					break;
				//Add forming group
				case '/joingroup':
					$this->insertParsedMessageJoingroup($textParts);
					break;

				
				// Invitation:
				case '/invite':
					$this->insertParsedMessageInvite($textParts);
					break;
				// AbortInvintation:
				case '/agree':
					$this->insertParsedMessageInviteAgree($textParts);
					break;				// AbortInvintation:
				case '/abort':
					$this->insertParsedMessageAbort($textParts);
					break;

				// Uninvitation:
				case '/uninvite':		
					$this->insertParsedMessageUninvite($textParts);
					break;
				// PvInvitation:
				case '/invitepv':
					$this->insertParsedMessagePvInvite($textParts);
					break;

				// PvUninvitation:
				case '/uninvitepv':		
					$this->insertParsedMessagePvUninvite($textParts);
					break;

				// Private messaging:
				case '/query':
					$this->insertParsedMessageQuery($textParts);
					break;
				
				// Kicking offending users from the chat:
				case '/kick':
					$this->insertParsedMessageKick($textParts);
					break;
				
				// Listing banned users:
				case '/bans':
					$this->insertParsedMessageBans($textParts);
					break;
				
				// Unban user (remove from ban list):
				case '/unban':
					$this->insertParsedMessageUnban($textParts);
					break;
				
				// Describing actions:
				case '/me':
				case '/action':
					$this->insertParsedMessageAction($textParts);
					break;


				// Listing online Users:
				case '/who':	
					$this->insertParsedMessageWho($textParts);
					break;
				
				// Listing available channels:
				case '/list':	
					$this->insertParsedMessageList($textParts);
					break;

				// Retrieving the channel of a User:
				case '/whereis':
					$this->insertParsedMessageWhereis($textParts);
					break;
				
				// Listing information about a User:
				case '/whois':
					$this->insertParsedMessageWhois($textParts);
					break;
				
				// Rolling dice:
				case '/roll':				
					$this->insertParsedMessageRoll($textParts);
					break;

				// Switching userName:
				case '/nick':				
					$this->insertParsedMessageNick($textParts);
					break;
			
				// Custom or unknown command:
				default:
					if(!$this->parseCustomCommands($text, $textParts)) {				
						$this->insertChatBotMessage(
							$this->getPrivateMessageID(),
							'/error UnknownCommand '.$textParts[0]
						);
					}
			}

		} else {
			// No command found, just insert the plain message:
			$this->insertCustomMessage(
				$this->getUserID(),
				$this->getUserName(),
				$this->getUserRole(),
				$this->getChannel(),
				$text
			);
		}
	}

	function insertParsedMessageJoin($textParts) {
		if(count($textParts) == 1) {
			// join with no arguments is the own private channel, if allowed:
			if($this->isAllowedToCreatePrivateChannel()) {
				// Private channels are identified by square brackets:
				$this->switchChannel($this->getChannelNameFromChannelID($this->getPrivateChannelID()));
			} else {
				$this->insertChatBotMessage(
					$this->getPrivateMessageID(),
					'/error MissingChannelName'
				);
			}
		} else {
			$this->switchChannel($textParts[1]);
		}
	}
	
	function insertParsedMessagePrivMsg($textParts) {
		if($this->isAllowedToSendPrivateMessage()) {
			if(count($textParts) < 3) {
				if(count($textParts) == 2) {
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/error MissingText'
					);
				} else {
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/error MissingUserName'
					);
				}
			} else {
				// Get UserID from UserName:
				$toUserID = $this->getIDFromName($textParts[1]);
				if($toUserID === null) {
					if($this->getQueryUserName() !== null) {
						// Close the current query:
						$this->insertMessage('/query');		
					} else {
						$this->insertChatBotMessage(
							$this->getPrivateMessageID(),
							'/error UserNameNotFound '.$textParts[1]
						);
					}
				} else {
					// Insert /privaction command if /describe is used:
					$command = ($textParts[0] == '/describe') ? '/privaction' : '/privmsg';							
					// Copy of private message to current User:
					$this->insertCustomMessage(
						$this->getUserID(),
						$this->getUserName(),
						$this->getUserRole(),
						$this->getPrivateMessageID(),
						$command.'to '.$textParts[1].' '.implode(' ', array_slice($textParts, 2))
					);								
					// Private message to requested User:
					$this->insertCustomMessage(
						$this->getUserID(),
						$this->getUserName(),
						$this->getUserRole(),
						$this->getPrivateMessageID($toUserID),
						$command.' '.implode(' ', array_slice($textParts, 2)),
						null, 0, 1 //unread msg flag
					);
				}
			}
		} else {
			$this->insertChatBotMessage(
				$this->getPrivateMessageID(),
				'/error PrivateMessageNotAllowed'
			);
		}
	}
	function insertParsedMessageAbort($textParts) {
		$toUserID = $this->getIDFromName($textParts[1]);
		$this->insertChatBotMessage(
						$this->getPrivateMessageID($toUserID),
						'aborted'
					);
	}
	function insertParsedMessageInviteAgree($textParts) {
		if (count($textParts) == 2) {
			$toUserID = $this->getIDFromName($textParts[1]);
			$this->insertChatBotMessage(
							$this->getPrivateMessageID($toUserID),
							'/chnlchange '.$textParts[1]
						);
		} else {
				for ($i=1;$i<4;$i++){
					$toUserID = $this->getIDFromName($textParts[$i]);
					$this->insertChatBotMessage(
							$this->getPrivateMessageID($toUserID),
							'/chnlchange '.$textParts[$i]
						);
					};
			};
	}
	function insertParsedMessageInvite($textParts) {
		if($this->getChannel() == $this->getPrivateChannelID() || in_array($this->getChannel(), $this->getChannels())) {
			if(count($textParts) == 1) {
				$this->insertChatBotMessage(
					$this->getPrivateMessageID(),
					'/error MissingUserName'
				);
			} else {
				$toUserID = $this->getIDFromName($textParts[1]);
				if($toUserID === null) {
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/error UserNameNotFound '.$textParts[1]
					);
				} else {						
					// Add the invitation to the database:
					$this->addInvitation($toUserID);
					$invitationChannelName = $this->getChannelNameFromChannelID($this->getChannel());
					// Copy of invitation to current User:
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/inviteto '.$textParts[1].' '.$invitationChannelName
					);							
					// Invitation to requested User:
					$this->insertChatBotMessage(
						$this->getPrivateMessageID($toUserID),
						'/invite '.$this->getUserName().' '.$invitationChannelName
					);
				}
			}						
		} else {
			$this->insertChatBotMessage(
				$this->getPrivateMessageID(),
				'/error InviteNotAllowed'
			);
		}
	}
	function insertParsedMessageStartgroup($textParts) {
	$text = '/groupstarted '.$textParts[1].' started group chat, push "join group" button if you want to help start the group';
	$this->insertChatBotMessage(
	$this->getChannel(),
	$text
	);
	$sql = 'UPDATE `ajax_chat_online` SET
		`group`  	= 1
	WHERE
		userName = \''.$textParts[1].'\';';
				
	// Create a new SQL query:
	$result = $this->db->sqlQuery($sql);
	
	// Stop if an error occurs:
	if($result->error()) {
		echo $result->getError();
		die();
	}
	
	}
	function insertParsedMessageJoingroup($textParts) {
	$text = $textParts[1].' connected to the group chat start, push "join group" button if you want to help start the group';
	$this->insertChatBotMessage(
	$this->getChannel(),
	$text
	);
	$sql = 'UPDATE `ajax_chat_online` SET
		`group`  	= 1
	WHERE
		userName = \''.$textParts[1].'\';';
				
	// Create a new SQL query:
	$result = $this->db->sqlQuery($sql);
	
	// Stop if an error occurs:
	if($result->error()) {
		echo $result->getError();
		die();
	}
	$sql1 = 'SELECT
		sum(`group`) groupcount
	FROM
		`ajax_chat_online`
	WHERE
		`group` = 1;';

	// Create a new SQL query:
	$result1 = $this->db->sqlQuery($sql1);
	
	// Stop if an error occurs:
	if($result->error()) {
		echo $result->getError();
		die();
	}
	
	$row = $result1->fetch();

	if ($row['groupcount'] == 3) {
		$toUserID = $this->getIDFromName('admin');
		$this->addInvitation($toUserID);
		$invitationChannelName = $this->getChannelNameFromChannelID($this->getChannel());
		$sql2 = 'SELECT
			userName 
		FROM
			`ajax_chat_online`
		WHERE
			`group` = 1;';

		// Create a new SQL query:
		$result2 = $this->db->sqlQuery($sql2);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		$message = '/groupinvite';
		while($row2 = $result2->fetch()) {
				$message .= ' '.$row2['userName'];
			}
		$message .=' admin ';
					$this->insertChatBotMessage(
					$this->getPrivateMessageID($toUserID),
						$message.$invitationChannelName
						);
	
	}
	}
	function insertParsedMessageUninvite($textParts) {
		if($this->getChannel() == $this->getPrivateChannelID() || in_array($this->getChannel(), $this->getChannels())) {
			if(count($textParts) == 1) {
				$this->insertChatBotMessage(
					$this->getPrivateMessageID(),
					'/error MissingUserName'
				);
			} else {
				$toUserID = $this->getIDFromName($textParts[1]);
				if($toUserID === null) {
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/error UserNameNotFound '.$textParts[1]
					);
				} else {						
					// Remove the invitation from the database:
					$this->removeInvitation($toUserID);
					$invitationChannelName = $this->getChannelNameFromChannelID($this->getChannel());
					// Copy of uninvitation to current User:
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/uninviteto '.$textParts[1].' '.$invitationChannelName
					);			
					// Uninvitation to requested User:
					$this->insertChatBotMessage(
						$this->getPrivateMessageID($toUserID),
						'/uninvite '.$this->getUserName().' '.$invitationChannelName
					);
				}
			}						
		} else {
			$this->insertChatBotMessage(
				$this->getPrivateMessageID(),
				'/error UninviteNotAllowed'
			);						
		}
	}

	function insertParsedMessageQuery($textParts) {
		if($this->isAllowedToSendPrivateMessage()) {
			if(count($textParts) == 1) {
				if($this->getQueryUserName() !== null) {
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/queryClose '.$this->getQueryUserName()
					);							
					// Close the current query:
					$this->setQueryUserName(null);
				} else {
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/error NoOpenQuery'
					);
				}
			} else {
				if($this->getIDFromName($textParts[1]) === null) {
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/error UserNameNotFound '.$textParts[1]
					);
				} else {
					if($this->getQueryUserName() !== null) {
						// Close the current query:
						$this->insertMessage('/query');
					}
					// Open a query to the requested user:
					$this->setQueryUserName($textParts[1]);
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/queryOpen '.$textParts[1]
					);
				}
			}
		} else {
			$this->insertChatBotMessage(
				$this->getPrivateMessageID(),
				'/error PrivateMessageNotAllowed'
			);
		}
	}
		
	function insertParsedMessageKick($textParts) {
		// Only moderators/admins may kick users:
		if($this->getUserRole() == AJAX_CHAT_ADMIN || $this->getUserRole() == AJAX_CHAT_MODERATOR) {
			if(count($textParts) == 1) {
				$this->insertChatBotMessage(
					$this->getPrivateMessageID(),
					'/error MissingUserName'
				);
			} else {
				// Get UserID from UserName:
				$kickUserID = $this->getIDFromName($textParts[1]);
				if($kickUserID === null) {
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/error UserNameNotFound '.$textParts[1]
					);
				} else {
					// Check the role of the user to kick:
					$kickUserRole = $this->getRoleFromID($kickUserID);
					if($kickUserRole == AJAX_CHAT_ADMIN || ($kickUserRole == AJAX_CHAT_MODERATOR && $this->getUserRole() != AJAX_CHAT_ADMIN)) {
						// Admins and moderators may not be kicked:
						$this->insertChatBotMessage(
							$this->getPrivateMessageID(),
							'/error KickNotAllowed '.$textParts[1]
						);
					} else {
						// Kick user and insert message:
						$channel = $this->getChannelFromID($kickUserID);
						$banMinutes = (count($textParts) > 2) ? $textParts[2] : null;
						$this->kickUser($textParts[1], $banMinutes, $kickUserID);
						// If no channel found, user logged out before he could be kicked
						if($channel !== null) {
							$this->insertChatBotMessage(
								$channel,
								'/kick '.$textParts[1],
								null,
								1
							);
							// Send a copy of the message to the current user, if not in the channel:
							if($channel != $this->getChannel()) {
								$this->insertChatBotMessage(
									$this->getPrivateMessageID(),
									'/kick '.$textParts[1],
									null,
									1
								);
							}
						}
					}
				}
			}
		} else {
			$this->insertChatBotMessage(
				$this->getPrivateMessageID(),
				'/error CommandNotAllowed '.$textParts[0]
			);
		}
	}
		
	function insertParsedMessageBans($textParts) {
		// Only moderators/admins may see the list of banned users:
		if($this->getUserRole() == AJAX_CHAT_ADMIN || $this->getUserRole() == AJAX_CHAT_MODERATOR) {
			$this->removeExpiredBans();
			$bannedUsers = $this->getBannedUsers();
			if(count($bannedUsers) > 0) {
				$this->insertChatBotMessage(
					$this->getPrivateMessageID(),
					'/bans '.implode(' ', $bannedUsers)
				);
			} else {
				$this->insertChatBotMessage(
					$this->getPrivateMessageID(),
					'/bansEmpty -'
				);
			}
		} else {
			$this->insertChatBotMessage(
				$this->getPrivateMessageID(),
				'/error CommandNotAllowed '.$textParts[0]
			);
		}
	}
		
	function insertParsedMessageUnban($textParts) {
		// Only moderators/admins may unban users:
		if($this->getUserRole() == AJAX_CHAT_ADMIN || $this->getUserRole() == AJAX_CHAT_MODERATOR) {
			$this->removeExpiredBans();
			if(count($textParts) == 1) {
				$this->insertChatBotMessage(
					$this->getPrivateMessageID(),
					'/error MissingUserName'
				);
			} else {
				if(!in_array($textParts[1], $this->getBannedUsers())) {
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/error UserNameNotFound '.$textParts[1]
					);
				} else {
					// Unban user and insert message:
					$this->unbanUser($textParts[1]);
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/unban '.$textParts[1]
					);	
				}
			}
		} else {
			$this->insertChatBotMessage(
				$this->getPrivateMessageID(),
				'/error CommandNotAllowed '.$textParts[0]
			);
		}
	}
		
	function insertParsedMessageAction($textParts) {
		if(count($textParts) == 1) {
			$this->insertChatBotMessage(
				$this->getPrivateMessageID(),
				'/error MissingText'
			);
		} else {
			if($this->getQueryUserName() !== null) {
				// If we are in query mode, sent the action to the query user:
				$this->insertMessage('/describe '.$this->getQueryUserName().' '.implode(' ', array_slice($textParts, 1)));
			} else {
				$this->insertCustomMessage(
					$this->getUserID(),
					$this->getUserName(),
					$this->getUserRole(),
					$this->getChannel(),
					implode(' ', $textParts)
				);
			}
		}
	}
		
	function insertParsedMessageWho($textParts) {
		if(count($textParts) == 1) {
			if($this->isAllowedToListHiddenUsers()) {
				// List online users from any channel:
				$this->insertChatBotMessage(
					$this->getPrivateMessageID(),
					'/who '.implode(' ', $this->getOnlineUsers())
				);
			} else {
				// Get online users for all accessible channels:
				$channels = $this->getChannels();
				// Add the own private channel if allowed:
				if($this->isAllowedToCreatePrivateChannel()) {
					array_push($channels, $this->getPrivateChannelID());
				}
				// Add the invitation channels:
				foreach($this->getInvitations() as $channelID) {
					if(!in_array($channelID, $channels)) {
						array_push($channels, $channelID);
					}
				}
				$this->insertChatBotMessage(
					$this->getPrivateMessageID(),
					'/who '.implode(' ', $this->getOnlineUsers($channels))
				);
			}
		} else {
			$channelName = $textParts[1];					
			$channelID = $this->getChannelIDFromChannelName($channelName);
			if(!$this->validateChannel($channelID)) {
				// Invalid channel:
				$this->insertChatBotMessage(
					$this->getPrivateMessageID(),
					'/error InvalidChannelName '.$channelName
				);
			} else {
				// Get online users for the given channel:
				$onlineUsers = $this->getOnlineUsers(array($channelID));
				if(count($onlineUsers) > 0) {
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/whoChannel '.$channelName.' '.implode(' ', $onlineUsers)
					);
				} else {
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/whoEmpty -'
					);
				}
			}
		}
	}
		
	function insertParsedMessageList($textParts) {
		// Get the names of all accessible channels:
		$channelNames = $this->getChannelNames();
		// Add the own private channel, if allowed:
		if($this->isAllowedToCreatePrivateChannel()) {
			array_push($channelNames, $this->getPrivateChannelName());
		}
		// Add the invitation channels:
		foreach($this->getInvitations() as $channelID) {
			$channelName = $this->getChannelNameFromChannelID($channelID);
			if($channelName !== null && !in_array($channelName, $channelNames)) {
				array_push($channelNames, $channelName);
			}
		}
		$this->insertChatBotMessage(
			$this->getPrivateMessageID(),
			'/list '.implode(' ', $channelNames)
		);
	}

	function insertParsedMessageWhereis($textParts) {
		if(count($textParts) == 1) {
			$this->insertChatBotMessage(
				$this->getPrivateMessageID(),
				'/error MissingUserName'
			);
		} else {
			// Get UserID from UserName:
			$whereisUserID = $this->getIDFromName($textParts[1]);		
			if($whereisUserID === null) {
				$this->insertChatBotMessage(
					$this->getPrivateMessageID(),
					'/error UserNameNotFound '.$textParts[1]
				);
			} else {					
				$channelID = $this->getChannelFromID($whereisUserID);
				if($this->validateChannel($channelID)) {
					$channelName = $this->getChannelNameFromChannelID($channelID);					
				} else {
					$channelName = null;
				}
				if($channelName === null) {
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/error UserNameNotFound '.$textParts[1]
					);
				} else {
					// List user information:
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/whereis '.$textParts[1].' '.$channelName
					);	
				}
			}
		}
	}
			
	function insertParsedMessageWhois($textParts) {
		// Only moderators/admins:
		if($this->getUserRole() == AJAX_CHAT_ADMIN || $this->getUserRole() == AJAX_CHAT_MODERATOR) {
			if(count($textParts) == 1) {
				$this->insertChatBotMessage(
					$this->getPrivateMessageID(),
					'/error MissingUserName'
				);
			} else {
				// Get UserID from UserName:
				$whoisUserID = $this->getIDFromName($textParts[1]);
				if($whoisUserID === null) {
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/error UserNameNotFound '.$textParts[1]
					);
				} else {
					// List user information:
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/whois '.$textParts[1].' '.$this->getIPFromID($whoisUserID)
					);
				}
			}
		} else {
			$this->insertChatBotMessage(
				$this->getPrivateMessageID(),
				'/error CommandNotAllowed '.$textParts[0]
			);
		}
	}
			
	function insertParsedMessageRoll($textParts) {
		if(count($textParts) == 1) {
			// default is one d6:
			$text = '/roll '.$this->getUserName().' 1d6 '.$this->rollDice(6);
		} else {
			$diceParts = explode('d', $textParts[1]);
			if(count($diceParts) == 2) {
				$number = (int)$diceParts[0];
				$sides = (int)$diceParts[1];
				
				// Dice number must be an integer between 1 and 100, else roll only one:
				$number = ($number > 0 && $number <= 100) ?  $number : 1;
				
				// Sides must be an integer between 1 and 100, else take 6:
				$sides = ($sides > 0 && $sides <= 100) ?  $sides : 6;
				
				$text = '/roll '.$this->getUserName().' '.$number.'d'.$sides.' ';
				for($i=0; $i<$number; $i++) {
					if($i != 0)
						$text .= ',';
					$text .= $this->rollDice($sides);
				}
			} else {
				// if dice syntax is invalid, roll one d6:
				$text = '/roll '.$this->getUserName().' 1d6 '.$this->rollDice(6);
			}
		}
		$this->insertChatBotMessage(
			$this->getChannel(),
			$text
		);
	}
			
	function insertParsedMessageNick($textParts) {
		if(!$this->getConfig('allowNickChange') ||
			(!$this->getConfig('allowGuestUserName') && $this->getUserRole() == AJAX_CHAT_GUEST)) {
			$this->insertChatBotMessage(
				$this->getPrivateMessageID(),
				'/error CommandNotAllowed '.$textParts[0]
			);
		} else if(count($textParts) == 1) {
			$this->insertChatBotMessage(
				$this->getPrivateMessageID(),
				'/error MissingUserName'
			);
		} else {
			$newUserName = implode(' ', array_slice($textParts, 1));
			if($newUserName == $this->getLoginUserName()) {
				// Allow the user to regain the original login userName:
				$prefix = '';
				$suffix = '';
			} else if($this->getUserRole() == AJAX_CHAT_GUEST) {
				$prefix = $this->getConfig('guestUserPrefix');
				$suffix = $this->getConfig('guestUserSuffix');
			} else {
				$prefix = $this->getConfig('changedNickPrefix');
				$suffix = $this->getConfig('changedNickSuffix');
			}
			$maxLength =	$this->getConfig('userNameMaxLength')
							- $this->stringLength($prefix)
							- $this->stringLength($suffix);
			$newUserName = $this->trimString($newUserName, 'UTF-8', $maxLength, true);
			if(!$newUserName) {
				$this->insertChatBotMessage(
					$this->getPrivateMessageID(),
					'/error InvalidUserName'
				);
			} else {
				$newUserName = $prefix.$newUserName.$suffix;
				if($this->isUserNameInUse($newUserName)) {
					$this->insertChatBotMessage(
						$this->getPrivateMessageID(),
						'/error UserNameInUse'
					);
				} else {
					$oldUserName = $this->getUserName();
					$this->setUserName($newUserName);
					$this->updateOnlineList();
					// Add info message to update the client-side stored userName:
					$this->addInfoMessage($this->getUserName(), 'userName');
					$this->insertChatBotMessage(
						$this->getChannel(),
						'/nick '.$oldUserName.' '.$newUserName,
						null,
						2
					);
				}
			}
		}
	}
	
	function insertMessage($text) {
		if(!$this->isAllowedToWriteMessage())
			return;

		if(!$this->floodControl())
			return;

		$text = $this->trimMessageText($text);	
		if($text == '')
			return;
		
		if(!$this->onNewMessage($text))
			return;
		
		$text = $this->replaceCustomText($text);
		
		$this->insertParsedMessage($text);
	}

	
	
	function deleteMessage($messageID) {
		// Retrieve the channel of the given message:
		$sql = 'SELECT
					channel
				FROM
					'.$this->getDataBaseTable('messages').'
				WHERE
					id='.$this->db->makeSafe($messageID).';';
		
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		
		$row = $result->fetch();
		
		if($row['channel'] !== null) {
			$channel = $row['channel'];
			
			if($this->getUserRole() == AJAX_CHAT_ADMIN) {
				$condition = '';
			} else if($this->getUserRole() == AJAX_CHAT_MODERATOR) {
				$condition = '	AND
									NOT (userRole='.$this->db->makeSafe(AJAX_CHAT_ADMIN).')
								AND
									NOT (userRole='.$this->db->makeSafe(AJAX_CHAT_CHATBOT).')';
			} else if($this->getUserRole() == AJAX_CHAT_USER && $this->getConfig('allowUserMessageDelete')) {
				$condition = 'AND
								(
								userID='.$this->db->makeSafe($this->getUserID()).'
								OR
									(
									channel = '.$this->db->makeSafe($this->getPrivateMessageID()).'
									OR
									channel = '.$this->db->makeSafe($this->getPrivateChannelID()).'
									)
									AND
										NOT (userRole='.$this->db->makeSafe(AJAX_CHAT_ADMIN).')
									AND
										NOT (userRole='.$this->db->makeSafe(AJAX_CHAT_CHATBOT).')
								)';
			} else {
				return false;
			}
	
			// Remove given message from the database:
			$sql = 'DELETE FROM
						'.$this->getDataBaseTable('messages').'
					WHERE
						id='.$this->db->makeSafe($messageID).'
						'.$condition.';';
			
			// Create a new SQL query:
			$result = $this->db->sqlQuery($sql);
			
			// Stop if an error occurs:
			if($result->error()) {
				echo $result->getError();
				die();
			}
			
			if($result->affectedRows() == 1) {
				// Insert a deletion command to remove the message from the clients chatlists:
				$this->insertChatBotMessage($channel, '/delete '.$messageID);
				return true;
			}
		}
		return false;
	}
	
	function floodControl() {
		// Moderators and Admins need no flood control:
		if($this->getUserRole() == AJAX_CHAT_MODERATOR || $this->getUserRole() == AJAX_CHAT_ADMIN) {
			return true;
		}
		$time = time();
		// Check the time of the last inserted message:
		if($this->getInsertedMessagesRateTimeStamp()+60 < $time) {
			$this->setInsertedMessagesRateTimeStamp($time);
			$this->setInsertedMessagesRate(1);
		} else {
			// Increase the inserted messages rate:
			$rate = $this->getInsertedMessagesRate()+1;
			$this->setInsertedMessagesRate($rate);
			// Check if message rate is too high:
			if($rate > $this->getConfig('maxMessageRate')) {
				$this->insertChatBotMessage(
					$this->getPrivateMessageID(),
					'/error MaxMessageRate'
				);
				// Return false so the message is not inserted:
				return false;
			}
		}
		return true;
	}
	
	function isAllowedToWriteMessage() {
		if($this->getUserRole() != AJAX_CHAT_GUEST)
			return true;
		if($this->getConfig('allowGuestWrite'))
			return true;
		return false;
	}

	function insertChatBotMessage($channelID, $messageText, $ip=null, $mode=0) {
		$this->insertCustomMessage(
			$this->getConfig('chatBotID'),
			$this->getConfig('chatBotName'),
			AJAX_CHAT_CHATBOT,
			$channelID,
			$messageText,
			$ip,
			$mode
		);
	}
	
	function insertCustomMessage($userID, $userName, $userRole, $channelID, $text, $ip=null, $mode=0, $priv_status=0) {
		// The $mode parameter is used for socket updates:
		// 0 = normal messages
		// 1 = channel messages (e.g. login/logout, channel enter/leave, kick)
		// 2 = messages with online user updates (nick)
		
		$ip = $ip ? $ip : $_SERVER['REMOTE_ADDR'];
		
		$sql = 'INSERT INTO '.$this->getDataBaseTable('messages').'(
								userID,
								userName,
								userRole,
								channel,
								dateTime,
								ip,
								text,
								unread
							)
				VALUES (
					'.$this->db->makeSafe($userID).',
					'.$this->db->makeSafe($userName).',
					'.$this->db->makeSafe($userRole).',
					'.$this->db->makeSafe($channelID).',
					NOW(),
					'.$this->db->makeSafe($this->ipToStorageFormat($ip)).',
					'.$this->db->makeSafe($text).',
					'.$this->db->makeSafe($priv_status).'
				);';

		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		
		if($this->getConfig('socketServerEnabled')) {
			$this->sendSocketMessage(
				$this->getSocketBroadcastMessage(
					$this->db->getLastInsertedID(),
					time(),
					$userID,
					$userName,
					$userRole,
					$channelID,
					$text,
					$mode
				)
			);	
		}
	}

	function getSocketBroadcastMessage(
		$messageID,
		$timeStamp,
		$userID,
		$userName,
		$userRole,
		$channelID,
		$text,
		$mode	
		) {
		// The $mode parameter:
		// 0 = normal messages
		// 1 = channel messages (e.g. login/logout, channel enter/leave, kick)
		// 2 = messages with online user updates (nick)

		// Get the message XML content:
		$xml = '<root chatID="'.$this->getConfig('socketServerChatID').'" channelID="'.$channelID.'" mode="'.$mode.'">';
		if($mode) {
			// Add the list of online users if the user list has been updated ($mode > 0):
			$xml .= $this->getChatViewOnlineUsersXML(array($channelID));
		}
		if($mode != 1 || $this->getConfig('showChannelMessages')) {
			$xml .= '<messages>';
			$xml .= $this->getChatViewMessageXML(
				$messageID,
				$timeStamp,
				$userID,
				$userName,
				$userRole,
				$channelID,
				$text
			);
			$xml .= '</messages>';	
		}
		$xml .= '</root>';
		return $xml;
	}

	function sendSocketMessage($message) {
		// Open a TCP socket connection to the socket server:
		if($socket = @socket_create(AF_INET, SOCK_STREAM, SOL_TCP)) {
			if(@socket_connect($socket,	$this->getConfig('socketServerIP'),	$this->getConfig('socketServerPort'))) {
				// Append a null-byte to the string as EOL (End Of Line) character
				// which is required by Flash XML socket communication:
				$message .= "\0";
				@socket_write(
					$socket,
					$message,
					strlen($message) // Using strlen to count the bytes instead of the number of UTF-8 characters
				);
			}
			@socket_close($socket);
		}		
	}

	function updateSocketAuthentication($userID, $socketRegistrationID=null, $channels=null) {
		// If no $socketRegistrationID or no $channels are given the authentication is removed for the given user:
		$authentication = '<authenticate chatID="'.$this->getConfig('socketServerChatID').'" userID="'.$userID.'" regID="'.$socketRegistrationID.'">';
		if($channels) {
			foreach($channels as $channelID) {
				$authentication .= '<channel id="'.$channelID.'"/>';
			}
		}
		$authentication .= '</authenticate>';
		$this->sendSocketMessage($authentication);
	}

	function setSocketRegistrationID($value) {
		$this->setSessionVar('SocketRegistrationID', $value);
	}
	
	function getSocketRegistrationID() {
		return $this->getSessionVar('SocketRegistrationID');
	}
	
	function rollDice($sides) {
		// seed with microseconds since last "whole" second:
		mt_srand((double)microtime()*1000000);
		
		return mt_rand(1, $sides);
	}
	
	function kickUser($userName, $banMinutes=null, $userID=null) {
		if($userID === null) {
			$userID = $this->getIDFromName($userName);
		}
		if($userID === null) {
			return;
		}

		$banMinutes = $banMinutes ? $banMinutes : $this->getConfig('defaultBanTime');

		if($banMinutes) {
			// Ban User for the given time in minutes:
			$this->banUser($userName, $banMinutes, $userID);
		}

		// Remove given User from online list:
		$sql = 'DELETE FROM
					'.$this->getDataBaseTable('online').'
				WHERE
					userID = '.$this->db->makeSafe($userID).';';
		
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}

		// Update the socket server authentication for the kicked user:
		if($this->getConfig('socketServerEnabled')) {
			$this->updateSocketAuthentication($userID);
		}
		
		$this->removeUserFromOnlineUsersData($userID);
	}
	

	
	function getBannedUsersData($key=null, $value=null) {
		if($this->_bannedUsersData === null) {
			$this->_bannedUsersData = array();

			$sql = 'SELECT
						userID,
						userName,
						ip
					FROM
						'.$this->getDataBaseTable('bans').'
					WHERE
						NOW() < dateTime;';
			
			// Create a new SQL query:
			$result = $this->db->sqlQuery($sql);
			
			// Stop if an error occurs:
			if($result->error()) {
				echo $result->getError();
				die();
			}
			
			while($row = $result->fetch()) {
				$row['ip'] = $this->ipFromStorageFormat($row['ip']);
				array_push($this->_bannedUsersData, $row);
			}
			
			$result->free();
		}
		
		if($key) {
			$bannedUsersData = array();		
			foreach($this->_bannedUsersData as $bannedUserData) {
				if(!isset($bannedUserData[$key])) {
					return $bannedUsersData;
				}
				if($value) {
					if($bannedUserData[$key] == $value) {
						array_push($bannedUsersData, $bannedUserData);
					} else {
						continue;
					}
				} else {
					array_push($bannedUsersData, $bannedUserData[$key]);	
				}
			}
			return $bannedUsersData;
		}

		return $this->_bannedUsersData;
	}
	
	function getBannedUsers() {
		return $this->getBannedUsersData('userName');
	}
	
	function banUser($userName, $banMinutes=null, $userID=null) {
		if($userID === null) {
			$userID = $this->getIDFromName($userName);
		}
		$ip = $this->getIPFromID($userID);
		if(!$ip || $userID === null) {
			return;
		}

		// Remove expired bans:
		$this->removeExpiredBans();
		
		$banMinutes = (int)$banMinutes;
		if(!$banMinutes) {
			// If banMinutes is not a valid integer, use the defaultBanTime:
			$banMinutes = $this->getConfig('defaultBanTime');
		}
		
		$sql = 'INSERT INTO '.$this->getDataBaseTable('bans').'(
					userID,
					userName,
					dateTime,
					ip
				)
				VALUES (
					'.$this->db->makeSafe($userID).',
					'.$this->db->makeSafe($userName).',
					DATE_ADD(NOW(), interval '.$this->db->makeSafe($banMinutes).' MINUTE),
					'.$this->db->makeSafe($this->ipToStorageFormat($ip)).'
				);';	
		
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
	}
	
	function unbanUser($userName) {
		$sql = 'DELETE FROM
					'.$this->getDataBaseTable('bans').'
				WHERE
					userName = '.$this->db->makeSafe($userName).';';
		
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
	}
	
	function removeExpiredBans() {
		$sql = 'DELETE FROM
					'.$this->getDataBaseTable('bans').'
				WHERE
					dateTime < NOW();';
		
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
	}
	
	function setInactive($userID, $userName=null) {
		$condition = 'userID='.$this->db->makeSafe($userID);
		if($userName !== null) {
			$condition .= ' OR userName='.$this->db->makeSafe($userName);
		}
		$sql = 'UPDATE
					'.$this->getDataBaseTable('online').'
				SET
					dateTime = DATE_SUB(NOW(), interval '.(intval($this->getConfig('inactiveTimeout'))+1).' MINUTE)
				WHERE
					'.$condition.';';
					
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		
		$this->resetOnlineUsersData();
	}
	
	function removeInactive() {
		$sql = 'SELECT
					userID,
					userName,
					channel
				FROM
					'.$this->getDataBaseTable('online').'
				WHERE
					NOW() > DATE_ADD(dateTime, interval '.$this->getConfig('inactiveTimeout').' MINUTE);';
		
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		
		if($result->numRows() > 0) {
			$condition = '';
			while($row = $result->fetch()) {
				if(!empty($condition))
					$condition .= ' OR ';
				// Add userID to condition for removal:
				$condition .= 'userID='.$this->db->makeSafe($row['userID']);

				// Update the socket server authentication for the kicked user:
				if($this->getConfig('socketServerEnabled')) {
					$this->updateSocketAuthentication($row['userID']);
				}

				$this->removeUserFromOnlineUsersData($row['userID']);
				
				// Insert logout timeout message:
				$text = '/logout '.$row['userName'].' Timeout';
				$this->insertChatBotMessage(
					$row['channel'],
					$text,
					null,
					1
				);
			}
			
			$result->free();
			
			$sql = 'DELETE FROM
						'.$this->getDataBaseTable('online').'
					WHERE
						'.$condition.';';
			
			// Create a new SQL query:
			$result = $this->db->sqlQuery($sql);
			
			// Stop if an error occurs:
			if($result->error()) {
				echo $result->getError();
				die();
			}
		}
	}

	function updateOnlineStatus() {
		// Update online status every 50 seconds (this allows update requests to be in time):
		if(!$this->getStatusUpdateTimeStamp() || ((time() - $this->getStatusUpdateTimeStamp()) > 50)) {
			$this->updateOnlineList();
			$this->setStatusUpdateTimeStamp(time());
		}
	}
	
	function checkAndRemoveInactive() {
		// Remove inactive users every inactiveCheckInterval:
		if(!$this->getInactiveCheckTimeStamp() || ((time() - $this->getInactiveCheckTimeStamp()) > $this->getConfig('inactiveCheckInterval')*60)) {
			$this->removeInactive();
			$this->setInactiveCheckTimeStamp(time());
		}
	}
	
	function sendXMLMessages() {		
		$httpHeader = new AJAXChatHTTPHeader('UTF-8', 'text/xml');

		// Send HTTP header:
		$httpHeader->send();
		
		// Output XML messages:
		echo $this->getXMLMessages();
	}

	function getXMLMessages() {
		switch($this->getView()) {
			case 'chat':
				return $this->getChatViewXMLMessages();
			case 'teaser':
				return $this->getTeaserViewXMLMessages();
			case 'logs':
				return $this->getLogsViewXMLMessages();
			default:
				return $this->getLogoutXMLMessage();
		}
	}

	function getMessageCondition() {
		$condition = 	'id > '.$this->db->makeSafe($this->getRequestVar('lastID')).'
						AND (
							channel = '.$this->db->makeSafe($this->getChannel()).'
							OR
							channel = '.$this->db->makeSafe($this->getPrivateMessageID()).'
						)
						AND
						';
		if($this->getConfig('requestMessagesPriorChannelEnter') ||
			($this->getConfig('requestMessagesPriorChannelEnterList') && in_array($this->getChannel(), $this->getConfig('requestMessagesPriorChannelEnterList')))) {
			$condition .= 'NOW() < DATE_ADD(dateTime, interval '.$this->getConfig('requestMessagesTimeDiff').' HOUR)';
		} else {
			$condition .= 'dateTime >= \''.date('Y-m-d H:i:s', $this->getChannelEnterTimeStamp()).'\'';	
		}
		return $condition;
	}
	
	function getMessageFilter() {
			$filterChannelMessages = '';
			if(!$this->getConfig('showChannelMessages') || $this->getRequestVar('shoutbox')) {
				$filterChannelMessages = '	AND NOT (
											text LIKE (\'/login%\')
											OR
											text LIKE (\'/logout%\')
											OR
											text LIKE (\'/channelEnter%\')
											OR
											text LIKE (\'/channelLeave%\')
											OR
											text LIKE (\'/kick%\')
										)';
			}
			return $filterChannelMessages;		
	}

	function getInfoMessagesXML() {
		$xml = '<infos>';
		// Go through the info messages:
		foreach($this->getInfoMessages() as $type=>$infoArray) {
			foreach($infoArray as $info) {
				$xml .= '<info type="'.$type.'">';
				$xml .= '<![CDATA['.$this->encodeSpecialChars($info).']]>';
				$xml .= '</info>';
			}
		}
		$xml .= '</infos>';
		return $xml;
	}

	function getChatViewOnlineUsersXML($channelIDs) {
		// Get the online users for the given channels:
		$onlineUsersData = $this->getOnlineUsersData($channelIDs);		
		$xml = '<users>';
		foreach($onlineUsersData as $onlineUserData) {
			$xml .= '<user';
			$xml .= ' userID="'.$onlineUserData['userID'].'"';
			$xml .= ' userRole="'.$onlineUserData['userRole'].'"';
			$xml .= ' channelID="'.$onlineUserData['channel'].'"';
			$xml .= '>';
			$xml .= '<![CDATA['.$this->encodeSpecialChars($onlineUserData['userName']).']]>';
			$xml .= '</user>';
		}
		$xml .= '</users>';	
		return $xml;
	}

	function getLogoutXMLMessage() {
		$xml = '<?xml version="1.0" encoding="UTF-8"?>';
		$xml .= '<root>';
		$xml .= '<infos>';
		$xml .= '<info type="logout">';
		$xml .= '<![CDATA['.$this->encodeSpecialChars($this->getConfig('logoutData')).']]>';
		$xml .= '</info>';
		$xml .= '</infos>';
		$xml .= '</root>';
		return $xml;
	}

	function getChatViewMessageXML(
		$messageID,
		$timeStamp,
		$userID,
		$userName,
		$userRole,
		$channelID,
		$text
		) {
		$message = '<message';
		$message .= ' id="'.$messageID.'"';
		$message .= ' dateTime="'.date('r', $timeStamp).'"';
		$message .= ' userID="'.$userID.'"';
		$message .= ' userRole="'.$userRole.'"';
		$message .= ' channelID="'.$channelID.'"';
		$message .= '>';
		$message .= '<username><![CDATA['.$this->encodeSpecialChars($userName).']]></username>';
		$message .= '<text><![CDATA['.$this->encodeSpecialChars($text).']]></text>';
		$message .= '</message>';
		return $message;
	}

	function getChatViewMessagesXML() {
		// Get the last messages in descending order (this optimises the LIMIT usage):
		$sql = 'SELECT
					id,
					userID,
					userName,
					userRole,
					channel AS channelID,
					UNIX_TIMESTAMP(dateTime) AS timeStamp,
					text
				FROM
					'.$this->getDataBaseTable('messages').'
				WHERE
					'.$this->getMessageCondition().'
					'.$this->getMessageFilter().'
				ORDER BY
					id
					DESC
				LIMIT '.$this->getConfig('requestMessagesLimit').';';

		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		
		$messages = '';
		
		// Add the messages in reverse order so it is ascending again:
		while($row = $result->fetch()) {			
			$message = $this->getChatViewMessageXML(
				$row['id'],
				$row['timeStamp'],
				$row['userID'],
				$row['userName'],
				$row['userRole'],
				$row['channelID'],
				$row['text']
			);		
			$messages = $message.$messages;
		}
		$result->free();		
		
		$messages = '<messages>'.$messages.'</messages>';
		return $messages;
	}
	
	function getChatViewXMLMessages() {
		$xml = '<?xml version="1.0" encoding="UTF-8"?>';
		$xml .= '<root>';
		$xml .= $this->getInfoMessagesXML();
		$xml .= $this->getChatViewOnlineUsersXML(array($this->getChannel()));
		$xml .= $this->getChatViewMessagesXML();
		$xml .= '</root>';		
		return $xml;
	}

	function getTeaserMessageCondition() {
		$channelID = $this->getValidRequestChannelID();		
		$condition = 	'channel = '.$this->db->makeSafe($channelID).'
						AND
						';
		if($this->getConfig('requestMessagesPriorChannelEnter') ||
			($this->getConfig('requestMessagesPriorChannelEnterList') && in_array($channelID, $this->getConfig('requestMessagesPriorChannelEnterList')))) {
			$condition .= 'NOW() < DATE_ADD(dateTime, interval '.$this->getConfig('requestMessagesTimeDiff').' HOUR)';
		} else {
			// Teaser content may not be shown for this channel:
			$condition .= '0 = 1';	
		}
		return $condition;
	}

	function getTeaserViewMessagesXML() {
		// Get the last messages in descending order (this optimises the LIMIT usage):
		$sql = 'SELECT
					id,
					userID,
					userName,
					userRole,
					channel AS channelID,
					UNIX_TIMESTAMP(dateTime) AS timeStamp,
					text
				FROM
					'.$this->getDataBaseTable('messages').'
				WHERE
					'.$this->getTeaserMessageCondition().'
					'.$this->getMessageFilter().'
				ORDER BY
					id
					DESC
				LIMIT '.$this->getConfig('requestMessagesLimit').';';

		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		
		$messages = '';
		
		// Add the messages in reverse order so it is ascending again:
		while($row = $result->fetch()) {			
			$message = '';
			$message .= '<message';
			$message .= ' id="'.$row['id'].'"';
			$message .= ' dateTime="'.date('r', $row['timeStamp']).'"';
			$message .= ' userID="'.$row['userID'].'"';
			$message .= ' userRole="'.$row['userRole'].'"';
			$message .= ' channelID="'.$row['channelID'].'"';
			$message .= '>';
			$message .= '<username><![CDATA['.$this->encodeSpecialChars($row['userName']).']]></username>';
			$message .= '<text><![CDATA['.$this->encodeSpecialChars($row['text']).']]></text>';
			$message .= '</message>';
			$messages = $message.$messages;
		}
		$result->free();	
		
		$messages = '<messages>'.$messages.'</messages>';
		return $messages;
	}

	function getTeaserViewXMLMessages() {
		$xml = '<?xml version="1.0" encoding="UTF-8"?>';
		$xml .= '<root>';
		$xml .= $this->getInfoMessagesXML();
		$xml .= $this->getTeaserViewMessagesXML();
		$xml .= '</root>';		
		return $xml;
	}
	
	function getLogsViewCondition() {
		$condition = 'id > '.$this->db->makeSafe($this->getRequestVar('lastID'));
		
		// Check the channel condition:
		switch($this->getRequestVar('channelID')) {
			case '-3':
				// Just display messages from all accessible channels
				if($this->getUserRole() != AJAX_CHAT_ADMIN) {
					$condition .= ' AND (channel = '.$this->db->makeSafe($this->getPrivateMessageID());
					$condition .= ' OR channel = '.$this->db->makeSafe($this->getPrivateChannelID());
					foreach($this->getChannels() as $channel) {
						if($this->getConfig('logsUserAccessChannelList') && !in_array($channel, $this->getConfig('logsUserAccessChannelList'))) {
							continue;
						}
						$condition .= ' OR channel = '.$this->db->makeSafe($channel);
					}
					$condition .= ')';
				}
				break;
			case '-2':
				if($this->getUserRole() != AJAX_CHAT_ADMIN) {
					$condition .= ' AND channel = '.($this->getPrivateMessageID());
				} else {
					$condition .= ' AND channel > '.($this->getConfig('privateMessageDiff')-1);
				}
				break;
			case '-1':
				if($this->getUserRole() != AJAX_CHAT_ADMIN) {
					$condition .= ' AND channel = '.($this->getPrivateChannelID());
				} else {
					$condition .= ' AND (channel > '.($this->getConfig('privateChannelDiff')-1).' AND channel < '.($this->getConfig('privateMessageDiff')).')';
				}
				break;
			default:
				if(($this->getUserRole() == AJAX_CHAT_ADMIN || !$this->getConfig('logsUserAccessChannelList') || in_array($this->getRequestVar('channelID'), $this->getConfig('logsUserAccessChannelList')))
					&& $this->validateChannel($this->getRequestVar('channelID'))) {
					$condition .= ' AND channel = '.$this->db->makeSafe($this->getRequestVar('channelID'));
				} else {
					// No valid channel:
					$condition .= ' AND 0 = 1';
				}
		}
		
		// Check the period condition:
		$hour	= ($this->getRequestVar('hour') === null || $this->getRequestVar('hour') > 23 || $this->getRequestVar('hour') < 0) ? null : $this->getRequestVar('hour');
		$day	= ($this->getRequestVar('day') === null || $this->getRequestVar('day') > 31 || $this->getRequestVar('day') < 1) ? null : $this->getRequestVar('day');
		$month	= ($this->getRequestVar('month') === null || $this->getRequestVar('month') > 12 || $this->getRequestVar('month') < 1) ? null : $this->getRequestVar('month');
		$year	= ($this->getRequestVar('year') === null || $this->getRequestVar('year') > date('Y') || $this->getRequestVar('year') < $this->getConfig('logsFirstYear')) ? null : $this->getRequestVar('year');

		// If a time (hour) is given but no date (year, month, day), use the current date:
		if($hour !== null) {
			if($day === null)
				$day = date('j');
			if($month === null)
				$month = date('n');
			if($year === null)
				$year = date('Y');
		}
		
		if($year === null) {
			// No year given, so no period condition
		} else if($month === null) {
			// Define the given year as period:
			$periodStart = mktime(0, 0, 0, 1, 1, $year);
			// The last day in a month can be expressed by using 0 for the day of the next month:
			$periodEnd = mktime(23, 59, 59, 13, 0, $year);
		} else if($day === null) {
			// Define the given month as period:
			$periodStart = mktime(0, 0, 0, $month, 1, $year);
			// The last day in a month can be expressed by using 0 for the day of the next month:
			$periodEnd = mktime(23, 59, 59, $month+1, 0, $year);
		} else if($hour === null){
			// Define the given day as period:
			$periodStart = mktime(0, 0, 0, $month, $day, $year);
			$periodEnd = mktime(23, 59, 59, $month, $day, $year);
		} else {
			// Define the given hour as period:
			$periodStart = mktime($hour, 0, 0, $month, $day, $year);
			$periodEnd = mktime($hour, 59, 59, $month, $day, $year);
		}
		
		if(isset($periodStart))
			$condition .= ' AND dateTime > \''.date('Y-m-d H:i:s', $periodStart).'\' AND dateTime <= \''.date('Y-m-d H:i:s', $periodEnd).'\'';
		
		// Check the search condition:
		if($this->getRequestVar('search')) {
			if(($this->getUserRole() == AJAX_CHAT_ADMIN || $this->getUserRole() == AJAX_CHAT_MODERATOR) && strpos($this->getRequestVar('search'), 'ip=') === 0) {
				// Search for messages with the given IP:
				$ip = substr($this->getRequestVar('search'), 3);
				$condition .= ' AND (ip = '.$this->db->makeSafe($this->ipToStorageFormat($ip)).')';
			} else if(strpos($this->getRequestVar('search'), 'userID=') === 0) {
				// Search for messages with the given userID:
				$userID = substr($this->getRequestVar('search'), 7);
				$condition .= ' AND (userID = '.$this->db->makeSafe($userID).')';
			} else {
				// Use the search value as regular expression on message text and username:
				$condition .= ' AND (userName REGEXP '.$this->db->makeSafe($this->getRequestVar('search')).' OR text REGEXP '.$this->db->makeSafe($this->getRequestVar('search')).')';
			}
		}
		
		// If no period or search condition is given, just monitor the last messages on the given channel:
		if(!isset($periodStart) && !$this->getRequestVar('search')) {
			$condition .= ' AND NOW() < DATE_ADD(dateTime, interval '.$this->getConfig('logsRequestMessagesTimeDiff').' HOUR)';
		}

		return $condition;
	}

	function getLogsViewMessagesXML() {
		$sql = 'SELECT
					id,
					userID,
					userName,
					userRole,
					channel AS channelID,
					UNIX_TIMESTAMP(dateTime) AS timeStamp,
					ip,
					text
				FROM
					'.$this->getDataBaseTable('messages').'
				WHERE
					'.$this->getLogsViewCondition().'
				ORDER BY
					id
				LIMIT '.$this->getConfig('logsRequestMessagesLimit').';';
					
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}

		$xml = '<messages>';
		while($row = $result->fetch()) {
			$xml .= '<message';
			$xml .= ' id="'.$row['id'].'"';
			$xml .= ' dateTime="'.date('r', $row['timeStamp']).'"';
			$xml .= ' userID="'.$row['userID'].'"';
			$xml .= ' userRole="'.$row['userRole'].'"';
			$xml .= ' channelID="'.$row['channelID'].'"';
			if($this->getUserRole() == AJAX_CHAT_ADMIN || $this->getUserRole() == AJAX_CHAT_MODERATOR) {
				$xml .= ' ip="'.$this->ipFromStorageFormat($row['ip']).'"';					
			}
			$xml .= '>';
			$xml .= '<username><![CDATA['.$this->encodeSpecialChars($row['userName']).']]></username>';
			$xml .= '<text><![CDATA['.$this->encodeSpecialChars($row['text']).']]></text>';
			$xml .= '</message>';
		}
		$result->free();

		$xml .= '</messages>';
		
		return $xml;
	}
	
	function getLogsViewXMLMessages() {
		$xml = '<?xml version="1.0" encoding="UTF-8"?>';
		$xml .= '<root>';
		$xml .= $this->getInfoMessagesXML();
		$xml .= $this->getLogsViewMessagesXML();
		$xml .= '</root>';		
		return $xml;
	}
		
	function purgeLogs() {
		$sql = 'DELETE FROM
					'.$this->getDataBaseTable('messages').'
				WHERE
					dateTime < DATE_SUB(NOW(), interval '.$this->getConfig('logsPurgeTimeDiff').' DAY);';
		
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
	}
	
	function getInfoMessages($type=null) {
		if(!isset($this->_infoMessages)) {
			$this->_infoMessages = array();
		}
		if($type) {
			if(!isset($this->_infoMessages[$type])) {
				$this->_infoMessages[$type] = array();
			}
			return $this->_infoMessages[$type];
		} else {
			return $this->_infoMessages;
		}
	}
	
	function addInfoMessage($info, $type='error') {
		if(!isset($this->_infoMessages)) {
			$this->_infoMessages = array();
		}
		if(!isset($this->_infoMessages[$type])) {
			$this->_infoMessages[$type] = array();
		}	
		if(!in_array($info, $this->_infoMessages[$type])) {
			array_push($this->_infoMessages[$type], $info);
		}
	}
	
	function getRequestVars() {
		return $this->_requestVars;
	}
	
	function getRequestVar($key) {
		if($this->_requestVars && isset($this->_requestVars[$key])) {
			return $this->_requestVars[$key];
		}
		return null;
	}
	
	function setRequestVar($key, $value) {
		if(!$this->_requestVars) {
			$this->_requestVars = array();
		}
		$this->_requestVars[$key] = $value;
	}

	function getOnlineUsersData($channelIDs=null, $key=null, $value=null) {
		if($this->_onlineUsersData === null) {
			$this->_onlineUsersData = array();
			
			$sql = 'SELECT
						userID,
						userName,
						userRole,
						channel,
						UNIX_TIMESTAMP(dateTime) AS timeStamp,
						ip
					FROM
						'.$this->getDataBaseTable('online').'
					ORDER BY
						userName;';
			
			// Create a new SQL query:
			$result = $this->db->sqlQuery($sql);
			
			// Stop if an error occurs:
			if($result->error()) {
				echo $result->getError();
				die();
			}
			
			while($row = $result->fetch()) {
				$row['ip'] = $this->ipFromStorageFormat($row['ip']);
				array_push($this->_onlineUsersData, $row);
			}
			
			$result->free();
		}
		
		if($channelIDs || $key) {
			$onlineUsersData = array();		
			foreach($this->_onlineUsersData as $userData) {
				if($channelIDs && !in_array($userData['channel'], $channelIDs)) {
					continue;
				}
				if($key) {
					if(!isset($userData[$key])) {
						return $onlineUsersData;
					}
					if($value !== null) {
						if($userData[$key] == $value) {
							array_push($onlineUsersData, $userData);
						} else {
							continue;
						}
					} else {
						array_push($onlineUsersData, $userData[$key]);	
					}
				} else {
					array_push($onlineUsersData, $userData);
				}
			}
			return $onlineUsersData;
		}
		
		return $this->_onlineUsersData;
	}

	function removeUserFromOnlineUsersData($userID=null) {
		if(!$this->_onlineUsersData) {
			return;
		}
		$userID = ($userID === null) ? $this->getUserID() : $userID;
		for($i=0; $i<count($this->_onlineUsersData); $i++) {
			if($this->_onlineUsersData[$i]['userID'] == $userID) {
				array_splice($this->_onlineUsersData, $i, 1);
				break;	
			}
		}
	}
	
	function resetOnlineUsersData() {
		$this->_onlineUsersData = null;
	}

	function getOnlineUsers($channelIDs=null) {
		return $this->getOnlineUsersData($channelIDs, 'userName');
	}

	function getOnlineUserIDs($channelIDs=null) {
		return $this->getOnlineUsersData($channelIDs, 'userID');
	}

	function startSession() {
		if(!session_id()) {
			// Set the session name:
			session_name($this->getConfig('sessionName'));

			// Set session cookie parameters:
			session_set_cookie_params(
				0, // The session is destroyed on logout anyway, so no use to set this
				$this->getConfig('sessionCookiePath'),
				$this->getConfig('sessionCookieDomain'),
				$this->getConfig('sessionCookieSecure')
			);

			// Start the session:
			session_start();
			
			// We started a new session:
			$this->_sessionNew = true;
		}
	}
	
	function destroySession() {
		if($this->_sessionNew) {	
			// Delete all session variables:
			$_SESSION = array();
			
			// Delete the session cookie:
			if (isset($_COOKIE[session_name()])) {
				setcookie(
					session_name(),
					'',
					time()-42000,
					$this->getConfig('sessionCookiePath'),
					$this->getConfig('sessionCookieDomain'),
					$this->getConfig('sessionCookieSecure')
				);
			}
			
			// Destroy the session:
			session_destroy();
		} else {
			// Unset all session variables starting with the sessionKeyPrefix:
			foreach($_SESSION as $key=>$value) {
				if(strpos($key, $this->getConfig('sessionKeyPrefix')) === 0) {
					unset($_SESSION[$key]);
				}
			}
		}
	}

	function regenerateSessionID() {
		if($this->_sessionNew) {
			// Regenerate session id:
			@session_regenerate_id(true);
		}
	}

	function getSessionVar($key, $prefix=null) {
		if($prefix === null)
			$prefix = $this->getConfig('sessionKeyPrefix');

		// Return the session value if existing:
		if(isset($_SESSION[$prefix.$key]))
			return $_SESSION[$prefix.$key];
		else
			return null;
	}
	
	function setSessionVar($key, $value, $prefix=null) {
		if($prefix === null)
			$prefix = $this->getConfig('sessionKeyPrefix');
		
		// Set the session value:
		$_SESSION[$prefix.$key] = $value;
	}
	
	function getSessionIP() {
		return $this->getSessionVar('IP');
	}
	
	function setSessionIP($ip) {
		$this->setSessionVar('IP', $ip);
	}
	
	function getQueryUserName() {
		return $this->getSessionVar('QueryUserName');
	}
	
	function setQueryUserName($userName) {
		$this->setSessionVar('QueryUserName', $userName);
	}
	
	function getInvitations() {
		if($this->_invitations === null) {
			$this->_invitations = array();
			
			$sql = 'SELECT
						channel
					FROM
						'.$this->getDataBaseTable('invitations').'
					WHERE
						userID='.$this->db->makeSafe($this->getUserID()).'
						AND
						DATE_SUB(NOW(), interval 1 DAY) < dateTime;';
			
			// Create a new SQL query:
			$result = $this->db->sqlQuery($sql);
			
			// Stop if an error occurs:
			if($result->error()) {
				echo $result->getError();
				die();
			}
			
			while($row = $result->fetch()) {
				array_push($this->_invitations, $row['channel']);
			}
			
			$result->free();
		}
		return $this->_invitations;
	}

	function removeExpiredInvitations() {
		$sql = 'DELETE FROM
					'.$this->getDataBaseTable('invitations').'
				WHERE
					DATE_SUB(NOW(), interval 1 DAY) > dateTime;';
		
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
	}

	function addInvitation($userID, $channelID=null) {
		$this->removeExpiredInvitations();

		$channelID = ($channelID === null) ? $this->getChannel() : $channelID;

		$sql = 'INSERT INTO '.$this->getDataBaseTable('invitations').'(
					userID,
					channel,
					dateTime
				)
				VALUES (
					'.$this->db->makeSafe($userID).',
					'.$this->db->makeSafe($channelID).',
					NOW()
				);';	
		
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
	}

	function removeInvitation($userID, $channelID=null) {
		$channelID = ($channelID === null) ? $this->getChannel() : $channelID;

		$sql = 'DELETE FROM
					'.$this->getDataBaseTable('invitations').'
				WHERE
					userID='.$this->db->makeSafe($userID).'
					AND
					channel='.$this->db->makeSafe($channelID).';';
		
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
	}
	
	function getUserID() {
		return $this->getSessionVar('UserID');
	}
	
	function setUserID($id) {
		$this->setSessionVar('UserID', $id);
	}

	function getUserName() {
		return $this->getSessionVar('UserName');
	}
	
	function setUserName($name) {
		$this->setSessionVar('UserName', $name);
	}

	function getLoginUserName() {
		return $this->getSessionVar('LoginUserName');
	}
	
	function setLoginUserName($name) {
		$this->setSessionVar('LoginUserName', $name);
	}

	function getUserRole() {		
		$userRole = $this->getSessionVar('UserRole');
		if($userRole === null)
			return AJAX_CHAT_GUEST;
		return $userRole;
	}
	
	function setUserRole($role) {
		$this->setSessionVar('UserRole', $role);
	}

	function getChannel() {
		return $this->getSessionVar('Channel');
	}
	
	function setChannel($channel) {
		$this->setSessionVar('Channel', $channel);
		
		// Save the channel enter timestamp:
		$this->setChannelEnterTimeStamp(time());
		
		// Update the channel authentication for the socket server:
		if($this->getConfig('socketServerEnabled')) {
			$this->updateSocketAuthentication(
				$this->getUserID(),
				$this->getSocketRegistrationID(),
				array($channel,$this->getPrivateMessageID())
			);
		}

		// Reset the logs view socket authentication session var:		
		if($this->getSessionVar('logsViewSocketAuthenticated')) {
			$this->setSessionVar('logsViewSocketAuthenticated', false);
		}
	}

	function isLoggedIn() {
		return (bool)$this->getSessionVar('LoggedIn');
	}
	
	function setLoggedIn($bool) {
		$this->setSessionVar('LoggedIn', $bool);
	}
	
	function getLoginTimeStamp() {
		return $this->getSessionVar('LoginTimeStamp');
	}

	function setLoginTimeStamp($time) {
		$this->setSessionVar('LoginTimeStamp', $time);
	}

	function getChannelEnterTimeStamp() {
		return $this->getSessionVar('ChannelEnterTimeStamp');
	}

	function setChannelEnterTimeStamp($time) {
		$this->setSessionVar('ChannelEnterTimeStamp', $time);
	}

	function getStatusUpdateTimeStamp() {
		return $this->getSessionVar('StatusUpdateTimeStamp');
	}

	function setStatusUpdateTimeStamp($time) {
		$this->setSessionVar('StatusUpdateTimeStamp', $time);
	}

	function getInactiveCheckTimeStamp() {
		return $this->getSessionVar('InactiveCheckTimeStamp');
	}

	function setInactiveCheckTimeStamp($time) {
		$this->setSessionVar('InactiveCheckTimeStamp', $time);
	}
	
	function getInsertedMessagesRate() {
		return $this->getSessionVar('InsertedMessagesRate');
	}
	
	function setInsertedMessagesRate($rate) {
		$this->setSessionVar('InsertedMessagesRate', $rate);
	}

	function getInsertedMessagesRateTimeStamp() {
		return $this->getSessionVar('InsertedMessagesRateTimeStamp');
	}

	function setInsertedMessagesRateTimeStamp($time) {
		$this->setSessionVar('InsertedMessagesRateTimeStamp', $time);
	}

	function getLangCode() {
		// Get the langCode from request or cookie:
		$langCodeCookie = isset($_COOKIE[$this->getConfig('sessionName').'_lang']) ? $_COOKIE[$this->getConfig('sessionName').'_lang'] : null;
		$langCode = $this->getRequestVar('lang') ? $this->getRequestVar('lang') : $langCodeCookie;
		// Check if the langCode is valid:
		if(!in_array($langCode, $this->getConfig('langAvailable'))) {
			// Determine the user language:
			$language = new AJAXChatLanguage($this->getConfig('langAvailable'), $this->getConfig('langDefault'));
			$langCode = $language->getLangCode();
		}
		return $langCode;
	}

	function setLangCodeCookie() {
		setcookie(
			$this->getConfig('sessionName').'_lang',
			$this->getLangCode(),
			time()+60*60*24*$this->getConfig('sessionCookieLifeTime'),
			$this->getConfig('sessionCookiePath'),
			$this->getConfig('sessionCookieDomain'),
			$this->getConfig('sessionCookieSecure')
		);
	}

	function removeUnsafeCharacters($str) {
		// Remove NO-WS-CTL, non-whitespace control characters (RFC 2822), decimal 1–8, 11–12, 14–31, and 127:
		return AJAXChatEncoding::removeUnsafeCharacters($str);
	}

	function subString($str, $start=0, $length=null, $encoding='UTF-8') {
		return AJAXChatString::subString($str, $start, $length, $encoding);
	}
	
	function stringLength($str, $encoding='UTF-8') {
		return AJAXChatString::stringLength($str, $encoding);
	}

	function trimMessageText($text) {
		return $this->trimString($text, 'UTF-8', $this->getConfig('messageTextMaxLength'));
	}

	function trimUserName($userName) {
		return $this->trimString($userName, null, $this->getConfig('userNameMaxLength'), true, true);
	}
	
	function trimChannelName($channelName) {		
		return $this->trimString($channelName, null, null, true, true);
	}

	function trimString($str, $sourceEncoding=null, $maxLength=null, $replaceWhitespace=false, $decodeEntities=false, $htmlEntitiesMap=null) {
		// Make sure the string contains valid unicode:
		$str = $this->convertToUnicode($str, $sourceEncoding);
		
		// Make sure the string contains no unsafe characters:
		$str = $this->removeUnsafeCharacters($str);
		
		// Strip whitespace from the beginning and end of the string:
		$str = trim($str);

		if($replaceWhitespace) {
			// Replace any whitespace in the userName with the underscore "_":
			$str = preg_replace('/\s/u', '_', $str);	
		}

		if($decodeEntities) {
			// Decode entities:
			$str = $this->decodeEntities($str, 'UTF-8', $htmlEntitiesMap);	
		}
		
		if($maxLength) {
			// Cut the string to the allowed length:
			$str = $this->subString($str, 0, $maxLength);
		}
		
		return $str;
	}
	
	function convertToUnicode($str, $sourceEncoding=null) {
		if($sourceEncoding === null) {
			$sourceEncoding = $this->getConfig('sourceEncoding');
		}
		return $this->convertEncoding($str, $sourceEncoding, 'UTF-8');
	}
	
	function convertFromUnicode($str, $contentEncoding=null) {
		if($contentEncoding === null) {
			$contentEncoding = $this->getConfig('contentEncoding');
		}
		return $this->convertEncoding($str, 'UTF-8', $contentEncoding);
	}

	function convertEncoding($str, $charsetFrom, $charsetTo) {
		return AJAXChatEncoding::convertEncoding($str, $charsetFrom, $charsetTo);
	}

	function encodeEntities($str, $encoding='UTF-8', $convmap=null) {
		return AJAXChatEncoding::encodeEntities($str, $encoding, $convmap);
	}

	function decodeEntities($str, $encoding='UTF-8', $htmlEntitiesMap=null) {
		return AJAXChatEncoding::decodeEntities($str, $encoding, $htmlEntitiesMap);
	}
	
	function htmlEncode($str) {
		return AJAXChatEncoding::htmlEncode($str, $this->getConfig('contentEncoding'));
	}
	
	function encodeSpecialChars($str) {
		return AJAXChatEncoding::encodeSpecialChars($str);
	}

	function decodeSpecialChars($str) {
		return AJAXChatEncoding::decodeSpecialChars($str);
	}

	function ipToStorageFormat($ip) {
		if(function_exists('inet_pton')) {
			// ipv4 & ipv6:
			return @inet_pton($ip);
		}
		// Only ipv4:
		return @pack('N',@ip2long($ip));
	}
	
	function ipFromStorageFormat($ip) {
		if(function_exists('inet_ntop')) {
			// ipv4 & ipv6:
			return @inet_ntop($ip);
		}
		// Only ipv4:
		$unpacked = @unpack('Nlong',$ip);
		if(isset($unpacked['long'])) {
			return @long2ip($unpacked['long']);
		}
		return null;
	}
	
	function getConfig($key, $subkey=null) {
		if($subkey)
			return $this->_config[$key][$subkey];
		else
			return $this->_config[$key];
	}

	function setConfig($key, $subkey, $value) {
		if($subkey) {
			if(!isset($this->_config[$key])) {
				$this->_config[$key] = array();
			}
			$this->_config[$key][$subkey] = $value;
		} else {
			$this->_config[$key] = $value;
		}
	}
	
	function getLang($key=null) {
		if(!$this->_lang) {
			// Include the language file:
			$lang = null;
			require(AJAX_CHAT_PATH.'lib/lang/'.$this->getLangCode().'.php');
			$this->_lang = &$lang;
		}
		if($key === null)
			return $this->_lang;
		if(isset($this->_lang[$key]))
			return $this->_lang[$key];
		return null;
	}

	function getChatURL() {
		if(defined('AJAX_CHAT_URL')) {
			return AJAX_CHAT_URL;
		}
		
		return
			(isset($_SERVER['HTTPS']) ? 'https://' : 'http://').
			(isset($_SERVER['REMOTE_USER']) ? $_SERVER['REMOTE_USER'].'@' : '').
			(isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : ($_SERVER['SERVER_NAME'].
			(isset($_SERVER['HTTPS']) && $_SERVER['SERVER_PORT'] == 443 || $_SERVER['SERVER_PORT'] == 80 ? '' : ':'.$_SERVER['SERVER_PORT']))).
			substr($_SERVER['SCRIPT_NAME'],0, strrpos($_SERVER['SCRIPT_NAME'], '/')+1);
	}

	function getIDFromName($userName) {
		$userDataArray = $this->getOnlineUsersData(null,'userName',$userName);
		if($userDataArray && isset($userDataArray[0])) {
			return $userDataArray[0]['userID'];
		}
		return null;
	}

	function getNameFromID($userID) {
		$userDataArray = $this->getOnlineUsersData(null,'userID',$userID);
		if($userDataArray && isset($userDataArray[0])) {
			return $userDataArray[0]['userName'];
		}
		return null;
	}

	function getChannelFromID($userID) {
		$userDataArray = $this->getOnlineUsersData(null,'userID',$userID);
		if($userDataArray && isset($userDataArray[0])) {
			return $userDataArray[0]['channel'];
		}
		return null;
	}

	function getIPFromID($userID) {
		$userDataArray = $this->getOnlineUsersData(null,'userID',$userID);
		if($userDataArray && isset($userDataArray[0])) {
			return $userDataArray[0]['ip'];
		}
		return null;
	}
	
	function getRoleFromID($userID) {
		$userDataArray = $this->getOnlineUsersData(null,'userID',$userID);
		if($userDataArray && isset($userDataArray[0])) {
			return $userDataArray[0]['userRole'];
		}
		return null;
	}
	
	function getChannelNames() {
		return array_flip($this->getChannels());
	}
	
	function getChannelIDFromChannelName($channelName) {
		if(!$channelName)
			return null;
		$channels = $this->getAllChannels();
		if(array_key_exists($channelName,$channels)) {
			return $channels[$channelName];
		}
		$channelID = null;
		// Check if the requested channel is the own private channel:
		if($channelName == $this->getPrivateChannelName()) {
			return $this->getPrivateChannelID();
		}
		// Try to retrieve a private room ID:
		$strlenChannelName = $this->stringLength($channelName);
		$strlenPrefix = $this->stringLength($this->getConfig('privateChannelPrefix'));
		$strlenSuffix = $this->stringLength($this->getConfig('privateChannelSuffix'));
		if($this->subString($channelName,0,$strlenPrefix) == $this->getConfig('privateChannelPrefix')
			&& $this->subString($channelName,$strlenChannelName-$strlenSuffix) == $this->getConfig('privateChannelSuffix')) {
			$userName = $this->subString(
							$channelName,
							$strlenPrefix,
							$strlenChannelName-($strlenPrefix+$strlenSuffix)
						);
			$userID = $this->getIDFromName($userName);
			if($userID !== null) {
				$channelID = $this->getPrivateChannelID($userID);
			}
		}
		return $channelID;
	}
	
	function getChannelNameFromChannelID($channelID) {
		foreach($this->getAllChannels() as $key=>$value) {
			if($value == $channelID) {
				return $key;
			}
		}
		// Try to retrieve a private room name:
		if($channelID == $this->getPrivateChannelID()) {
			return $this->getPrivateChannelName();
		}
		$userName = $this->getNameFromID($channelID-$this->getConfig('privateChannelDiff'));
		if($userName === null) {
			return null;
		}
		return $this->getPrivateChannelName($userName);
	}
	
	function getChannelName() {
		return $this->getChannelNameFromChannelID($this->getChannel());
	}

	function getPrivateChannelName($userName=null) {
		if($userName === null) {
			$userName = $this->getUserName();
		}
		return $this->getConfig('privateChannelPrefix').$userName.$this->getConfig('privateChannelSuffix');
	}

	function getPrivateChannelID($userID=null) {
		if($userID === null) {
			$userID = $this->getUserID();
		}
		return $userID + $this->getConfig('privateChannelDiff');
	}
	
	function getPrivateMessageID($userID=null) {
		if($userID === null) {
			$userID = $this->getUserID();
		}
		return $userID + $this->getConfig('privateMessageDiff');
	}

	function isAllowedToSendPrivateMessage() {
		if($this->getConfig('allowPrivateMessages') || $this->getUserRole() == AJAX_CHAT_ADMIN) {
			return true;
		}
		return false;
	}
	
	function isAllowedToCreatePrivateChannel() {
		if($this->getConfig('allowPrivateChannels')) {
			switch($this->getUserRole()) {
				case AJAX_CHAT_USER:
					return true;
				case AJAX_CHAT_MODERATOR:
					return true;
				case AJAX_CHAT_ADMIN:
					return true;
				default:
					return false;
			}
		}
		return false;
	}
	
	function isAllowedToListHiddenUsers() {
		// Hidden users are users within private or restricted channels:
		switch($this->getUserRole()) {
			case AJAX_CHAT_MODERATOR:
				return true;
			case AJAX_CHAT_ADMIN:
				return true;
			default:
				return false;
		}
	}

	function isUserOnline($userID=null) {
		$userID = ($userID === null) ? $this->getUserID() : $userID;
		$userDataArray = $this->getOnlineUsersData(null,'userID',$userID);
		if($userDataArray && count($userDataArray) > 0) {
			return true;
		}
		return false;
	}

	function isUserNameInUse($userName=null) {
		$userName = ($userName === null) ? $this->getUserName() : $userName;
		$userDataArray = $this->getOnlineUsersData(null,'userName',$userName);
		if($userDataArray && count($userDataArray) > 0) {
			return true;
		}
		return false;
	}
	
	function isUserBanned($userName, $userID=null, $ip=null) {
		if($userID !== null) {
			$bannedUserDataArray = $this->getBannedUsersData('userID',$userID);
			if($bannedUserDataArray && isset($bannedUserDataArray[0])) {
				return true;
			}
		}
		if($ip !== null) {
			$bannedUserDataArray = $this->getBannedUsersData('ip',$ip);
			if($bannedUserDataArray && isset($bannedUserDataArray[0])) {
				return true;
			}
		}
		$bannedUserDataArray = $this->getBannedUsersData('userName',$userName);
		if($bannedUserDataArray && isset($bannedUserDataArray[0])) {
			return true;
		}	
		return false;
	}
	
	function isMaxUsersLoggedIn() {
		if(count($this->getOnlineUsersData()) >= $this->getConfig('maxUsersLoggedIn')) {
			return true;
		}
		return false;
	}
			
	function validateChannel($channelID) {
		if($channelID === null) {
			return false;
		}
		// Return true for normal channels the user has acces to:
		if(in_array($channelID, $this->getChannels())) {
			return true;
		}
		// Return true if the user is allowed to join his own private channel:
		if($channelID == $this->getPrivateChannelID() && $this->isAllowedToCreatePrivateChannel()) {
			return true;
		}
		// Return true if the user has been invited to a restricted or private channel:
		if(in_array($channelID, $this->getInvitations())) {
			return true;	
		}
		// No valid channel, return false:
		return false;
	}
	
	function createGuestUserName() {
		$maxLength =	$this->getConfig('userNameMaxLength')
						- $this->stringLength($this->getConfig('guestUserPrefix'))
						- $this->stringLength($this->getConfig('guestUserSuffix'));

		// seed with microseconds since last "whole" second:
		mt_srand((double)microtime()*1000000);

		// Create a random userName using numbers between 100000 and 999999:
		$userName = substr(mt_rand(100000, 999999), 0, $maxLength);

		return $this->getConfig('guestUserPrefix').$userName.$this->getConfig('guestUserSuffix');
	}
	
	// Guest userIDs must not interfere with existing userIDs and must be lower than privateChannelDiff:
	function createGuestUserID() {
		// seed with microseconds since last "whole" second:
		mt_srand((double)microtime()*1000000);
		
		return mt_rand($this->getConfig('minGuestUserID'), $this->getConfig('privateChannelDiff')-1);
	}

	function getGuestUser() {
		if(!$this->getConfig('allowGuestLogins'))
			return null;

		if($this->getConfig('allowGuestUserName')) {
			$maxLength =	$this->getConfig('userNameMaxLength')
							- $this->stringLength($this->getConfig('guestUserPrefix'))
							- $this->stringLength($this->getConfig('guestUserSuffix'));

			// Trim guest userName:
			$userName = $this->trimString($this->getRequestVar('userName'), null, $maxLength, true, true);

			// If given userName is invalid, create one:
			if(!$userName) {
				$userName = $this->createGuestUserName();
			} else {
				// Add the guest users prefix and suffix to the given userName:
				$userName = $this->getConfig('guestUserPrefix').$userName.$this->getConfig('guestUserSuffix');	
			}
		} else {
			$userName = $this->createGuestUserName();
		}

		$userData = array();
		$userData['userID'] = $this->createGuestUserID();
		$userData['userName'] = $userName;
		$userData['userRole'] = AJAX_CHAT_GUEST;
		return $userData;		
	}

	function getCustomVar($key) {
		if(!isset($this->_customVars))
			$this->_customVars = array();
		if(!isset($this->_customVars[$key]))
			return null;
		return $this->_customVars[$key];
	}
	
	function setCustomVar($key, $value) {
		if(!isset($this->_customVars))
			$this->_customVars = array();
		$this->_customVars[$key] = $value;
	}

	// Override to replace custom template tags:
	// Return the replacement for the given tag (and given tagContent)	
	function replaceCustomTemplateTags($tag, $tagContent) {
		return null;
	}

	// Override to initialize custom configuration settings:
	function initCustomConfig() {
	}

	// Override to add custom request variables:
	// Add values to the request variables array: $this->_requestVars['customVariable'] = null;
	function initCustomRequestVars() {
	}

	// Override to add custom session code right after the session has been started:
	function initCustomSession() {
	}

	// Override, to parse custom info requests:
	// $infoRequest contains the current info request
	// Add info responses using the method addInfoMessage($info, $type)
	function parseCustomInfoRequest($infoRequest) {
	}

	// Override to replace custom text:
	// Return replaced text
	// $text contains the whole message
	function replaceCustomText(&$text) {
		return $text;
	}

	// Override to add custom commands:
	// Return true if a custom command has been successfully parsed, else false
	// $text contains the whole message, $textParts the message split up as words array
	function parseCustomCommands($text, $textParts) {
		return false;
	}

	// Override to perform custom actions on new messages:
	// Return true if message may be inserted, else false
	// $text contains the whole message
	function onNewMessage($text) {
		return true;
	}

	// Override to perform custom actions on new messages:
	// Method to set the style cookie depending on user data
	function setStyle() {
	}

	// Override:
	// Returns true if the userID of the logged in user is identical to the userID of the authentication system
	// or the user is authenticated as guest in the chat and the authentication system
	function revalidateUserID() {
		return true;
	}
	
	// Override:
	// Returns an associative array containing userName, userID and userRole
	// Returns null if login is invalid
	function getValidLoginUserData() {
		// Check if we have a valid registered user:
		if(false) {
			// Here is the place to check user authentication
		} else {
			// Guest users:
			return $this->getGuestUser();
		}
	}

	// Override:
	// Store the channels the current user has access to
	// Make sure channel names don't contain any whitespace
	function &getChannels() {
		if($this->_channels === null) {
			$this->_channels = $this->getAllChannels();
		}
		return $this->_channels;
	}

	// Override:
	// Store all existing channels
	// Make sure channel names don't contain any whitespace
	function &getAllChannels() {
		if($this->_allChannels === null) {
			$this->_allChannels = array();
			
			// Default channel, public to everyone:
			$this->_allChannels[$this->trimChannelName($this->getConfig('defaultChannelName'))] = $this->getConfig('defaultChannelID');
		}
		return $this->_allChannels;
	}
	function getJoomUsername() {

		$sessionID = @$_GET["sessionid"];
		$sql = "SELECT * FROM `jos_session` where session_id='".$sessionID."';";

		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		
		$row = $result->fetch();

		$result->free();		
		if ($row['guest'] == 1){
			$uname=' ';
		}
		else 
			$uname=$row['username'];
		return $uname;
		}
		
	function logoutinfo(){
		$logoutinfr = @$_GET["logout"];
		if ($logoutinfr)
			$logoutinf = "window.top.location.href = \"http://".$_SERVER["SERVER_NAME"]."\";";
		else
		$logoutinf = "document.getElementById('loginForm').submit();";
		return $logoutinf;
	}
	
	function pay($intv) {
		$name = @$_SESSION["ajaxChatLoginUserName"];
		$sql = "SELECT `user_balance` FROM `joomla_user_balance` where uname='".$name."';";

		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		
		$row = $result->fetch();

		$result->free();
		 
		if ($row['user_balance']>=$intv)
		{
			$sql = "UPDATE `joomla_user_balance` SET user_balance=user_balance-".$intv." where  uname='".$name."';";
			$sql2 = "UPDATE `joomla_user_balance` SET user_balance=user_balance+".$intv." where  uname='admin';";
			// /*Create a new SQL query:*/
			$result = $this->db->sqlQuery($sql2);
			$result = $this->db->sqlQuery($sql);
			// /*Stop if an error occurs:*/
			if($result->error()) {
				echo $result->getError();
				die();
			}
			echo $row['user_balance']-$intv;
		} else
		{
			echo '-1';
		}	

			
		 // $sql = "UPDATE `joomla_user_balance` SET user_balance=user_balance-".$intv." where  uname='".$name."';";
		 // $sql2 = "UPDATE `joomla_user_balance` SET user_balance=user_balance+".$intv." where  uname='admin';";

/* 		Create a new SQL query: */
		// $result = $this->db->sqlQuery($sql2);

		// $result = $this->db->sqlQuery($sql);
		/*Stop if an error occurs:*/
		// if($result->error()) {
			// echo $result->getError();
			// die();
		// }
	}
	function tip($intv) {
		$name = @$_SESSION["ajaxChatLoginUserName"];
		$sql = "SELECT `user_balance` FROM `joomla_user_balance` where uname='".$name."';";

		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		
		$row = $result->fetch();

		$result->free();
		 
		if ($row['user_balance']>=$intv)
		{
			$sql = "UPDATE `joomla_user_balance` SET user_balance=user_balance-".$intv." where  uname='".$name."';";
			$sql2 = "UPDATE `joomla_user_balance` SET user_balance=user_balance+".$intv." where  uname='admin';";
			// /*Create a new SQL query:*/
			$result = $this->db->sqlQuery($sql2);
			$result = $this->db->sqlQuery($sql);
			// /*Stop if an error occurs:*/
			if($result->error()) {
				echo $result->getError();
				die();
			}
			$this->insertChatBotMessage(
				$this->getChannel(),
				$name." tipped ".$intv." dollars and say: ".$this->getRequestVar('tipcomment'),
				null,
				1
			);
			echo $row['user_balance']-$intv;
		} else
		{
			echo '-1';
		}
	}
	function getCurrentCoins(){
		$name = @$_SESSION["ajaxChatLoginUserName"];
		$sql = "SELECT * FROM `joomla_user_balance` where  uname='".$name."';";
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		$row = $result->fetch();
		$result->free();
		return $row['user_balance'];
	}
	function getModelPanel(){
		$name = @$_SESSION["ajaxChatLoginUserName"];
		if ($name == 'admin')
		{


			return '<ul id="tabs" class="css_tabs">
						<li><a href="#tab2">Home</a></li>
						<li><a href="#tab1">ChatRoom</a></li>
						</ul>
					<ul id="tabcontent" class="css_tabcontent">
					<li id="tab1">';
		} else
		{
			return '';
		}
	}
	function getModelPanelEnd(){
		$name = @$_SESSION["ajaxChatLoginUserName"];
		if ($name == 'admin')
		{


			return '</li>
					<li id="tab2">
					<div class="tab_home"> 
					What`s new:
					
					</div>
					</li>
					</ul>';
		} else
		{
			return '';
		}
	}
	function getUVPanel(){
		$name = @$_SESSION["ajaxChatLoginUserName"];
		if ($name == 'admin')
		{


			return '
			<br/>
			<div class="stripe_broadcasting">
			<input type="button" name="bth_not_broadcasting" class="bth_not_broadcasting" onclick="alert(this.class)"/>
			<input type="button" name="bth_cam_preview" class="bth_cam_preview" onclick="alert(this.class)"/>
			</div>
			<hr/>
			
			
			
			<br/><td class="tbl_left">
<span id="a_friends_spoiler" class="onner1" onclick="showSpoiler(this);"><img src="../chat/img/icon_friends.png" width="16%"/>FRIENDS</span>
				<div class="inner" id="m_friend_list" style="display:none;">
						<tr><td>
						
						<span id="a_friends_onl_spoiler" class="onner2" onclick="showSpoiler(this);"><img src="../chat/img/icon_folder.png" width="16%"/>online friends</span>
						<div class="inner" id="m_friend_list" style="display:none;">
							<tr><td>User 1</td><td>(3)</td></tr>
							<tr><td>User 2</td><td>(5)</td></tr>
							<tr><td>User 3</td><td>(7)</td></tr>
						</div>
						
						
						</td><td>(3)</td></tr>

						<tr><td>
						
						
						<span id="a_friends_offl_spoiler" class="onner2" onclick="showSpoiler(this);"><img src="../chat/img/icon_folder.png" width="16%"/>offline friends</span>
						<div class="inner" id="m_friend_list" style="display:none;">
							<tr><td>User 1</td><td>(3)</td></tr>
							<tr><td>User 2</td><td>(5)</td></tr>
							<tr><td>User 3</td><td>(7)</td></tr>
						</div>	
						
						</td><td>(5)</td></tr>
				</div>
</td>
<td class="tbl_right">
	<span id="a_menu_spoiler" class="onner1" onclick="showSpoiler(this);"><img src="../chat/img/icon_tokens.png" width="16%"/>TOKENS
		<input class="bth_admine_refresh" type="button" value="" onclick="alert(this.class)"/>
		<input class="bth_admine_find" type="button" value="" onclick="alert(this.class)"/>
		<input class="bth_admine_list" type="button" value="" onclick="alert(this.class)"/>
	</span>
				<div class="inner" id="m_menu_list" style="display:none;">
						<tr><td>
						<img src="../chat/img/icon_admine_private.png" width="8%"/>Private ............ 0<br/>
						<img src="../chat/img/icon_admine_group.png" width="8%"/>Group .............. 0<br/>
						<img src="../chat/img/icon_admine_spy.png" width="8%"/>Spy ................ 0<br/>
						<img src="../chat/img/icon_admine_tips.png" width="8%"/>Tips ............... 0<br/>
						<hr/>
						<img src="../chat/img/icon_admine_total.png" width="8%"/>Total .............. 0<br/>
						</td></tr>
				</div>
</td>';
		} else
		{
			return '<!--tr>
						<img id="currenttime" src=""></img-->
						<!--old trash textarea id="currenttime" rows="1" cols="5">12</textarea-->
						<!--textarea id="tipssend" rows="1" cols="5">12</textarea>
						<textarea id="tipscomment" rows="1" cols="5">comment</textarea>
						<input type="button" id="" value="tip" onclick="ajaxChat.sendtip(document.getElementById(\'tipssend\').value,document.getElementById(\'tipscomment\').value);"/>
				</tr-->
				<tr>
					<input type="button" id="" value="" onclick="" class="bth_volume"/>
					
					<input type="button" id="" value="" onclick="ajaxChat.videofunction(\'refresh\')" class="bth_refresh"/>
					
					<!-- <input type="button" id="bth_fullscreen" onclick="bth_change(this, \'bth_fullscreen\', \'bth_fullscreen_a\');fscreenon()" class="bth_fullscreen"/> -->
					<input type="button" id="bth_video" value="" onclick="bth_change(this, \'bth_video\', \'bth_video_a\');ajaxChat.videofunction(\'onoff\')" class="bth_video"/>
					<input type="button" id="video_hide" value="" onclick="bth_change(this, \'bth_video_hide\', \'bth_video_display\');ajaxChat.videofunction(\'hide\')" class="bth_video_hide"/>
					<input type="button" id="video_resize" onclick="bth_change(this, \'bth_video_resize\', \'bth_video_resize_full\');resize()" class="bth_video_resize" />
				</tr>
				<tr>
					<input type="button" id="" value="" onclick="ajaxChat.videofunction(\'goprivate\');" class="bth_private"/>
					<input type="button" id="startgroupbutton" value="" onclick="ajaxChat.videofunction(\'groupStart\');" class="bth_startgroupe"/>
					<input style="display:none;" type="button" id="joingroupbutton" value="" onclick="ajaxChat.joingroup()" class="bth_joingroupe"/>
					<!--input type="button" id="" value="quit" onclick="ajaxChat.videofunction(\'quitP\');" /-->
					
				</tr>
				<tr>
					<input type="button" id="" value="vojar" onclick="ajaxChat.videofunction(\'chVojar\');"/>
					<div id="main_tokens"></div>
					<script>CreateTokens([SHOW_CURRENT_COINS/]);</script>
					<!--input type="button" id="" value="stopvojar" onclick="ajaxChat.stopvojar();"/-->
					<!--button id="view1fullscreen">Fullscreen</button-->
				</tr>';
		}
	}
	function privateMsgCount($uname){
	
		$sql = "SELECT SUM(`unread`) unread_sum FROM `ajax_chat_messages` WHERE `unread` = 1 and `userName` <> '".$uname."' 
								and `channel` = 1000000000+(select `userID` 
								from `ajax_chat_messages` 
								where `userName` =('".$uname."' ) 
								GROUP BY `userID`);";
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		
		$row = $result->fetch();
		$result->free();

		// if ($row['unread_sum'] > 0){
			echo (int)$row['unread_sum'];
		// } else {
			// echo 0;
		// };
	
	}
	function in_private_msg($uname){
		$sql = "SELECT `userName` , SUM( `unread` ) sum FROM `ajax_chat_messages` WHERE `unread` =1 and `userName` <> '".$uname."' and `channel` = 1000000000+(select `userID` 
								from `ajax_chat_messages` 
								where `userName` =('".$uname."' ) 
								GROUP BY `userID`)GROUP BY `userName`;";
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		$output_print = '';
		while($row = $result->fetch()) {
				$output_print .= "<tr><td onclick=\"ajaxChat.z_alert(this.innerHTML);\">".$row['userName']."</td><td>(".$row['sum'].")</td></tr>";
			}
			print($output_print);
		$result->free();
	}
	function get_private_msg($name,$name2){
		//$sql = "SELECT `dateTime`, `userName`, `text` FROM `ajax_chat_messages` WHERE  `userRole` <4 AND `channel` >1 AND `channel` - `userID` <> 1000000000 AND `unread` = 1 and `userName` = '".$name."'";
		$sql = "SELECT *
				FROM `ajax_chat_messages`
				WHERE	`unread` =1
				AND `channel` - `userID` <>1000000000
				AND `userName` IN ('".$name."' , '".$name2."')
				AND `channel` IN (
					1000000000+(select `userID` 
								from `ajax_chat_messages` 
								where `userName` =('".$name."' ) 
								GROUP BY `userID`),
					1000000000+(select `userID` 
								from `ajax_chat_messages` 
								where `userName` =('".$name2."' ) 
								GROUP BY `userID`)
								);";
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		$output_print = '<div id="'.$name.'" class="winID"
							style="z-index: 9999;
							background: #E1EBF2;
							position:absolute;
							width:200px;
							height:200px;
							left:500px;
							top:120px;
							border-top: 20px solid black;
							border-top-left-radius: 10px;
							border-top-right-radius: 10px;
							border-left: 1px solid black;
							border-right: 1px solid black;
							border-bottom: 1px solid black;"
							onmousedown="MousePress(event,this);"><div style="background: url(\'close.png\') no-repeat  52% 53% ;
									border-radius: 9px;
									width: 13%;
									margin-left: 87%;
									margin-top: -10%;
									height: 10%; " 
									onclick="del(this);"></div><div style="
									border-radius: 9px;
									width: 13%;
									color:red;
									margin-top: -10%;
									height: 10%; " 
									onclick="document.getElementById(\''.$name.'\').style.display = \'none\';">'.$name.'</div><div id="'.$name.'_pv_messages" style="overflow: auto; height: 80%;">';
		while($row = $result->fetch()) {
				$output_print .= "<tr id=\"".$row['id']."\" class=\"pvMsg_info\"><td class=\"pv_dateTime\" style=\"font-size: 0.7em;\">".$row['dateTime']."</td><td id = \"pv_nick1".$row['id']."\" class=\"pv_nick_cl\" style=\"font-style: italic; font-weight: bold; font-size: 1.3em; color: rgb(211, 17, 65);\">".$row['userName']."</td></tr><tr class=\"pvMsg\"><td class=\"pv_msg\" style=\"color: rgb(40, 49, 63); font-style: italic; font-size: 0.8em; padding-left: 36px;\">".substr($row['text'], 9)."</td></tr>";
			}
		$output_print .= '</div><div><textarea  id="pv_inputField"
										rows="1" 
										title="Press SHIFT+ENTER" 
										onkeypress="ajaxChat.pv_msg_KeyPress(event);" 
										onkeyup="ajaxChat.pv_msg_KeyUp(event);"
										onclick="clean_unread_msg(this);"
										style="height: 32px;"></textarea></div></div>';
			print($output_print);
		$result->free();
	
	}
	function initInImages($iii){
// $array = ('<a href="javascript:ajaxChat.insertText(\'%3Ao)\');"><img src="./img/emoticons/monkey.png" alt=":o)" title=":o)"/></a>'.
				// '<a href="javascript:ajaxChat.insertText(\'%3Ao)\');"><img src="./img/emoticons/monkey.png" alt=":o)" title=":o)"/></a>'.
				// '<a href="javascript:ajaxChat.insertText(\'%3Ao)\');"><img src="./img/emoticons/monkey.png" alt=":o)" title=":o)"/></a>'.
				// '<a href="javascript:ajaxChat.insertText(\'%3Ao)\');"><img src="./img/emoticons/monkey.png" alt=":o)" title=":o)"/></a>'.
				// '<a href="javascript:ajaxChat.insertText(\'%3Ao)\');"><img src="./img/emoticons/monkey.png" alt=":o)" title=":o)"/></a>');
				// print($array);

		$sql = "SELECT `image` FROM `chat_images` WHERE `status` = 1";
		//Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		//Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		 $output_print = '';
		while($row = $result->fetch()) {
				$output_print .= '<a href="javascript:ajaxChat.insertText(\'[img]http://'.$_SERVER['SERVER_NAME'].''.$row['image'].'[/img]\');"><img width = "100px" src="http://'.$_SERVER['SERVER_NAME'].''.$row['image'].'" alt=":o)" title=":o)"/></a>';
			}
		// $output_print .= '</div><div><textarea  id="pv_inputField"
										// rows="1" 
										// title="Press SHIFT+ENTER" 
										// onkeypress="ajaxChat.pv_msg_KeyPress(event);" 
										// onkeyup="ajaxChat.pv_msg_KeyUp(event);"
										// onclick="clean_unread_msg(this);"
										// style="height: 32px;"></textarea></div></div>';
			print($output_print);
		$result->free();
	
	}
	function upd_pv_msg($name,$name2,$lastmsg){
	$output_print = '';
		$sql = "SELECT *
				FROM `ajax_chat_messages`
				WHERE	`unread` =1
				AND `channel` - `userID` <>1000000000
				AND `userName` IN ('".$name."' , '".$name2."')
				AND `channel` IN (
					1000000000+(select `userID` 
								from `ajax_chat_messages` 
								where `userName` =('".$name."' ) 
								GROUP BY `userID`),
					1000000000+(select `userID` 
								from `ajax_chat_messages` 
								where `userName` =('".$name2."' ) 
								GROUP BY `userID`)
								)
				AND `id` > ".$lastmsg.";";
		// Create a new SQL query:
		$result = $this->db->sqlQuery($sql);
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		
		while($row = $result->fetch()) {
		$output_print .= "<tr id=\"".$row['id']."\" class=\"pvMsg_info\"><td class=\"pv_dateTime\" style=\"font-size: 0.7em;\">".$row['dateTime']."</td><td id = \"pv_nick1".$row['id']."\" class=\"pv_nick_cl\" style=\"font-style: italic; font-weight: bold; font-size: 1.3em; color: rgb(211, 17, 65);\">".$row['userName']."</td></tr><tr class=\"pvMsg\"><td class=\"pv_msg\" style=\"color: rgb(40, 49, 63); font-style: italic; font-size: 0.8em; padding-left: 36px;\">".substr($row['text'], 9)."</td></tr>";
			}
						echo ($output_print);

		$result->free();
	}
	function getAvatarID($avID){
		$sql = "SELECT `avatar` FROM `jos_comprofiler` WHERE `user_id` = ".$avID.";";
		$result = $this->db->sqlQuery($sql);
		// Stop if an error occurs:
		if($result->error()) {
			echo $result->getError();
			die();
		}
		$row = $result->fetch();

		echo $row['avatar'];
		$result->free();

	}
	function clean_pv_message($arr){
	$sql .= "UPDATE `ajax_chat_messages` SET unread=0 where  id IN (".$arr[0];
	for($x = 1;$x < count($arr);$x++){
	$sql .= ",".$arr[$x];
                }
	$sql .=");";
	// $sql = '';
	// for ($i=0;$i<count($ids);$i++ ) {
			// $sql .= $ids[$i]; 
			// "UPDATE `asd` SET asd=asd where  asd='"$arr[$i]"';";
			// };
				
// $d = date('l jS \of F Y h:i:s A');
// $filename = "./AjaxChatLog.txt";
// $fh = fopen($filename, "a+");
// fwrite($fh, $d." My Ajax Chat log "." фывафыв variable  ".$sql."\r\n\n");
// fclose($fh);
			/*Create a new SQL query:*/
			$result = $this->db->sqlQuery($sql);
			// /*Stop if an error occurs:*/
			if($result->error()) {
				echo $result->getError();
				die();
			}
	}
}
?>