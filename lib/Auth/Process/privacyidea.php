<?php
/**
 * This authentication processing filter allows you to add a second step
 * authentication against privacyIDEA
 *
 * @author Cornelius Kölbel <cornelius.koelbel@netknights.it>
 */



class sspmod_privacyidea_Auth_Process_privacyidea extends SimpleSAML_Auth_ProcessingFilter
{
	/**
	 * This contains the server configuration
	 * @var array
	 */
	private $serverconfig;

    /**
     * privacyidea constructor.
     *
     * @param array $config The configuration of this authproc.
     * @param mixed $reserved
     *
     * @throws \SimpleSAML\Error\CriticalConfigurationError in case the configuration is wrong.
     */

     public function __construct(array $config, $reserved)
     {
        SimpleSAML_Logger::info("Create the Auth Proc Filter privacyidea");
        parent::__construct($config, $reserved);
        $cfg = SimpleSAML_Configuration::loadFromArray($config, 'privacyidea:privacyidea');
        $this->serverconfig['privacyideaserver'] = $cfg->getString('privacyideaserver', null);
        $this->serverconfig['sslverifyhost'] = $cfg->getBoolean('sslverifyhost', null);
        $this->serverconfig['sslverifypeer'] = $cfg->getBoolean('sslverifypeer', null);
        $this->serverconfig['realm'] = $cfg->getString('realm', null);
        $this->serverconfig['uidKey'] = $cfg->getString('uidKey', null);
        $this->serverconfig['enabledPath'] = $cfg->getString('enabledPath', null);
        $this->serverconfig['enabledKey'] = $cfg->getString('enabledKey', null);
        $this->serverconfig['serviceAccount'] = $cfg->getString('serviceAccount', null);
	    $this->serverconfig['servicePass'] = $cfg->getString('servicePass', null);
     }

    /**
     * Run the filter.
     *
     * @param array $state
     *
     * @throws \Exception if authentication fails
     */
    public function process(&$state)
    {
	    SimpleSAML_Logger::info("privacyIDEA Auth Proc Filter: Entering process function");

	    /**
	     * If a configuration is not set in privacyidea:tokenEnrollment,
	     * We are using the config from privacyidea:serverconfig.
	     */

	    foreach ($this->serverconfig as $key => $value) {
	    	if ($value === null) {
	    		$this->serverconfig[$key] = $state['privacyidea:serverconfig'][$key];
		    }
	    }

    	$state['privacyidea:privacyidea'] = array(
    		'privacyideaserver' => $this->serverconfig['privacyideaserver'],
		    'sslverifyhost' => $this->serverconfig['sslverifyhost'],
		    'sslverifypeer' => $this->serverconfig['sslverifypeer'],
		    'realm' => $this->serverconfig['realm'],
		    'uidKey' => $this->serverconfig['uidKey'],
	    );

    	if(isset($state[$this->serverconfig['enabledPath']][$this->serverconfig['enabledKey']][0])) {
    		$piEnabled = $state[$this->serverconfig['enabledPath']][$this->serverconfig['enabledKey']][0];
	    } else {
    		$piEnabled = True;
	    }

		if ($this->serverconfig['privacyideaserver'] === '') {
			$piEnabled = False;
			SimpleSAML_Logger::error("privacyIDEA url is not set!");
		}

		if($piEnabled) {
			SimpleSAML_Logger::debug("privacyIDEA: privacyIDEA is enabled, so we use 2FA");
			$id  = SimpleSAML_Auth_State::saveState( $state, 'privacyidea:privacyidea:init' );
			$url = SimpleSAML_Module::getModuleURL( 'privacyidea/otpform.php' );
			SimpleSAML_Utilities::redirectTrustedURL( $url, array( 'StateId' => $id ) );
		} else {
			SimpleSAML_Logger::debug("privacyIDEA: " . $this->serverconfig['enabledPath'] . " -> " . $this->serverconfig['enabledKey'] . " is not set to true -> privacyIDEA is disabled");
		}
    }

    /**
     * Perform 2FA authentication given the current state and an OTP from a token managed by privacyIDEA
     * The otp is sent to the privacyidea_url.
     *
     * @param array $state The state array in the "privacyidea:privacyidea:init" stage.
     * @param string $otp A one time password generated by a yubikey.
     * @return boolean True if authentication succeeded and the key belongs to the user, false otherwise.
     *
     * @throws \InvalidArgumentException if the state array is not in a valid stage or the given OTP has incorrect
     * length.
     */

    public static function authenticate(array &$state, $otp, $transaction_id, $signaturedata, $clientdata)
    {

	    $cfg = $state['privacyidea:privacyidea'];

	    $params = array(
		    "user" => $state["Attributes"][$cfg['uidKey']][0],
		    "pass" => $otp,
		    "realm"=> $cfg['realm'],
	    );
        if ($transaction_id) {
            SimpleSAML_Logger::debug("Authenticating with transaction_id: " . $transaction_id);
            $params["transaction_id"] = $transaction_id;
        }
        if ($signaturedata) {
            SimpleSAML_Logger::debug("Authenticating with signaturedata: " . urlencode($signaturedata));
            $params["signaturedata"] = $signaturedata;
        }
        if ($clientdata) {
            SimpleSAML_Logger::debug("Authenticating with clientdata: " . urlencode($clientdata));
            $params["clientdata"] = $clientdata;
        }
		$attributes = NULL;

	    $body = sspmod_privacyidea_Auth_utils::curl($params, null, $cfg, "/validate/samlcheck", "POST");

	    try {
		    $result = $body->result;
		    $status = $result->status;
		    $value  = $result->value;
		    $auth   = $value->auth;
	    } catch (Exception $e) {
		    throw new SimpleSAML_Error_BadRequest("privacyIDEA: We were not able to read the response from the PI server");
	    }

	    if ($status !== true) {
		    throw new SimpleSAML_Error_BadRequest("privacyIDEA: Valid JSON response, but some internal error occured in PI server");
	    }
	    if ( $auth !== true ) {
		    SimpleSAML_Logger::debug( "Throwing WRONGUSERPASS" );
		    $detail = $body->detail;
		    $message = $detail->message;
		    if (property_exists( $detail, "attributes")){
			    $attributes = $detail->attributes;
			    if (property_exists( $attributes, "u2fSignRequest")){
				    SimpleSAML_Logger::debug("This is an U2F authentication request");
				    SimpleSAML_Logger::debug(print_r($attributes, true));
				    /*
					 * In case of U2F the $attributes looks like this:
					[img] => static/css/FIDO-U2F-Security-Key-444x444.png#012
					[hideResponseInput] => 1#012
					[u2fSignRequest] => [challenge] => yji-PL1V0QELilDL3m6Lc-1yahpKZiU-z6ye5Zz2mp8#012
								[version] => U2F_V2#012
								[keyHandle] => fxDKTr6o8EEGWPyEyRVDvnoeA0c6v-dgvbN-6Mxc6XBmEItsw#012
								[appId] => https://172.16.200.138#012        )#012#012)
					*/
			    }
		    }
		    if (property_exists($detail, "transaction_id")){
		    	$transaction_id = $detail->transaction_id;
			    /* If we have a transaction_id, we do challenge response */
			    SimpleSAML_Logger::debug( "Throwing CHALLENGERESPONSE" );
			    throw new SimpleSAML_Error_Error(array("CHALLENGERESPONSE", $transaction_id, $message, $attributes));
		    }
		    SimpleSAML_Logger::debug( "Throwing WRONGUSERPASS" );
		    throw new SimpleSAML_Error_Error( "WRONGUSERPASS" );
		}

	    SimpleSAML_Logger::debug( "privacyIDEA: User authenticated successfully" );
	    return true;
    }

}
