<?php
/*
 * Copyright 2024 NetKnights GmbH - lukas.matusiewicz@netknights.it
 * <p>
 * Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3;
 * you may not use this file except in compliance with the License.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace SimpleSAML\Module\privacyidea\Auth;

class PIResponse
{
    /* @var string Combined messages of all triggered token. */
    private string $messages = "";

    /* @var string Message from the response. Should be shown to the user. */
    private string $message = "";

    /* @var string Transaction ID is used to reference the challenges contained in this response in later requests. */
    private string $transactionID = "";

    /* @var string Preferred mode in which client should work after triggering challenges. */
    private string $preferredClientMode = "";

    /* @var string Raw response in JSON format. */
    private string $raw = "";

    /* @var array Array of PIChallenge objects representing the triggered token challenges. */
    private array $multiChallenge = array();

    /* @var bool Status indicates if the request was processed successfully by the server. */
    private bool $status = false;

    /* @var bool Value is true if the authentication was successful. */
    private bool $value = false;

    /* @var string Authentication Status. */
    private string $authenticationStatus = "";

    /* @var array Additional attributes of the user that can be sent by the server. */
    private array $detailAndAttributes = array();

    /* @var string If an error occurred, the error code will be set here. */
    private string $errorCode = "";

    /* @var string If an error occurred, the error message will be set here. */
    private string $errorMessage = "";

    /**
     * Create a PIResponse object from the JSON response of the server.
     *
     * @param string $json Server response in JSON format.
     * @param PrivacyIDEA $privacyIDEA PrivacyIDEA object.
     * @return PIResponse|null Returns the PIResponse object or null if the response of the server is empty or malformed.
     */
    public static function fromJSON(string $json, PrivacyIDEA $privacyIDEA): ?PIResponse
    {
        assert('string' === gettype($json));

        if ($json == null || $json == "")
        {
            $privacyIDEA->errorLog("Response from the server is empty.");
            return null;
        }

        $ret = new PIResponse();
        $map = json_decode($json, true);
        if ($map == null)
        {
            $privacyIDEA->errorLog("Response from the server is malformed:\n" . $json);
            return null;
        }
        $ret->raw = $json;

        // If value is not present, an error occurred
        if (!isset($map['result']['value']))
        {
            $ret->errorCode = $map['result']['error']['code'];
	    $ret->errorMessage = $map['result']['error']['message'];
	    if ($ret->errorCode == 904){
              $ret->errorCode = 1312;
              $ret->errorMessage = 'Sorry, authentication failed... Please try again!';
            }
            return $ret;
        }

        if (isset($map['detail']['messages']))
        {
            $ret->messages = implode(", ", array_unique($map['detail']['messages'])) ?: "";
        }
        if (isset($map['detail']['message']))
        {
            $ret->message = $map['detail']['message'];
        }
        if (isset($map['detail']['transaction_id']))
        {
            $ret->transactionID = $map['detail']['transaction_id'];
        }
        if (isset($map['detail']['preferred_client_mode']))
        {
            $pref = $map['detail']['preferred_client_mode'];
            if ($pref === "poll")
            {
                $ret->preferredClientMode = "push";
            }
            elseif ($pref === "interactive")
            {
                $ret->preferredClientMode = "otp";
            }
            else
            {
                $ret->preferredClientMode = $map['detail']['preferred_client_mode'];
            }
        }

        // Check if the authentication status is legit
        $r = null;
        if (!empty($map['result']['authentication']))
        {
            $r = $map['result']['authentication'];
        }
        if ($r === AuthenticationStatus::CHALLENGE)
        {
            $ret->authenticationStatus = AuthenticationStatus::CHALLENGE;
        }
        elseif ($r === AuthenticationStatus::ACCEPT)
        {
            $ret->authenticationStatus = AuthenticationStatus::ACCEPT;
        }
        elseif ($r === AuthenticationStatus::REJECT)
        {
	    $ret->authenticationStatus = AuthenticationStatus::REJECT;
            $ret->errorCode = 1312;
            $ret->errorMessage = 'Sorry, authentication failed... Please try again!';
        }
        else
        {
            $privacyIDEA->debugLog("Unknown authentication status.");
            $ret->authenticationStatus = AuthenticationStatus::NONE;
        }
        $ret->status = $map['result']['status'] ?: false;
        $ret->value = $map['result']['value'] ?: false;

        // Attributes and detail
        if (!empty($map['detail']['user']))
        {
            $attributes = $map['detail']['user'];
            $detail = $map['detail'];

            if (isset($attributes['username']))
            {
                $attributes['realm'] = $map['detail']['user-realm'] ?: "";
                $attributes['resolver'] = $map['detail']['user-resolver'] ?: "";
            }
            $ret->detailAndAttributes = array("detail" => $detail, "attributes" => $attributes);
        }

        // Add any challenges to multiChallenge
        if (isset($map['detail']['multi_challenge']))
        {
            $mc = $map['detail']['multi_challenge'];
            foreach ($mc as $challenge)
            {
                $tmp = new PIChallenge();
                $tmp->transactionID = $challenge['transaction_id'];
                $tmp->message = $challenge['message'];
                $tmp->serial = $challenge['serial'];
                $tmp->type = $challenge['type'];
                if (isset($challenge['image']))
                {
                    $tmp->image = $challenge['image'];
                }
                if (isset($challenge['attributes']))
                {
                    $tmp->attributes = $challenge['attributes'];
                }
                if (isset($challenge['client_mode']))
                {
                    $tmp->clientMode = $challenge['client_mode'];
                }

                if ($tmp->type === "webauthn")
                {
                    $t = $challenge['attributes']['webAuthnSignRequest'];
                    $tmp->webAuthnSignRequest = json_encode($t);
                }
                if ($tmp->type === "u2f")
                {
                    $t = $challenge['attributes']['u2fSignRequest'];
                    $tmp->u2fSignRequest = json_encode($t);
                }

                $ret->multiChallenge[] = $tmp;
            }
        }
        return $ret;
    }

    /**
     * Get an array with all triggered token types.
     * @return array
     */
    public function triggeredTokenTypes(): array
    {
        $ret = array();
        foreach ($this->multiChallenge as $challenge)
        {
            $ret[] = $challenge->type;
        }
        return array_unique($ret);
    }

    /**
     * Get the message of any token that is not Push or WebAuthn. Those are OTP tokens requiring an input field.
     * @return string
     */
    public function otpMessage(): string
    {
        foreach ($this->multiChallenge as $challenge)
        {
            if ($challenge->type !== "push" && $challenge->type !== "webauthn" && $challenge->type !== "u2f")
            {
                return $challenge->message;
            }
        }
        return "";
    }

    /**
     * Get the Push token message if any were triggered.
     * @return string
     */
    public function pushMessage(): string
    {
        foreach ($this->multiChallenge as $challenge)
        {
            if ($challenge->type === "push")
            {
                return $challenge->message;
            }
        }
        return "";
    }

    /**
     * Get the WebAuthn token message if any were triggered.
     * @return string
     */
    public function webauthnMessage(): string
    {
        foreach ($this->multiChallenge as $challenge)
        {
            if ($challenge->type === "webauthn")
            {
                return $challenge->message;
            }
        }
        return "";
    }

    /**
     * Get the WebAuthnSignRequest for any triggered WebAuthn token.
     * @return string WebAuthnSignRequest or empty string if no WebAuthn token was triggered.
     */
    public function webAuthnSignRequest(): string
    {
        $arr = [];
        $webauthn = "";
        foreach ($this->multiChallenge as $challenge)
        {
            if ($challenge->type === "webauthn")
            {
                $t = json_decode($challenge->webAuthnSignRequest);
                if (empty($webauthn))
                {
                    $webauthn = $t;
                }
                $arr[] = $challenge->attributes['webAuthnSignRequest']['allowCredentials'][0];
            }
        }
        if (empty($webauthn))
        {
            return "";
        }
        else
        {
            $webauthn->allowCredentials = $arr;
            return json_encode($webauthn);
        }
    }

    /**
     * Get the U2FSignRequest for any triggered U2F token.
     * @return string U2FSignRequest or empty string if no U2F token was triggered.
     */
    public function u2fSignRequest(): string
    {
        $ret = "";
        foreach ($this->multiChallenge as $challenge)
        {
            if ($challenge->type === "u2f")
            {
                $ret = $challenge->u2fSignRequest;
                break;
            }
        }
        return $ret;
    }

    /**
     * Get the WebAuthn token message if any were triggered.
     * @return string
     */
    public function u2fMessage(): string
    {
        foreach ($this->multiChallenge as $challenge)
        {
            if ($challenge->type === "u2f")
            {
                return $challenge->message;
            }
        }
        return "";
    }

    // Getters

    /**
     * @return string Combined messages of all triggered token.
     */
    public function getMessages(): string
    {
        return $this->messages;
    }

    /**
     * @return string Message from the response. Should be shown to the user.
     */
    public function getMessage(): string
    {
        return $this->message;
    }

    /**
     * @return string Transaction ID is used to reference the challenges contained in this response in later requests.
     */
    public function getTransactionID(): string
    {
        return $this->transactionID;
    }

    /**
     * @return string Preferred mode in which client should work after triggering challenges.
     */
    public function getPreferredClientMode(): string
    {
        return $this->preferredClientMode;
    }

    /**
     * @return string Raw response in JSON format.
     */
    public function getRawResponse(): string
    {
        return $this->raw;
    }

    /**
     * @return array Array of PIChallenge objects representing the triggered token challenges.
     */
    public function getMultiChallenge(): array
    {
        return $this->multiChallenge;
    }

    /**
     * @return bool Status indicates if the request was processed successfully by the server.
     */
    public function getStatus(): bool
    {
        return $this->status;
    }

    /**
     * @return bool Value is true if the authentication was successful.
     */
    public function getValue(): bool
    {
        return $this->value;
    }

    /**
     * @return string Authentication Status.
     */
    public function getAuthenticationStatus(): string
    {
        return $this->authenticationStatus;
    }

    /**
     * @return array Additional attributes of the user that can be sent by the server.
     */
    public function getDetailAndAttributes(): array
    {
        return $this->detailAndAttributes;
    }

    /**
     * @return string If an error occurred, the error code will be set here.
     */
    public function getErrorCode(): string
    {
        return $this->errorCode;
    }

    /**
     * @return string If an error occurred, the error message will be set here.
     */
    public function getErrorMessage(): string
    {
        return $this->errorMessage;
    }
}
