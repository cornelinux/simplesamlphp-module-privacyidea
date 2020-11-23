<?php
/**
 * This Auth Proc Filter allows the selective deactivation of privacyIDEA for a list of regular expressions
 * which match SAML service provider entityIDs.
 * The filter checks the entityid in the SAML request against a list of regular expressions and sets the state variable
 * $state[enabledPath][enabledKey][0] to false on match, which can be used to disable privacyIDEA.
 * For any value in entityids, the config parameter excludeattributes may be used to enable privacyIDEA for a subset
 * of users which have these attribute values (e.g. memberOf).
 * @author Henning Hollermann <henning.hollermann@netknights.it>
 */

class sspmod_privacyIDEA_Auth_Process_checkEntityID extends SimpleSAML_Auth_ProcessingFilter {

    private $entityids = array();
    private $excludeattributes = array();
    private $setPath = '';
    private $setKey = '';

    private function str_matches_reg_arr($str, $reg_arr) {
        /*
         * This function checks a given string against an array with regular expressions
         * It will return true if a match is found.
         */
        $ret_arr = array();
        foreach ($reg_arr as $reg) {
            if ($reg[0] != "/") {
                $reg = "/" . $reg . "/";
            }
            SimpleSAML_Logger::debug("privacyidea:checkEntityID: test regexp " . $reg .
                " against the string " . $str);
            if (preg_match($reg, $str)) {
                array_push($ret_arr, $reg);
            }
        }
        return $ret_arr;
    }

    public function __construct(array $config, $reserved)
    {
        SimpleSAML_Logger::info("Checking requesting entity ID for privacyIDEA");
        parent::__construct($config, $reserved);
        $cfg = SimpleSAML_Configuration::loadFromArray($config, 'privacyidea:checkEntityID');
        $this->entityids = $cfg->getArray('entityids', null);
        $this->excludeattributes = $cfg->getArray('excludeattributes', null);
        $this->setPath = $cfg->getString('setPath', null);
        $this->setKey = $cfg->getString('setKey', null);

    }

    public function process( &$state ) {
        // the default return value is true, privacyIDEA should be enabled by default.
        $ret = true;
        $request_entityid = $state["Destination"]["entityid"];
        // if the requesting entityid matches the given list set the return parameter to false
        SimpleSAML_Logger::debug("privacyidea:checkEntityID: Requesting entityID is " . $request_entityid);
        $matched_entityids = $this->str_matches_reg_arr($request_entityid, $this->entityids);
        if ($matched_entityids) {
            $ret = false;
            $entityid_key = $matched_entityids[0];
            SimpleSAML_Logger::debug("privacyidea:checkEntityID: Matched entityID is " . $entityid_key);
            // if there is also a match for any attribute value in the excludeattributes
            // fall back to the default return value: true
            if (isset($this->excludeattributes[$entityid_key])) {
                foreach ($this->excludeattributes[$entityid_key] as $attr_key => $attr_regexp_arr) {
                    if (isset($state["Attributes"][$attr_key])) {
                        foreach($state["Attributes"][$attr_key] as $attr_val) {
                            $matched_attrs = $this->str_matches_reg_arr($attr_val, $attr_regexp_arr);
                            if (!empty($matched_attrs)) {
                                $ret = true;
                                SimpleSAML_Logger::error("privacyidea:checkEntityID: Requesting entityID in " .
                                    "list, but excluded by at least one attribute regexp \"" .$attr_key.
                                    "\" = \"" . $matched_attrs[0]. "\".");
                                break;
                            }
                        }
                    } else {
                        SimpleSAML_Logger::debug("privacyidea:checkEntityID: attribute key " .
                            $attr_key . " not contained in request");
                    }
                }
            }
        } else {
            SimpleSAML_Logger::debug("privacyidea:checkEntityID: Requesting entityID " .
                $request_entityid ." not matched by any regexp.");
        }
        $state[$this->setPath][$this->setKey][0] = $ret;
        if ($ret) {$ret_str = "true";} else {$ret_str = "false";}
        SimpleSAML_Logger::debug("Setting \$state[" . $this->setPath. "][".$this->setKey."][0] = ".$ret_str.".");
    }

}
