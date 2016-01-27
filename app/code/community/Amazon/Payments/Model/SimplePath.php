<?php
/**
 * Amazon Payments
 *
 * @category    Amazon
 * @package     Amazon_Payments
 * @copyright   Copyright (c) 2014 Amazon.com
 * @license     http://opensource.org/licenses/Apache-2.0  Apache License, Version 2.0
 */

class Amazon_Payments_Model_SimplePath
{
    const API_ENDPOINT_DOWNLOAD_KEYS = 'https://spow-na.integ.amazon.com/workflow';
    const API_ENDPOINT_GET_PUBLICKEY = 'https://spow-na.integ.amazon.com/getpublickey';

    const PARAM_SP_NAME = '';

    const CONFIG_XML_PATH_PRIVATE_KEY = 'payment/amazon_payments/simplepath/privatekey';
    const CONFIG_XML_PATH_PUBLIC_KEY  = 'payment/amazon_payments/simplepath/publickey';

    /**
     * Generate and save RSA keys
     */
    public function generateKeys()
    {
        $rsa = new Zend_Crypt_Rsa;
        $keys = $rsa->generateKeys(array('private_key_bits' => 2048, 'hashAlgorithm' => 'sha1'));

        $config = Mage::getModel('core/config');
        $config->saveConfig(self::CONFIG_XML_PATH_PUBLIC_KEY, $keys['publicKey'], 'default', 0);
        $config->saveConfig(self::CONFIG_XML_PATH_PRIVATE_KEY, Mage::helper('core')->encrypt($keys['privateKey']), 'default', 0);

        return $keys;
    }

    /**
     * Delete key-pair from config
     */
    public function destroyKeys()
    {
        $config = Mage::getModel('core/config');
        $config->deleteConfig(self::CONFIG_XML_PATH_PUBLIC_KEY, 'default', 0);
        $config->deleteConfig(self::CONFIG_XML_PATH_PRIVATE_KEY, 'default', 0);
    }

    /**
     * Return RSA public key
     *
     * @param bool $pemformat  Return key in PEM format
     */
    public function getPublicKey($pemformat = false, $reset = false)
    {
        $publickey = Mage::getStoreConfig(self::CONFIG_XML_PATH_PUBLIC_KEY, 0);

        // Generate key pair
        if (!$publickey || $reset) {
            $keys = $this->generateKeys();
            $publickey = $keys['publicKey'];
        }

        if (!$pemformat) {
            $publickey = str_replace(array('-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----', "\n"), array('','',''), $publickey);
        }
        return $publickey;
    }

    /**
     * Return RSA private key
     */
    public function getPrivateKey()
    {
        return Mage::helper('core')->decrypt(Mage::getStoreConfig(self::CONFIG_XML_PATH_PRIVATE_KEY, 0));
    }

    /**
     * Convert key to PEM format for openssl functions
     */
    public function key2pem($key)
    {
        return "-----BEGIN PUBLIC KEY-----\n" .
               chunk_split($key, 64, "\n") .
               "-----END PUBLIC KEY-----\n";
    }

    /**
     * Verify and decrypt JSON payload
     *
     * @param string $payloadJson
     */
    public function decryptPayload($payloadJson)
    {
        $payload = Zend_Json::decode($payloadJson, Zend_Json::TYPE_OBJECT);
        $payloadVerify = clone $payload;

        // Validate JSON
        if (!isset($payload->encryptedKey, $payload->encryptedPayload, $payload->iv, $payload->sigKeyID, $payload->signature)) {
            Mage::throwException("Unable to import Amazon keys. Please verify your JSON format and values.");
        }

        // URL decode values
        foreach ($payload as $key => $value) {
            $payload->$key = urldecode($value);
        }

        // Retrieve Amazon public key to verify signature
        try {
            $client = new Zend_Http_Client(self::API_ENDPOINT_GET_PUBLICKEY, array(
                'maxredirects' => 2,
                'timeout'      => 30));

            $client->setParameterGet(array('sigkey_id' => $payload->sigKeyID));

            $response = $client->request();
            $amazonPublickey = urldecode($response->getBody());

        } catch (Exception $e) {
            Mage::throwException($e->getMessage());
        }

        // Use raw JSON (without signature or URL decode) as the data to verify signature
        unset($payloadVerify->signature);
        $payloadVerifyJson = Zend_Json::encode($payloadVerify);

        // Verify signature using Amazon publickey and JSON paylaod
        if ($amazonPublickey && openssl_verify($payloadVerifyJson, base64_decode($payload->signature), $this->key2pem($amazonPublickey), OPENSSL_ALGO_SHA256)) {

            // Decrypt Amazon key using own private key
            $decryptedKey = null;
            openssl_private_decrypt(base64_decode($payload->encryptedKey), $decryptedKey, $this->getPrivateKey(), OPENSSL_PKCS1_OAEP_PADDING);

            // Decrypt final payload (AES 128-bit)
            $finalPayload = mcrypt_cbc(MCRYPT_RIJNDAEL_128, $decryptedKey, base64_decode($payload->encryptedPayload), MCRYPT_DECRYPT, base64_decode($payload->iv));

            if (Zend_Json::decode($finalPayload)) {
                $this->saveToConfig($finalPayload);
                $this->destroyKeys();
                return $finalPayload;
            }

        } else {
            Mage::throwException("Unable to verify signature for JSON payload.");
        }

        return false;
    }

    /**
     * Save values to Mage config
     *
     * @param string $json
     */
    public function saveToConfig($json)
    {
        if ($values = Zend_Json::decode($json, Zend_Json::TYPE_OBJECT)) {
            $config = Mage::getModel('core/config');
            $amazonConfig = Mage::getSingleton('amazon_payments/config');

            $config->saveConfig($amazonConfig::CONFIG_XML_PATH_SELLER_ID, $values->merchant_id, 'default', 0);
            $config->saveConfig($amazonConfig::CONFIG_XML_PATH_CLIENT_ID, $values->client_id, 'default', 0);
            $config->saveConfig($amazonConfig::CONFIG_XML_PATH_CLIENT_SECRET, Mage::helper('core')->encrypt($values->client_secret), 'default', 0);
            $config->saveConfig($amazonConfig::CONFIG_XML_PATH_ACCESS_KEY, $values->access_key, 'default', 0);
            $config->saveConfig($amazonConfig::CONFIG_XML_PATH_ACCESS_SECRET, Mage::helper('core')->encrypt($values->secret_key), 'default', 0);
        }
    }

    /**
     * Return listner URL
     */
    public function getListenerUrl()
    {
        $replace_cleanup = array('index.php/', ':80', ':443');
        return str_replace($replace_cleanup, '', Mage::getUrl('amazon_payments/simplepath', array('_store' => 1, '_forced_secure' => true)));
    }

    /**
     * Return simplepath URL
     */
    public function getSimplepathUrl()
    {
        // Don't generate key-pair or simplepath URL if credentials exist
        if (Mage::getSingleton('amazon_payments/config')->getSellerId()) {
            return;
        }

        return self::API_ENDPOINT_DOWNLOAD_KEYS . '?returnUrl=' . $this->getListenerUrl() .
						'&pub_key=' . urlencode($this->getPublicKey(false, true)) .
						'#event/fromSP';
    }

    /**
     * Return array of form POST params for SimplePath sign up
     */
    public function getFormParams()
    {
        // Retrieve store URLs from config
        $urls = array();
        $db = Mage::getSingleton('core/resource')->getConnection('core_read');

        $select = $db->select()
            ->from('core_config_data')
            ->where('path IN (?)', array('web/unsecure/base_url', 'web/secure/base_url'));

        foreach ($db->fetchAll($select) as $row) {
            $urls[] = str_replace('http:', 'https:', $row['value']);
        }

        return array(
            'locale' => Mage::getStoreConfig('general/country/default'),
            'spName' => self::PARAM_SP_NAME,
            'allowedLoginDomains[]' => array(array_unique($urls)),
            'spSoftwareVersion' => Mage::getVersion(),
            'spAmazonPluginVersion' => Mage::getConfig()->getModuleConfig("Amazon_Payments")->version,
        );
    }

    /**
     * Return array of config for JSON AmazonSp variable.
     *
     * @see Amazon_Payments_Model_System_Config_Backend_Enabled->getCommentText()
     */
    public function getJsonAmazonSpConfig()
    {
        return array(
            'amazonUrl'     => $this->getSimplepathUrl(),
            'pollUrl'       => Mage::helper("adminhtml")->getUrl('adminhtml/amazon_simplepath/poll'),
            //'spUrl'         => Mage::helper("adminhtml")->getUrl('adminhtml/amazon_simplepath/spurl'),
            'isSecure'      => (int) (Mage::app()->getFrontController()->getRequest()->isSecure()),
            'isUsa'         => (int) (Mage::getStoreConfig('general/country/default') == 'US'),
            'hasOpenssl'    => (int) (extension_loaded('openssl')),
            'formParams'    => $this->getFormParams(),
        );
    }
}