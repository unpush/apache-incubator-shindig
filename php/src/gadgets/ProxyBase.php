<?php
/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

require_once 'src/gadgets/MakeRequest.php';

/**
 * This class contains the shared methods between the Proxy and makeRequest handlers
 */
class ProxyBase {
  /**
   * @var GadgetContext
   */
  public $context;

  public function __construct($context, MakeRequest $makeRequest = null) {
    $this->context = $context;
    if (isset($makeRequest)) {
      $this->makeRequest = $makeRequest;
    } else {
      $this->makeRequest = new MakeRequest();
    }
  }

  /**
   * Retrieves the actual content
   *
   * @param string $url the url to fetch
   * @param string $method http method
   * @param SecurityTokenDecoder $signer
   * @return RemoteContentRequest the filled in request (RemoteContentRequest)
   */
  protected function buildRequest($url, $method = 'GET', $signer = null) {
    // TODO: Check to see if we can just use MakeRequestOptions::fromCurrentRequest
    $st = isset($_GET['st']) ? $_GET['st'] : (isset($_POST['st']) ? $_POST['st'] : false);
    $body = isset($_GET['postData']) ? $_GET['postData'] : (isset($_POST['postData']) ? $_POST['postData'] : false);
    $authz = isset($_GET['authz']) ? $_GET['authz'] : (isset($_POST['authz']) ? $_POST['authz'] : null);
    $headers = isset($_GET['headers']) ? $_GET['headers'] : (isset($_POST['headers']) ? $_POST['headers'] : null);
    $params = new MakeRequestOptions($url);
    $params->setSecurityTokenString($st)
      ->setAuthz($authz)
      ->setRequestBody($body)
      ->setHttpMethod($method)
      ->setFormEncodedRequestHeaders($headers);
    return $this->makeRequest->buildRequest($this->context, $params, $signer);
  }

  /**
   * Sets the caching (Cache-Control & Expires) with a cache age of $lastModified
   * or if $lastModified === false, sets Pragma: no-cache & Cache-Control: no-cache
   */
  protected function setCachingHeaders($lastModified = false) {
    $maxAge = $this->context->getIgnoreCache() ? false : $this->context->getRefreshInterval();
    if ($maxAge) {
      if ($lastModified) {
        header("Last-Modified: $lastModified");
      }
      // time() is a kernel call, so lets avoid it and use the request time instead
      $time = $_SERVER['REQUEST_TIME'];
      $expires = $maxAge !== false ? $time + $maxAge : $time - 3000;
      $public = $maxAge ? 'public' : 'private';
      $maxAge = $maxAge === false ? '0' : $maxAge;
      header("Cache-Control: {$public}; max-age={$maxAge}", true);
      header("Expires: " . gmdate("D, d M Y H:i:s", $expires) . " GMT", true);
    } else {
      header("Cache-Control: no-cache", true);
      header("Pragma: no-cache", true);
    }
  }

  /**
   * Does a quick-and-dirty url validation
   *
   * @param string $url
   * @return string the 'validated' url
   */
  protected function validateUrl($url) {
    return MakeRequestOptions::validateUrl($url);
  }

  /**
   * Returns the request headers, using the apache_request_headers function if it's
   * available, and otherwise tries to guess them from the $_SERVER superglobal
   *
   * @return unknown
   */
  protected function request_headers() {
    // Try to use apache's request headers if available
    if (function_exists("apache_request_headers")) {
      if (($headers = apache_request_headers())) {
        return $headers;
      }
    }
    // if that failed, try to create them from the _SERVER superglobal
    $headers = array();
    foreach (array_keys($_SERVER) as $skey) {
      if (substr($skey, 0, 5) == "HTTP_") {
        $headername = str_replace(" ", "-", ucwords(strtolower(str_replace("_", " ", substr($skey, 0, 5)))));
        $headers[$headername] = $_SERVER[$skey];
      }
    }
    return $headers;
  }
}
