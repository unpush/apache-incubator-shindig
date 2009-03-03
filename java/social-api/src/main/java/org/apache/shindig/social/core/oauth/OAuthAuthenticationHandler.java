/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.apache.shindig.social.core.oauth;

import org.apache.shindig.auth.AuthenticationHandler;
import org.apache.shindig.auth.AuthenticationMode;
import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.social.opensocial.oauth.OAuthDataStore;
import org.apache.shindig.social.opensocial.oauth.OAuthEntry;

import com.google.inject.Inject;
import net.oauth.OAuthAccessor;
import net.oauth.OAuthConsumer;
import net.oauth.OAuthException;
import net.oauth.OAuthMessage;
import net.oauth.OAuthServiceProvider;
import net.oauth.SimpleOAuthValidator;
import net.oauth.server.OAuthServlet;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URISyntaxException;

/**
 * Normal three legged OAuth handler
 */
public class OAuthAuthenticationHandler implements AuthenticationHandler {
  private OAuthDataStore store;

  @Inject
  public OAuthAuthenticationHandler(OAuthDataStore store) {
    this.store = store;
  }

  public String getName() {
    return AuthenticationMode.OAUTH.name();
  }

  public String getWWWAuthenticateHeader(String realm) {
    return String.format("OAuth realm=\"%s\"", realm);
  }

  public SecurityToken getSecurityTokenFromRequest(HttpServletRequest request) {
    OAuthMessage message = OAuthServlet.getMessage(request, null);
    OAuthEntry entry;

    try {
      // We only return null if this request 
      if (message.getToken() == null) return null;
      // no token available...

      entry = store.getEntry(message.getToken());
    } catch (IOException e) {
      return null;
    }

    if (entry == null)
      throw new InvalidAuthenticationException("access token not found.", null);
    if (entry.type != OAuthEntry.Type.ACCESS)
      throw new InvalidAuthenticationException("token is not an access token.", null);
    if (entry.isExpired())
      throw new InvalidAuthenticationException("access token has expired.", null);

    OAuthServiceProvider provider = new OAuthServiceProvider(null, null, null);
    OAuthAccessor accessor = new OAuthAccessor(new OAuthConsumer(null, entry.consumerKey,
        store.getConsumer(entry.consumerKey).consumerSecret, provider));

    accessor.tokenSecret = entry.tokenSecret;
    accessor.accessToken = entry.token;

    try {
      message.validateMessage(accessor, new SimpleOAuthValidator());
    } catch (OAuthException e) {
      throw new InvalidAuthenticationException(e.getMessage(), e);
    } catch (IOException e) {
      throw new InvalidAuthenticationException(e.getMessage(), e);
    } catch (URISyntaxException e) {
      throw new InvalidAuthenticationException(e.getMessage(), e);
    }

    return new OAuthSecurityToken(entry.userId, entry.callbackUrl, entry.appId,
        entry.domain, entry.container);
  }
}
