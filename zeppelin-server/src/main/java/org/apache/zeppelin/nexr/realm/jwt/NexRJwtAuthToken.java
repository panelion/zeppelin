/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.zeppelin.nexr.realm.jwt;

import com.nimbusds.jwt.SignedJWT;
import org.apache.shiro.authc.AuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.regex.Pattern;

/**
 * NexR Auth Token
 */
public class NexRJwtAuthToken implements AuthenticationToken {

  private static final Logger logger
    = LoggerFactory.getLogger(NexRJwtAuthToken.class);

  private static final Pattern BEARER
    = Pattern.compile("^Bearer$", Pattern.CASE_INSENSITIVE);
  private String token;

  public NexRJwtAuthToken(String token) {
    this.token = this.obtainJwtAuthenticationToken(token);
  }

  @Override
  public Object getPrincipal() {
    return token;
  }

  @Override
  public Object getCredentials() {
    return token;
  }

  private String obtainJwtAuthenticationToken(String plainToken) {
    String[] parts = plainToken.split(" ");
    if (parts.length == 2) {
      String scheme = parts[0];
      String realToken = parts[1];
      return BEARER.matcher(scheme).matches() ? realToken : null;
    } else if (parts.length == 1) {
      // Without Bearer
      return parts[0];
    }
    return null;
  }

  public String getUserName() {
    try {
      SignedJWT signed = SignedJWT.parse(this.token);
      return signed.getJWTClaimsSet().getSubject();

    } catch (ParseException e) {
      logger.error(e.getMessage());
    }
    return null;
  }
}
