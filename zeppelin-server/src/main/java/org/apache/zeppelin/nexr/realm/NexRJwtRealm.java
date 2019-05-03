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
package org.apache.zeppelin.nexr.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.zeppelin.nexr.realm.jwt.NexRJwtAuthToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;

/**
 * NexRJwtRealm
 */
public class NexRJwtRealm extends AuthorizingRealm {

  private static final Logger logger = LoggerFactory.getLogger(NexRJwtRealm.class);

  @Override
  public boolean supports(AuthenticationToken token) {
    return token instanceof NexRJwtAuthToken;
  }

  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(
    AuthenticationToken authenticationToken) throws AuthenticationException {
    NexRJwtAuthToken token = (NexRJwtAuthToken) authenticationToken;
    if (validateToken(token)) {
      getUserInfo();
      // TODO(david.woo): getUerInfo 를 통해, 얻어온 정보를 이용하여 SimpleAccount 를 생성한다.?
      return new SimpleAuthenticationInfo(token.getPrincipal(), token.getCredentials(), getName());
    }
    return null;
  }

  private void getUserInfo() {
  }

  private boolean validateToken(NexRJwtAuthToken token) {
    logger.info("Validate Token: {}", token);
    return true;
  }

  @Override
  protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
    Set<String> roles = new HashSet<>();
    return new SimpleAuthorizationInfo(roles);
  }
}
