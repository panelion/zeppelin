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

import org.apache.commons.lang.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 * NexR 전용 Apache Shiro Filter
 */
public class NexRJwtAuthFilter extends BasicHttpAuthenticationFilter {

  private static final Logger logger = LoggerFactory.getLogger(NexRJwtAuthFilter.class);

  @Override
  protected boolean isLoginAttempt(ServletRequest request, ServletResponse response) {
    HttpServletRequest httpServletRequest = (HttpServletRequest) request;
    String authorization = httpServletRequest.getHeader("Authorization");
    return authorization != null;
  }

  @Override
  protected boolean executeLogin(
    ServletRequest request, ServletResponse response) throws Exception {
    HttpServletRequest httpServletRequest = (HttpServletRequest) request;
    String authorization = httpServletRequest.getHeader("Authorization");
    NexRJwtAuthToken token = new NexRJwtAuthToken(authorization);

    if (StringUtils.isBlank(token.getCredentials().toString()) ||
            StringUtils.isBlank(token.getPrincipal().toString())) {
      throw new UnauthorizedException("Token is invalid.");
    }

    if (!SecurityUtils.getSubject().isAuthenticated()) {
      SecurityUtils.getSubject().login(token);
    }
    return true;
  }


  @Override
  protected boolean isAccessAllowed(ServletRequest request,
                                    ServletResponse response,
                                    Object mappedValue) {
    logger.info("Try NexR JWT Login.");
    // TODO(david.woo): Session 에 저장된 로그인 정보와 Token 정보를 비교하여 로그인 하지 않고,
    // Subject 를 사용할 수 있도록 수정
    if (isLoginAttempt(request, response)) {
      try {
        executeLogin(request, response);
      } catch (Exception e) {
        logger.error(e.getMessage());
        return false;
      }
    }
    return true;
  }

  @Override
  protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
    // TODO(David.woo): Response Header 에 특정 값을 입력해야 하는 경우에 사용.
    return super.preHandle(request, response);
  }
}
