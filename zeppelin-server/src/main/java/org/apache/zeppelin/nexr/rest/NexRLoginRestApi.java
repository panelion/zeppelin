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
package org.apache.zeppelin.nexr.rest;

import com.google.gson.Gson;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.zeppelin.annotation.ZeppelinApi;
import org.apache.zeppelin.conf.ZeppelinConfiguration;
import org.apache.zeppelin.nexr.realm.NexRJwtRealm;
import org.apache.zeppelin.nexr.realm.jwt.NexRJwtAuthToken;
import org.apache.zeppelin.notebook.Notebook;
import org.apache.zeppelin.notebook.NotebookAuthorization;
import org.apache.zeppelin.server.JsonResponse;
import org.apache.zeppelin.ticket.TicketContainer;
import org.apache.zeppelin.utils.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/**
 * NexR 관련 Login API
 */
@Path("/nexr/login")
@Produces("application/json")
public class NexRLoginRestApi {
  private static final Logger logger = LoggerFactory.getLogger(NexRLoginRestApi.class);
  private static final Gson gson = new Gson();

  private Notebook notebook;
  private ZeppelinConfiguration zeppelinConf;

  public NexRLoginRestApi() {
    super();
  }

  public NexRLoginRestApi(Notebook notebook) {
    super();
    this.notebook = notebook;
    this.zeppelinConf = notebook.getConf();
  }

  @POST
  @ZeppelinApi
  public Response loginWithJwt(@Context HttpHeaders headers) {
    logger.info("Call loginWithJwt");
    JsonResponse response;

    Subject currentUser = org.apache.shiro.SecurityUtils.getSubject();
    if (!currentUser.isAuthenticated()) {
      String strToken = headers.getHeaderString("Authorization");
      NexRJwtAuthToken token = new NexRJwtAuthToken(strToken);
      response = proceedToLogin(currentUser, token);
    } else {
      response = new JsonResponse<Void>(Response.Status.OK, "Already login.", null);
    }
    return response.build();
  }

  private JsonResponse proceedToLogin(Subject currentUser, AuthenticationToken token) {
    JsonResponse response = null;
    try {
      logoutCurrentUser();
      currentUser.getSession(true);
      currentUser.login(token);

      HashSet<String> roles = SecurityUtils.getRoles();
      String principal = SecurityUtils.getPrincipal();

      String ticket = TicketContainer.instance.getTicket(principal);

      Map<String, String> data = new HashMap<>();
      data.put("principal", principal);
      data.put("roles", gson.toJson(roles));
      data.put("ticket", ticket);

      response = new JsonResponse<>(Response.Status.OK, "", data);
      NotebookAuthorization.getInstance().setRoles(principal, roles);

    } catch (AuthenticationException ae) {
      logger.error("Exception in login: ", ae);
    }
    return response;
  }

  private void logoutCurrentUser() {
    Subject currentUser = org.apache.shiro.SecurityUtils.getSubject();
    TicketContainer.instance.removeTicket(SecurityUtils.getPrincipal());
    currentUser.getSession().stop();
    currentUser.logout();
  }

  private NexRJwtRealm getNexrJwtRealm() {
    Collection realmsList = SecurityUtils.getRealmsList();
    if (realmsList != null) {
      for (Object realm : realmsList) {
        String name = realm.getClass().getName();

        logger.debug("RealmClass.getName: " + name);

        if (name.equals("com.nexr.zeppelin.server.realm.NexRJwtRealm")) {
          return (NexRJwtRealm) realm;
        }
      }
    }
    return null;
  }
}
