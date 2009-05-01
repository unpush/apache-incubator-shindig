/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shindig.gadgets.render;


import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.logging.Level;

import org.apache.shindig.config.ContainerConfig;
import org.apache.shindig.gadgets.http.HttpFetcher;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.common.uri.Uri;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.google.common.collect.ImmutableMultimap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.LinkedHashMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.Multimaps;
import com.google.common.collect.Sets;
import com.google.inject.Inject;

/**
 * Retrieves the rpc services for a container by fetching them from the container's
 * system.listMethods endpoints as defined in the container config.
 */
public class RpcServiceFetcher {

  private static final Logger logger = Logger.getLogger(Renderer.class.getName());

  private static final String JSON_RESPONSE_WRAPPER_ELEMENT = "data";

  private static final String OSAPI_FEATURE_CONFIG = "osapi";

  private static final String GADGETS_FEATURES_CONFIG = "gadgets.features";

  private static final String SYSTEM_LIST_METHODS_METHOD = "system.listMethods";

  /** Key in container config that lists the endpoints offering services */
  private static final String OSAPI_BASE_ENDPOINTS = "endPoints";

  private final ContainerConfig containerConfig;

  private final HttpFetcher fetcher;

  /** @param config Container Config for looking up endpoints */
  @Inject
  public RpcServiceFetcher(ContainerConfig config, HttpFetcher fetcher) {
    this.containerConfig = config;
    this.fetcher = fetcher;
  }

  /**
   * Returns the services, keyed by endpoint for the given container.
   *
   * @param container The particular container whose services we want.
   * @return Map endpoints and their serviceMethod list
   */
  public Multimap<String, String> getServicesForContainer(String container, String host) {
    if (containerConfig == null) {
      return ImmutableMultimap.<String, String>builder().build();
    }
    List<String> endpoints = getEndpointsFromContainerConfig(container, host);
    LinkedHashMultimap<String, String> endpointServices = Multimaps.newLinkedHashMultimap();
    for (String endpoint : endpoints) {
      endpointServices.putAll(endpoint, retrieveServices(endpoint.replace("%host%", host)));
    }
    return ImmutableMultimap.copyOf(endpointServices);
  }

  private List<String> getEndpointsFromContainerConfig(String container, String host) {
    @SuppressWarnings("unchecked")
    Map<String, Object> properties = (Map<String, Object>) containerConfig.getMap(container,
        GADGETS_FEATURES_CONFIG).get(OSAPI_FEATURE_CONFIG);

    @SuppressWarnings("unchecked")
    List<String> endpoints = (List<String>) properties.get(OSAPI_BASE_ENDPOINTS);
    return endpoints;
  }

  private Set<String> retrieveServices(String endpoint) {
    Uri url = Uri.parse(endpoint + "?method=" + SYSTEM_LIST_METHODS_METHOD);
    HttpRequest request = new HttpRequest(url);
    try {
      HttpResponse response = fetcher.fetch(request);
      if (response.getHttpStatusCode() == HttpResponse.SC_OK) {
        return getServicesFromJsonResponse(response.getResponseAsString());
      } else {
        logger.log(Level.SEVERE, "HTTP Error " + response.getHttpStatusCode() +
            " fetching service methods from endpoint " + endpoint);
      }
    } catch (GadgetException ge) {
      logger.log(Level.SEVERE, "Failed to fetch services methods from endpoint " + endpoint +
          ". Error " + ge.getMessage());
    } catch (JSONException je) {
      logger.log(Level.SEVERE, "Failed to parse services methods from endpoint " + endpoint +
          ". " + je.getMessage());
    }
    return ImmutableSet.of();
  }

  private Set<String> getServicesFromJsonResponse(String content)
      throws JSONException {
    Set<String> services = Sets.newHashSet();
    JSONObject js = new JSONObject(content);
    JSONArray json = js.getJSONArray(JSON_RESPONSE_WRAPPER_ELEMENT);
    for (int i = 0; i < json.length(); i++) {
      String o = json.getString(i);
      services.add(o);
    }
    return services;
  }
}
