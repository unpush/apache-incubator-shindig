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
 * under the License.Blob
 */
package org.apache.shindig.gadgets.preload;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.apache.shindig.config.ContainerConfig;
import org.apache.shindig.expressions.Expressions;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.http.HttpResponseBuilder;
import org.apache.shindig.gadgets.http.RequestPipeline;
import org.apache.shindig.gadgets.spec.GadgetSpec;
import org.apache.shindig.gadgets.spec.PipelinedData;
import org.apache.shindig.gadgets.GadgetException;

import org.easymock.EasyMock;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Callable;

import com.google.common.collect.Lists;

/**
 * Test for PipelinedDataPreloader.
 */
public class PipelinedDataPreloaderTest extends PreloaderTestFixture {
  private ContainerConfig containerConfig;
  private Expressions expressions = new Expressions();

  private static final String XML = "<Module xmlns:os=\"" + PipelinedData.OPENSOCIAL_NAMESPACE
      + "\">" + "<ModulePrefs title=\"Title\"/>"
      + "<Content href=\"http://example.org/proxied.php\" view=\"profile\">"
      + "  <os:PeopleRequest key=\"p\" userIds=\"you\"/>"
      + "  <os:PersonAppDataRequest key=\"a\" userId=\"she\"/>" + "</Content></Module>";

  private static final String HTTP_REQUEST_URL =  "http://example.org/preload.html";
  private static final String PARAMS = "a=b&c=d";
  private static final String XML_PARAMS = "a=b&amp;c=d";
  
  private static final String XML_WITH_HTTP_REQUEST = "<Module xmlns:os=\""
      + PipelinedData.OPENSOCIAL_NAMESPACE + "\">"
      + "<ModulePrefs title=\"Title\"/>"
      + "<Content href=\"http://example.org/proxied.php\" view=\"profile\">"
      + "  <os:HttpRequest key=\"p\" href=\"" + HTTP_REQUEST_URL + "\" "
      + "refreshInterval=\"60\" method=\"POST\"/>" + "</Content></Module>";

  private static final String XML_WITH_HTTP_REQUEST_AND_PARAMS = "<Module xmlns:os=\""
    + PipelinedData.OPENSOCIAL_NAMESPACE + "\">"
    + "<ModulePrefs title=\"Title\"/>"
    + "<Content href=\"http://example.org/proxied.php\" view=\"profile\">"
    + "  <os:HttpRequest key=\"p\" href=\"" + HTTP_REQUEST_URL + "\" "
    + "                  method=\"POST\" params=\"" + XML_PARAMS + "\"/>"
    + "</Content></Module>";

  private static final String XML_WITH_HTTP_REQUEST_AND_GET_PARAMS = "<Module xmlns:os=\""
    + PipelinedData.OPENSOCIAL_NAMESPACE + "\">"
    + "<ModulePrefs title=\"Title\"/>"
    + "<Content href=\"http://example.org/proxied.php\" view=\"profile\">"
    + "  <os:HttpRequest key=\"p\" href=\"" + HTTP_REQUEST_URL + "\" "
    + "                  method=\"GET\" params=\"" + XML_PARAMS + "\"/>"
    + "</Content></Module>";
  
  @Before
  public void createContainerConfig() {
    containerConfig = EasyMock.createMock(ContainerConfig.class);
    EasyMock.expect(containerConfig.getString(CONTAINER, "gadgets.osDataUri")).andStubReturn(
        "http://%host%/social/rpc");
    EasyMock.replay(containerConfig);
  }

  @Test
  public void testSocialPreload() throws Exception {
    GadgetSpec spec = new GadgetSpec(GADGET_URL, XML);

    String socialResult = "[{id:'p', data:1}, {id:'a', data:2}]";
    RecordingRequestPipeline pipeline = new RecordingRequestPipeline(socialResult);
    PipelinedDataPreloader preloader = new PipelinedDataPreloader(pipeline, containerConfig,
        expressions);
    
    view = "profile";
    contextParams.put("st", "token");

    Collection<Callable<PreloadedData>> tasks = preloader.createPreloadTasks(context, spec,
        PreloaderService.PreloadPhase.PROXY_FETCH);
    assertEquals(1, tasks.size());
    // Nothing fetched yet
    assertEquals(0, pipeline.requests.size());

    Collection<Object> result = tasks.iterator().next().call().toJson();
    assertEquals(2, result.size());

    JSONObject resultWithKeyP = new JSONObject("{id: 'p', data: 1}");
    JSONObject resultWithKeyA = new JSONObject("{id: 'a', data: 2}");
    Iterator<Object> iter = result.iterator();
    assertEquals(resultWithKeyP.toString(), iter.next().toString());
    assertEquals(resultWithKeyA.toString(), iter.next().toString());

    // Should have only fetched one request
    assertEquals(1, pipeline.requests.size());
    HttpRequest request = pipeline.requests.get(0);

    assertEquals("http://" + context.getHost() + "/social/rpc?st=token", request.getUri()
        .toString());
    assertEquals("POST", request.getMethod());
    assertTrue(request.getContentType().startsWith("application/json"));
  }

  @Test
  public void testHttpPreload() throws Exception {
    GadgetSpec spec = new GadgetSpec(GADGET_URL, XML_WITH_HTTP_REQUEST);

    String httpResult = "{foo: 'bar'}";
    RecordingRequestPipeline pipeline = new RecordingRequestPipeline(httpResult);
    PipelinedDataPreloader preloader = new PipelinedDataPreloader(pipeline, containerConfig,
        expressions);
    view = "profile";

    Collection<Callable<PreloadedData>> tasks = preloader.createPreloadTasks(context, spec,
        PreloaderService.PreloadPhase.PROXY_FETCH);
    assertEquals(1, tasks.size());
    // Nothing fetched yet
    assertEquals(0, pipeline.requests.size());

    Collection<Object> result = tasks.iterator().next().call().toJson();
    assertEquals(1, result.size());

    String expectedResult = "{data: {foo: 'bar'}, id: 'p'}";
    assertEquals(new JSONObject(expectedResult).toString(), result.iterator().next().toString());

    // Should have only fetched one request
    assertEquals(1, pipeline.requests.size());
    HttpRequest request = pipeline.requests.get(0);

    assertEquals(HTTP_REQUEST_URL, request.getUri().toString());
    assertEquals("POST", request.getMethod());
    assertEquals(60, request.getCacheTtl());
  }

  @Test
  public void testHttpPreloadWithPostParams() throws Exception {
    GadgetSpec spec = new GadgetSpec(GADGET_URL, XML_WITH_HTTP_REQUEST_AND_PARAMS);

    String httpResult = "{foo: 'bar'}";
    RecordingRequestPipeline pipeline = new RecordingRequestPipeline(httpResult);
    PipelinedDataPreloader preloader = new PipelinedDataPreloader(pipeline, containerConfig,
        expressions);
    view = "profile";

    Collection<Callable<PreloadedData>> tasks = preloader.createPreloadTasks(context, spec,
        PreloaderService.PreloadPhase.PROXY_FETCH);
    tasks.iterator().next().call();

    // Should have only fetched one request
    assertEquals(1, pipeline.requests.size());
    HttpRequest request = pipeline.requests.get(0);

    assertEquals(HTTP_REQUEST_URL, request.getUri().toString());
    assertEquals("POST", request.getMethod());
    assertEquals(PARAMS, request.getPostBodyAsString());
  }

  @Test
  public void testHttpPreloadWithGetParams() throws Exception {
    GadgetSpec spec = new GadgetSpec(GADGET_URL, XML_WITH_HTTP_REQUEST_AND_GET_PARAMS);

    String httpResult = "{foo: 'bar'}";
    RecordingRequestPipeline pipeline = new RecordingRequestPipeline(httpResult);
    PipelinedDataPreloader preloader = new PipelinedDataPreloader(pipeline, containerConfig,
        expressions);
    view = "profile";

    Collection<Callable<PreloadedData>> tasks = preloader.createPreloadTasks(context, spec,
        PreloaderService.PreloadPhase.PROXY_FETCH);
    tasks.iterator().next().call();

    // Should have only fetched one request
    assertEquals(1, pipeline.requests.size());
    HttpRequest request = pipeline.requests.get(0);

    assertEquals(HTTP_REQUEST_URL + "?" + PARAMS, request.getUri().toString());
    assertEquals("GET", request.getMethod());
  }


  @Test
  public void testSocialPreloadForOtherView() throws Exception {
    GadgetSpec spec = new GadgetSpec(GADGET_URL, XML);

    String socialResult = "[{id:'p', data:1}, {id:'a', data:2}]";
    RecordingRequestPipeline pipeline = new RecordingRequestPipeline(socialResult);
    PipelinedDataPreloader preloader = new PipelinedDataPreloader(pipeline, containerConfig,
        expressions);
    view = "canvas";
    contextParams.put("st", "token");

    Collection<Callable<PreloadedData>> tasks = preloader.createPreloadTasks(context, spec,
        PreloaderService.PreloadPhase.PROXY_FETCH);
    assertTrue(tasks.isEmpty());
  }

  @Test
  public void testSocialPreloadForHtmlRender() throws Exception {
    GadgetSpec spec = new GadgetSpec(GADGET_URL, XML);

    String socialResult = "[{id:'p', data:1}, {id:'a', data:2}]";
    RecordingRequestPipeline pipeline = new RecordingRequestPipeline(socialResult);
    PipelinedDataPreloader preloader = new PipelinedDataPreloader(pipeline, containerConfig,
        expressions);
    view = "profile";
    contextParams.put("st", "token");

    Collection<Callable<PreloadedData>> tasks = preloader.createPreloadTasks(context, spec,
        PreloaderService.PreloadPhase.HTML_RENDER);
    assertTrue(tasks.isEmpty());
  }

  // TODO: test HttpPreloads

  private static class RecordingRequestPipeline implements RequestPipeline {
    public final List<HttpRequest> requests = Lists.newArrayList();
    private final String content;

    public RecordingRequestPipeline(String content) {
      this.content = content;
    }

    public HttpResponse execute(HttpRequest request) {
      requests.add(request);
      return new HttpResponseBuilder().setResponseString(content).create();
    }

    public void normalizeProtocol(HttpRequest request) throws GadgetException {}
  }
}
