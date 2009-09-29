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
package org.apache.shindig.gadgets.templates.tags;

import org.apache.shindig.common.EasyMockTestCase;
import org.apache.shindig.common.PropertiesModule;
import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.common.xml.DomUtil;
import org.apache.shindig.gadgets.Gadget;
import org.apache.shindig.gadgets.GadgetContext;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.GadgetFeature;
import org.apache.shindig.gadgets.GadgetFeatureRegistry;
import org.apache.shindig.gadgets.JsLibrary;
import org.apache.shindig.gadgets.parse.ParseModule;
import org.apache.shindig.gadgets.parse.nekohtml.NekoSimplifiedHtmlParser;
import org.apache.shindig.gadgets.rewrite.XPathWrapper;
import org.apache.shindig.gadgets.templates.TagRegistry;
import org.apache.shindig.gadgets.templates.TemplateContext;
import org.apache.shindig.gadgets.templates.TemplateProcessor;
import org.apache.shindig.protocol.conversion.BeanJsonConverter;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.inject.Guice;
import com.google.inject.Injector;
import org.easymock.EasyMock;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.DocumentFragment;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.el.ELResolver;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;

/**
 * Basic tests for Flash tag
 */
public class FlashTagHandlerTest extends EasyMockTestCase {

  private MyTemplateProcessor processor;
  private DOMImplementation documentProvider;
  private FlashTagHandler handler;
  private GadgetFeatureRegistry featureRegistry;
  private GadgetContext gadgetContext = mock(GadgetContext.class);
  private Gadget gadget = mock(Gadget.class);

  private NekoSimplifiedHtmlParser parser;
  protected Document result;

  @Before
  public void setUp() throws Exception {
    processor = new MyTemplateProcessor();
    processor.context = new TemplateContext(gadget, Collections.<String, JSONObject>emptyMap());
    Injector injector = Guice.createInjector(new ParseModule(), new PropertiesModule());
    documentProvider = injector.getInstance(DOMImplementation.class);
    parser = injector.getInstance(NekoSimplifiedHtmlParser.class);
    featureRegistry = mock(GadgetFeatureRegistry.class);
    handler = new FlashTagHandler(new BeanJsonConverter(injector), featureRegistry,
        "http://example.org/ns", "9.0.115");
    result = parser.parseDom("");

    EasyMock.expect(gadget.getContext()).andReturn(gadgetContext).anyTimes();
  }

  private void expectFeatureLookup() throws GadgetException {
    EasyMock.expect(featureRegistry.getFeatures(EasyMock.<Collection<String>>anyObject())).andReturn(
        ImmutableSet.of(new GadgetFeature("swfobject",
            ImmutableList.of(
                JsLibrary.create(JsLibrary.Type.INLINE, "swfobject()", "swfobject", null)),
            Collections.<String>emptySet())));
    EasyMock.expect(gadgetContext.getContainer()).andReturn("default");
  }

  private void expectSecurityToken() {
    EasyMock.expect(gadgetContext.getParameter(EasyMock.eq("st"))).andReturn("12345");
  }

  public void testBasicRender() throws Exception {
    Document document = parser.parseDom(
        "<script type='text/os-template'>"
            + "<osx:Flash swf='http://www.example.org/test.swf'>"
            + "Click Me"
          + "</osx:Flash></script>");
    Element tag = DomUtil.getElementsByTagNameCaseInsensitive(document, ImmutableSet.of("osx:flash"))
        .get(0);

    expectSecurityToken();
    EasyMock.expect(gadget.sanitizeOutput()).andReturn(false);
    expectFeatureLookup();
    replay();
    handler.process(result.getDocumentElement().getFirstChild().getNextSibling(), tag, processor);
    XPathWrapper wrapper = new XPathWrapper(result);
    assertEquals(wrapper.getValue("/html/head/script[1]"), "swfobject()");
    assertEquals(wrapper.getValue("/html/body/div/@id"), "os_xFlash_alt_1");
    assertEquals(wrapper.getValue("/html/body/div"), "Click Me");
    assertNull(wrapper.getNode("/html/body/div/@onclick"));
    assertEquals(wrapper.getValue("/html/body/script[1]"),
        "swfobject.embedSWF(\"http://www.example.org/test.swf\",\"os_xFlash_alt_1\",\"100px\","
            + "\"100px\",\"9.0.115\",null,null,{\"flashvars\":\"st=12345\"},{});");
    verify();
  }

  public void testSanitizedRender() throws Exception {
    Document document = parser.parseDom(
        "<script type='text/os-template'>"
            + "<osx:Flash swf='http://www.example.org/test.swf'>"
            + "Click Me"
          + "</osx:Flash></script>");
    Element tag = DomUtil.getElementsByTagNameCaseInsensitive(document, ImmutableSet.of("osx:flash"))
        .get(0);

    expectSecurityToken();
    EasyMock.expect(gadget.sanitizeOutput()).andReturn(true);
    expectFeatureLookup();
    replay();
    handler.process(result.getDocumentElement().getFirstChild().getNextSibling(), tag, processor);
    XPathWrapper wrapper = new XPathWrapper(result);
    assertEquals(wrapper.getValue("/html/head/script[1]"), "swfobject()");
    assertEquals(wrapper.getValue("/html/body/div/@id"), "os_xFlash_alt_1");
    assertEquals(wrapper.getValue("/html/body/div"), "Click Me");
    assertNull(wrapper.getNode("/html/body/div/@onclick"));
    assertEquals(wrapper.getValue("/html/body/script[1]"),
        "swfobject.embedSWF(\"http://www.example.org/test.swf\",\"os_xFlash_alt_1\",\"100px\","
            + "\"100px\",\"9.0.115\",null,null,{\"swliveconnect\":false,"
            + "\"flashvars\":\"st=12345\",\"allowscriptaccess\":\"never\",\"allownetworking\":\"internal\"},{});");
    verify();
  }

  public void testSanitizedRenderClickToPlay() throws Exception {
    Document document = parser.parseDom(
        "<script type='text/os-template'>"
            + "<osx:flash swf='http://www.example.org/test.swf' play='onclick'>"
            + "Click Me"
          + "</osx:flash></script>");
    Element tag = DomUtil.getElementsByTagNameCaseInsensitive(document, ImmutableSet.of("osx:flash"))
        .get(0);

    expectSecurityToken();
    EasyMock.expect(gadget.sanitizeOutput()).andReturn(true);
    expectFeatureLookup();
    replay();
    handler.process(result.getDocumentElement().getFirstChild().getNextSibling(), tag, processor);
    XPathWrapper wrapper = new XPathWrapper(result);
    assertEquals(wrapper.getValue("/html/head/script[1]"), "swfobject()");
    assertEquals(wrapper.getValue("/html/body/div/@id"), "os_xFlash_alt_1");
    assertEquals(wrapper.getValue("/html/body/div"), "Click Me");
    assertEquals(wrapper.getValue("/html/body/div/@onclick"), "os_xFlash_alt_1()");
    assertEquals(wrapper.getValue("/html/body/script[1]"),
        "function os_xFlash_alt_1(){ swfobject.embedSWF(\"http://www.example.org/test.swf\","
            + "\"os_xFlash_alt_1\",\"100px\",\"100px\",\"9.0.115\",null,null,"
            + "{\"swliveconnect\":false,\"flashvars\":\"st=12345\",\"allowscriptaccess\":\"never\",\"allownetworking\":\"internal\"},{}); }");
    verify();
  }

  @Test
  public void testConfigCreation() throws Exception {
    Document doc = documentProvider.createDocument(null, null, null);
    // Create a mock tag;  the name doesn't truly matter
    Element tag = doc.createElement("test");
    tag.setAttribute("id", "myflash");
    tag.setAttribute("class", "stylish");
    tag.setAttribute("swf", "http://www.example.org/x.swf");
    tag.setAttribute("width", "100px");
    tag.setAttribute("height", "200px");
    tag.setAttribute("name", "myflashname");
    tag.setAttribute("play", "onclick");
    tag.setAttribute("menu", "true");
    tag.setAttribute("scale", "exactfit");
    tag.setAttribute("wmode", "transparent");
    tag.setAttribute("devicefont", "true");
    tag.setAttribute("swliveconnect", "true");
    tag.setAttribute("allowscriptaccess", "samedomain");
    //tag.setAttribute("loop", "true");
    tag.setAttribute("quality", "autohigh");
    tag.setAttribute("salign", "tl");
    tag.setAttribute("bgcolor", "#77ff77");
    tag.setAttribute("allowfullscreen", "true");
    tag.setAttribute("allownetworking", "none");
    tag.setAttribute("flashvars", "a=b&c=d");
    FlashTagHandler.SwfObjectConfig config = handler.getSwfConfig(tag, processor);
    assertEquals(config.id,  "myflash");
    assertEquals(config.clazz,  "stylish");
    assertEquals(config.swf, Uri.parse("http://www.example.org/x.swf"));
    assertEquals(config.width, "100px");
    assertEquals(config.height, "200px");
    assertEquals(config.name, "myflashname");
    assertEquals(config.play, FlashTagHandler.SwfObjectConfig.Play.onclick);
    assertEquals(config.menu, Boolean.TRUE);
    assertEquals(config.scale, FlashTagHandler.SwfObjectConfig.Scale.exactfit);
    assertEquals(config.wmode, FlashTagHandler.SwfObjectConfig.WMode.transparent);
    assertEquals(config.devicefont, Boolean.TRUE);
    assertEquals(config.swliveconnect, Boolean.TRUE);
    assertEquals(config.allowscriptaccess, FlashTagHandler.SwfObjectConfig.ScriptAccess.samedomain);
    assertNull(config.loop);
    assertEquals(config.quality, FlashTagHandler.SwfObjectConfig.Quality.autohigh);
    assertEquals(config.salign, FlashTagHandler.SwfObjectConfig.SAlign.tl);
    assertEquals(config.bgcolor, "#77ff77");
    assertEquals(config.allowfullscreen, Boolean.TRUE);
    assertEquals(config.allownetworking, FlashTagHandler.SwfObjectConfig.NetworkAccess.none);
    assertEquals(config.flashvars, "a=b&c=d");
  }

  @Test
  public void testConfigBindingFailure() throws Exception {
    Document document = parser.parseDom(
        "<script type='text/os-template'>"
            + "<osx:flash swf='http://www.example.org/test.swf' play='junk'>"
            + "Click Me"
          + "</osx:flash></script>");
    Element tag = DomUtil.getElementsByTagNameCaseInsensitive(document, ImmutableSet.of("osx:flash"))
        .get(0);
    handler.process(result.getDocumentElement().getFirstChild().getNextSibling(), tag, processor);
    XPathWrapper wrapper = new XPathWrapper(result);
    assertTrue(wrapper.getValue("/html/body/span").startsWith("Failed to process os:Flash tag"));
  }

  private class MyTemplateProcessor implements TemplateProcessor {
    public TemplateContext context;

    public DocumentFragment processTemplate(Element template, TemplateContext templateContext,
                                            ELResolver globals, TagRegistry registry) {
      throw new UnsupportedOperationException();
    }

    public TemplateContext getTemplateContext() {
      return context;
    }

    public void processRepeat(Node result, Element element, Iterable<?> dataList,
                              Runnable onEachLoop) {
      // for (Object data : dataList) produces an unused variable warning
      Iterator<?> iterator = dataList.iterator();
      while (iterator.hasNext()) {
        iterator.next();
        onEachLoop.run();
      }
    }

    public <T> T evaluate(String expression, Class<T> type, T defaultValue) {
      return type.cast(expression);
    }

    public void processChildNodes(Node result, Node source) {
      NodeList childNodes = source.getChildNodes();
      for (int i = 0; i < childNodes.getLength(); i++) {
        Node child = childNodes.item(0).cloneNode(true);
        result.getOwnerDocument().adoptNode(child);
        result.appendChild(child);
      }
    }
  }
}
