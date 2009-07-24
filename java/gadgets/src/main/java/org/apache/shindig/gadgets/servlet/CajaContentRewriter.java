/*
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
package org.apache.shindig.gadgets.servlet;

import org.apache.commons.lang.StringUtils;
import org.apache.shindig.gadgets.Gadget;
import org.apache.shindig.gadgets.rewrite.MutableContent;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.net.URI;
import java.util.Map;
import java.util.logging.Logger;

import com.google.caja.lexer.CharProducer;
import com.google.caja.lexer.ExternalReference;
import com.google.caja.lexer.FilePosition;
import com.google.caja.lexer.InputSource;
import com.google.caja.lexer.escaping.Escaping;
import com.google.caja.opensocial.DefaultGadgetRewriter;
import com.google.caja.opensocial.GadgetRewriteException;
import com.google.caja.opensocial.UriCallback;
import com.google.caja.opensocial.UriCallbackException;
import com.google.caja.parser.html.Nodes;
import com.google.caja.reporting.BuildInfo;
import com.google.caja.reporting.Message;
import com.google.caja.reporting.MessageContext;
import com.google.caja.reporting.MessageLevel;
import com.google.caja.reporting.MessageQueue;
import com.google.caja.reporting.SimpleMessageQueue;
import com.google.caja.reporting.SnippetProducer;
import com.google.common.collect.Maps;

public class CajaContentRewriter implements org.apache.shindig.gadgets.rewrite.GadgetRewriter {
  private final Logger logger = Logger.getLogger(CajaContentRewriter.class.getName());

  public void rewrite(Gadget gadget, MutableContent content) {
    if (gadget.getSpec().getModulePrefs().getFeatures().containsKey("caja") ||
        "1".equals(gadget.getContext().getParameter("caja"))) {

      final URI retrievedUri = gadget.getContext().getUrl().toJavaUri();
      UriCallback cb = new UriCallback() {
        public Reader retrieve(ExternalReference externalReference, String string)
            throws UriCallbackException {
          logger.info("Retrieving " + externalReference.toString());
          try {
            URI resourceUri = retrievedUri.resolve(externalReference.getUri());
            Reader in = new InputStreamReader(
                resourceUri.toURL().openConnection().getInputStream(), "UTF-8");
            char[] buf = new char[4096];
            StringBuilder sb = new StringBuilder();
            for (int n; (n = in.read(buf)) > 0;) {
              sb.append(buf, 0, n);
            }
            return new StringReader(sb.toString());
          } catch (java.net.MalformedURLException ex) {
            throw new UriCallbackException(externalReference, ex);
          } catch (IOException ex) {
            throw new UriCallbackException(externalReference, ex);
          }
        }

        public URI rewrite(ExternalReference externalReference, String string) {
          return retrievedUri.resolve(externalReference.getUri());
        }
      };

      MessageQueue mq = new SimpleMessageQueue();
      BuildInfo bi = BuildInfo.getInstance();
      DefaultGadgetRewriter rw = new DefaultGadgetRewriter(bi, mq);
      rw.setValijaMode(true);
      InputSource is = new InputSource(retrievedUri);
      String origContent = content.getContent();
      CharProducer input = CharProducer.Factory.create(
          new StringReader(origContent),
          FilePosition.instance(is, 5, 5, 5));
      StringBuilder output = new StringBuilder();

      Document doc = content.getDocument();
      try {
        StringBuilder htmlAndJs = new StringBuilder();
        rw.rewriteContent(retrievedUri, input, cb, htmlAndJs);
        int splitPoint = htmlAndJs.indexOf("<script");
        String script = htmlAndJs.substring(splitPoint);
        String html = htmlAndJs.substring(0, splitPoint);
        String htmlElement = 
          "<div id=\"cajoled-output\" class=\"g___\">" +
          html +
          "</div>";
        output.append(htmlElement);
        output.append(tameCajaClientApi());
        output.append(script);
      } catch (Exception e) {
        content.setContent(messagesToHtml(doc, is, origContent, mq));
        throwCajolingException(e, mq);
        return;
      }
      content.setContent(output.toString());
    }
  }

  private String messagesToHtml(Document doc, InputSource is, CharSequence orig, MessageQueue mq) {
    MessageContext mc = new MessageContext();
    Map<InputSource, CharSequence> originalSrc = Maps.newHashMap();
    originalSrc.put(is, orig);
    mc.addInputSource(is);
    SnippetProducer sp = new SnippetProducer(originalSrc, mc);

    StringBuilder messageText = new StringBuilder();
    for (Message msg : mq.getMessages()) {
      // Ignore LINT messages
      if (MessageLevel.LINT.compareTo(msg.getMessageLevel()) <= 0) {
        String snippet = sp.getSnippet(msg);

        messageText.append(msg.getMessageLevel().name())
                   .append(" ")
                   .append(html(msg.format(mc)));
        if (!StringUtils.isEmpty(snippet)) {
          messageText.append("\n").append(snippet);
        }
      }
    }
    Element errElement = doc.createElement("pre");
    errElement.appendChild(doc.createTextNode(messageText.toString()));
    return messageText.toString();
  }

  private static String html(CharSequence s) {
    StringBuilder sb = new StringBuilder();
    Escaping.escapeXml(s, false, sb);
    return sb.toString();
  }

  private String tameCajaClientApi() {
    return "<script>" +
      "opensocial.Container.get().enableCaja();" +
      "</script>";
  }

    private void throwCajolingException(Exception cause, MessageQueue mq) {
    StringBuilder errbuilder = new StringBuilder();
    MessageContext mc = new MessageContext();

    if (cause != null) {
      errbuilder.append(cause).append('\n');
    }

    for (Message m : mq.getMessages()) {
      errbuilder.append(m.format(mc)).append('\n');
    }

    logger.info("Unable to cajole gadget: " + errbuilder);

    // throw new GadgetException(
    //    GadgetException.Code.MALFORMED_FOR_SAFE_INLINING, errbuilder.toString());
  }
}
