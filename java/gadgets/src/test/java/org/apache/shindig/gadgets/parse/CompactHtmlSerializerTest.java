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
package org.apache.shindig.gadgets.parse;

import org.apache.shindig.gadgets.parse.nekohtml.NekoSimplifiedHtmlParser;

import com.google.inject.Provider;

import java.io.IOException;
import java.io.StringWriter;

/**
 * Test cases for CompactHtmlSerializer.
 */
public class CompactHtmlSerializerTest extends AbstractParserAndSerializerTest {

  private GadgetHtmlParser full = new NekoSimplifiedHtmlParser(
      new ParseModule.DOMImplementationProvider().get());

  @Override
  public void setUp() throws Exception {
    full.setSerializerProvider(new Provider<HtmlSerializer>() {
      public HtmlSerializer get() {
        return new CompactHtmlSerializer();
      }
    });
  }

  public void testWhitespaceNotCollapsedInSpecialTags() throws Exception {
    String content = loadFile(
        "org/apache/shindig/gadgets/parse/nekohtml/test-with-specialtags.html");
    String expected = loadFile(
        "org/apache/shindig/gadgets/parse/nekohtml/test-with-specialtags-expected.html");
    parseAndCompareBalanced(content, expected, full);
  }
  
  public void testIeConditionalCommentNotRemoved() throws Exception {
    String content = loadFile("org/apache/shindig/gadgets/parse/nekohtml/test-with-iecond-comments.html");
    String expected = loadFile(
        "org/apache/shindig/gadgets/parse/nekohtml/test-with-iecond-comments-expected.html");
    parseAndCompareBalanced(content, expected, full);
  }

  public void testSpecialTagsAreRecognized() {
    assertSpecialTag("textArea");
    assertSpecialTag("scrIpt");
    assertSpecialTag("Style");
    assertSpecialTag("pRe");
  }

  private static void assertSpecialTag(String tagName) {
    assertTrue(tagName + "should be special tag",
        CompactHtmlSerializer.isSpecialTag(tagName));
    assertTrue(tagName.toUpperCase() + " should be special tag",
        CompactHtmlSerializer.isSpecialTag(tagName.toUpperCase()));
    assertTrue(tagName.toLowerCase() + "should be special tag",
        CompactHtmlSerializer.isSpecialTag(tagName.toLowerCase()));
  }

  public void testCollapseHtmlWhitespace() throws IOException {
    assertCollapsed("abc", "abc");
    assertCollapsed("abc ", "abc");
    assertCollapsed(" abc", "abc");
    assertCollapsed("  abc", "abc");
    assertCollapsed("abc \r", "abc");
    assertCollapsed("a\t bc", "a bc");
    assertCollapsed("a  b\n\r  c", "a b c");
    assertCollapsed(" \ra \tb  \n c  ", "a b c");
    assertCollapsed(" \n\t\r ", "");
  }

  private static void assertCollapsed(String input, String expected) throws IOException {
    Appendable output = new StringWriter();
    CompactHtmlSerializer.collapseWhitespace(input, output);
    assertEquals(expected, output.toString());
  }
}
