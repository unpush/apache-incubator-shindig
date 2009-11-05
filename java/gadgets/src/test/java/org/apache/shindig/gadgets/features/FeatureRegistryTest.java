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
package org.apache.shindig.gadgets.features;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.common.uri.UriBuilder;
import org.apache.shindig.config.ContainerConfig;
import org.apache.shindig.gadgets.GadgetContext;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.RenderingContext;
import org.junit.Before;
import org.junit.Test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import java.util.Map;

public class FeatureRegistryTest {
  private static final String NODEP_TPL =
      getFeatureTpl("nodep", new String[] {});
  private static final String TOP_TPL =
      getFeatureTpl("top", new String[] { "mid_a", "mid_b" });
  private static final String MID_A_TPL =
      getFeatureTpl("mid_a", new String[] { "bottom" });
  private static final String MID_B_TPL = 
      getFeatureTpl("mid_b", new String[] { "bottom" });
  private static final String BOTTOM_TPL = 
      getFeatureTpl("bottom", new String[] {});
  private static final String LOOP_A_TPL = 
      getFeatureTpl("loop_a", new String[] { "loop_b" });
  private static final String LOOP_B_TPL =
      getFeatureTpl("loop_b", new String[] { "loop_c" });
  private static final String LOOP_C_TPL =
      getFeatureTpl("loop_c", new String[] { "loop_a" });
  private static final String BAD_DEP_TPL =
      getFeatureTpl("bad_dep", new String[] { "no-exists" });
  
  private static String RESOURCE_BASE_PATH = "/resource/base/path";
  private static int resourceIdx = 0;
  private FeatureRegistry registry;
  private FeatureResourceLoader resourceLoader;
  private ResourceMock resourceMock;
  
  @Before
  public void setUp() {
    resourceMock = new ResourceMock();
    resourceLoader = new FeatureResourceLoader() {
      @Override
      protected String getResourceContent(String resource) {
        try {
          return resourceMock.get(resource);
        } catch (IOException e) {
          return null;
        }
      }
    };
    registry = new FeatureRegistry(resourceLoader) {
      @Override
      String getResourceContent(String resource) throws IOException {
        return resourceMock.get(resource);
      }
    };
  }
  
  @Test
  public void registerFromFileFeatureXmlFileScheme() throws Exception {
    checkRegisterFromFileFeatureXml(true);
  }
  
  @Test
  public void registerFromFileFeatureXmlNoScheme() throws Exception {
    checkRegisterFromFileFeatureXml(false);
  }
  
  private void checkRegisterFromFileFeatureXml(boolean withScheme) throws Exception {
    String content = "content-" + (withScheme ? "withScheme" : "noScheme");
    Uri resUri = makeFile(content);
    Uri featureFile = makeFile(xml(NODEP_TPL, "gadget",
        withScheme ? resUri.toString() : resUri.getPath(), null));
    registry.register(withScheme ? featureFile.toString() : featureFile.getPath());
    
    // Verify single resource works all the way through.
    List<FeatureResource> resources = registry.getAllFeatures();
    assertEquals(1, resources.size());
    assertEquals(content, resources.get(0).getContent());
  }
  
  @Test
  public void registerFromFileInNestedDirectoryFeatureXmlFile() throws Exception {
    // Get the directory from dummyUri and create a subdir.
    File tmpFile = File.createTempFile("dummy", ".dat");
    tmpFile.deleteOnExit();
    File parentDir = tmpFile.getParentFile();
    String childDirName = "" + Math.random();
    File childDir = new File(parentDir, childDirName);
    childDir.mkdirs();
    childDir.deleteOnExit();
    File featureDir = new File(childDir, "thefeature");
    featureDir.mkdirs();
    featureDir.deleteOnExit();
    File resFile = File.createTempFile("content", ".js", featureDir);
    resFile.deleteOnExit();
    String content = "content-foo";
    BufferedWriter out = new BufferedWriter(new FileWriter(resFile));
    out.write(content);
    out.close();
    File featureFile = File.createTempFile("feature", ".xml", featureDir);
    featureFile.deleteOnExit();
    out = new BufferedWriter(new FileWriter(featureFile));
    out.write(xml(NODEP_TPL, "gadget", resFile.getAbsolutePath(), null));
    out.close();
    registry.register(childDir.getAbsolutePath());
    
    // Verify single resource works all the way through.
    List<FeatureResource> resources = registry.getAllFeatures();
    assertEquals(1, resources.size());
    assertEquals(content, resources.get(0).getContent());
  }
  
  @Test
  public void registerFromResourceFeatureXml() throws Exception {
    String content = "resource-content()";
    Uri contentUri = expectResource(content);
    Uri featureUri = expectResource(xml(NODEP_TPL, "gadget", contentUri.getPath(), null));
    registry.addDefaultFeatures(featureUri.toString());
    
    // Verify single resource works all the way through.
    List<FeatureResource> resources = registry.getAllFeatures();
    assertEquals(1, resources.size());
    assertEquals(content, resources.get(0).getContent());
  }
  
  @Test
  public void registerFromResourceFeatureXmlRelativeContent() throws Exception {
    String content = "resource-content-relative()";
    Uri contentUri = expectResource(content);
    String relativePath = contentUri.getPath().substring(contentUri.getPath().lastIndexOf('/') + 1);
    Uri featureUri = expectResource(xml(NODEP_TPL, "gadget", relativePath, null));
    registry.register(featureUri.toString());
    
    // Verify single resource works all the way through.
    List<FeatureResource> resources = registry.getAllFeatures();
    assertEquals(1, resources.size());
    assertEquals(content, resources.get(0).getContent());
  }
  
  @Test
  public void registerFromResourceIndex() throws Exception {
    // One with extern resource loaded content...
    String content1 = "content1()";
    Uri content1Uri = expectResource(content1);
    Uri feature1Uri = expectResource(xml(MID_A_TPL, "gadget", content1Uri.getPath(), null));

    // One feature with inline content (that it depends on)...
    String content2 = "inline()";
    Uri feature2Uri = expectResource(xml(BOTTOM_TPL, "gadget", null, content2));
    
    // .txt file to join the two
    Uri txtFile = expectResource(feature1Uri.toString() + "\n" + feature2Uri.toString(), ".txt");
    
    // Load resources from the text file and do basic validation they're good.
    registry.register(txtFile.toString());
    
    // Contents should be ordered based on the way they went in.
    List<FeatureResource> resources = registry.getAllFeatures();
    assertEquals(2, resources.size());
    assertEquals(content2, resources.get(0).getContent());
    assertEquals(content1, resources.get(1).getContent());
  }
  
  @Test
  public void registerOverrideFeature() throws Exception {
    // Feature 1
    String content1 = "content1()";
    Uri content1Uri = expectResource(content1);
    Uri feature1Uri = expectResource(xml(BOTTOM_TPL, "gadget", content1Uri.getPath(), null));
    
    String content2 = "content_two()";
    Uri content2Uri = expectResource(content2);
    Uri feature2Uri = expectResource(xml(BOTTOM_TPL, "gadget", content2Uri.getPath(), null));
    
    registry.register(feature1Uri.toString());
    
    // Register it again, different def.
    registry.register(feature2Uri.toString());
    List<FeatureResource> resources2 = registry.getAllFeatures();
    assertEquals(1, resources2.size());
    assertEquals(content2, resources2.get(0).getContent());
    
    // Check cached resources too.
    List<FeatureResource> resourcesAgain = registry.getAllFeatures();
    assertSame(resources2, resourcesAgain);
  }
  
  @Test
  public void missingIndexResultsInException() throws Exception {
    try {
      registry.register(makeResourceUri(".txt").toString());
      fail("Should have thrown an exception for missing .txt file");
    } catch (GadgetException e) {
      // Expected. Verify code.
      assertEquals(GadgetException.Code.INVALID_PATH, e.getCode());
    }
  }
  
  @Test
  public void missingFileResultsInException() throws Exception {
    try {
      registry.register(new UriBuilder().setScheme("file")
          .setPath("/is/not/there.foo.xml").toUri().toString());
      fail("Should have thrown missing .xml file exception");
    } catch (GadgetException e) {
      // Expected. Verify code.
      assertEquals(GadgetException.Code.INVALID_CONFIG, e.getCode());
    }
  }
  
  @Test
  public void selectExactFeatureResourcesGadget() throws Exception {
    checkExactFeatureResources("gadget", RenderingContext.GADGET);
  }
  
  @Test
  public void selectExactFeatureResourcesContainer() throws Exception {
    checkExactFeatureResources("container", RenderingContext.CONTAINER);
  }
  
  private void checkExactFeatureResources(String type, RenderingContext rctx) throws Exception {
    setupFullRegistry(type, null);
    GadgetContext ctx = getCtx(rctx, null);
    List<String> needed = Lists.newArrayList("nodep", "bottom");
    List<String> unsupported = Lists.newLinkedList();
    List<FeatureResource> resources = registry.getFeatureResources(ctx, needed, unsupported);
    assertEquals(0, unsupported.size());
    assertEquals(2, resources.size());
    assertEquals("nodep", resources.get(0).getContent());
    assertEquals("bottom", resources.get(1).getContent());
  }
  
  @Test
  public void selectNoContentValidFeatureResourcesGadget() throws Exception {
    checkNoContentValidFeatureResources("gadget", RenderingContext.CONTAINER);
  }
  
  @Test
  public void selectNoContentValidFeatureResourcesContainer() throws Exception {
    checkNoContentValidFeatureResources("container", RenderingContext.GADGET);
  }
  
  private void checkNoContentValidFeatureResources(
      String type, RenderingContext rctx) throws Exception {
    setupFullRegistry(type, null);
    GadgetContext ctx = getCtx(rctx, null);
    List<String> needed = Lists.newArrayList("nodep", "bottom");
    List<String> unsupported = Lists.newLinkedList();
    List<FeatureResource> resources = registry.getFeatureResources(ctx, needed, unsupported);
    assertEquals(0, resources.size());
  }
  
  @Test
  public void testTransitiveFeatureResourcesGadget() throws Exception {
    checkTransitiveFeatureResources("gadget", RenderingContext.GADGET);
  }
  
  @Test
  public void testTransitiveFeatureResourcesContainer() throws Exception {
    checkTransitiveFeatureResources("container", RenderingContext.CONTAINER);
  }
  
  private void checkTransitiveFeatureResources(String type, RenderingContext rctx)
      throws Exception {
    setupFullRegistry(type, null);
    GadgetContext ctx = getCtx(rctx, null);
    List<String> needed = Lists.newArrayList("top", "nodep");
    List<String> unsupported = Lists.newLinkedList();
    
    // Should come back in insertable order (from bottom of the graph up),
    // querying in feature.xml dependency order.
    List<FeatureResource> resources = registry.getFeatureResources(ctx, needed, unsupported);
    assertEquals(5, resources.size());
    assertEquals("bottom", resources.get(0).getContent());
    assertEquals("mid_a", resources.get(1).getContent());
    assertEquals("mid_b", resources.get(2).getContent());
    assertEquals("top", resources.get(3).getContent());
    assertEquals("nodep", resources.get(4).getContent());
  }
  
  @Test
  public void unsupportedFeaturesPopulated() throws Exception {
    // Test only for gadget case; above tests are sufficient to ensure
    // that type and RenderingContext filter results properly.
    setupFullRegistry("gadget", null);
    GadgetContext ctx = getCtx(RenderingContext.GADGET, null);
    List<String> needed = Lists.newArrayList("nodep", "does-not-exist");
    List<String> unsupported = Lists.newLinkedList();
    List<FeatureResource> resources = registry.getFeatureResources(ctx, needed, unsupported);
    assertEquals(1, resources.size());
    assertEquals("nodep", resources.get(0).getContent());
    assertEquals(1, unsupported.size());
    assertEquals("does-not-exist", unsupported.get(0));
  }
  
  @Test
  public void filterFeaturesByContainerMatch() throws Exception {
    // Again test only for gadget case; above tests cover type <-> RenderingContext
    setupFullRegistry("gadget", "one, two , three");
    GadgetContext ctx = getCtx(RenderingContext.GADGET, "two");
    List<String> needed = Lists.newArrayList("nodep", "bottom");
    List<String> unsupported = Lists.newLinkedList();
    List<FeatureResource> resources = registry.getFeatureResources(ctx, needed, unsupported);
    assertEquals(2, resources.size());
    assertEquals("nodep", resources.get(0).getContent());
    assertEquals("bottom", resources.get(1).getContent());
    assertEquals(0, unsupported.size());
  }
  
  @Test
  public void filterFeaturesByContainerNoMatch() throws Exception {
    // Again test only for gadget case; above tests cover type <-> RenderingContext
    setupFullRegistry("gadget", "one, two, three");
    GadgetContext ctx = getCtx(RenderingContext.GADGET, "four");
    List<String> needed = Lists.newArrayList("nodep", "bottom");
    List<String> unsupported = Lists.newLinkedList();
    List<FeatureResource> resources = registry.getFeatureResources(ctx, needed, unsupported);
    assertEquals(0, resources.size());  // no resource matches but all feature keys valid
    assertEquals(0, unsupported.size());
  }
  
  @Test
  public void getFeatureResourcesNoTransitiveSingle() throws Exception {
    setupFullRegistry("gadget", null);
    GadgetContext ctx = getCtx(RenderingContext.GADGET, null);
    List<String> needed = Lists.newArrayList("top", "bottom");
    List<String> unsupported = Lists.<String>newLinkedList();
    List<FeatureResource> resources = registry.getFeatureResources(ctx, needed, unsupported, false);
    // Should return in order requested.
    assertEquals(2, resources.size());
    assertEquals("top", resources.get(0).getContent());
    assertEquals("bottom", resources.get(1).getContent());
    assertEquals(0, unsupported.size());
  }
  
  @Test
  public void getAllFeatures() throws Exception {
    setupFullRegistry("gadget", null);
    List<FeatureResource> resources = registry.getAllFeatures();
    
    // No guaranteed order (top/mid/bottom bundle may be before nodep)
    // Just check that there are 5 resources around and let the above tests
    // handle transitivity checks.
    assertEquals(5, resources.size());
  }
  
  @Test
  public void getFeaturesStringsNoTransitive() throws Exception {
    setupFullRegistry("gadget", null);
    List<String> needed = Lists.newArrayList("nodep", "bottom");
    List<String> featureNames = registry.getFeatures(needed);
    assertEquals(2, featureNames.size());
    assertEquals("nodep", featureNames.get(0));
    assertEquals("bottom", featureNames.get(1));
  }
  
  @Test
  public void getFeaturesStringsTransitive() throws Exception {
    setupFullRegistry("gadget", null);
    List<String> needed = Lists.newArrayList("top", "nodep");
    List<String> featureNames = registry.getFeatures(needed);
    assertEquals(5, featureNames.size());
    assertEquals("bottom", featureNames.get(0));
    assertEquals("mid_a", featureNames.get(1));
    assertEquals("mid_b", featureNames.get(2));
    assertEquals("top", featureNames.get(3));
    assertEquals("nodep", featureNames.get(4));
  }
  
  @Test
  public void loopIsDetectedAndCrashes() throws Exception {
    // Set up a registry with features loop_a,b,c. C points back to A, which should
    // cause an exception to be thrown by the register method.
    String type = "gadget";
    Uri loopAUri = expectResource(xml(LOOP_A_TPL, type, null, "loop_a"));
    Uri loopBUri = expectResource(xml(LOOP_B_TPL, type, null, "loop_b"));
    Uri loopCUri = expectResource(xml(LOOP_C_TPL, type, null, "loop_c"));
    Uri txtFile = expectResource(loopAUri.toString() + "\n" + loopBUri.toString() + "\n" +
        loopCUri.toString(), ".txt");
    try {
      registry.register(txtFile.toString());
      fail("Should have thrown a loop-detected exception");
    } catch (GadgetException e) {
      assertEquals(GadgetException.Code.INVALID_CONFIG, e.getCode());
    }
  }
  
  @Test
  public void unavailableFeatureCrashes() throws Exception {
    Uri featUri = expectResource(xml(BAD_DEP_TPL, "gadget", null, "content"));
    try {
      registry.register(featUri.toString());
    } catch (GadgetException e) {
      assertEquals(GadgetException.Code.INVALID_CONFIG, e.getCode());
    }
  }
  
  private GadgetContext getCtx(final RenderingContext rctx, final String container) {
    return new GadgetContext() {
      @Override
      public RenderingContext getRenderingContext() {
        return rctx;
      }
      
      @Override
      public String getContainer() {
        return container != null ? container : ContainerConfig.DEFAULT_CONTAINER;
      }
    };
  }
  
  private void setupFullRegistry(String type, String containers) throws Exception {
    // Sets up a "full" gadget feature registry with several features registered:
    // nodep - has no deps on anything else
    // top - depends on mid_a and mid_b
    // mid_a and mid_b - both depend on bottom
    // bottom - depends on nothing else
    // The content registered for each is equal to the feature's name, for simplicity.
    // Also, all content is loaded as inline, also for simplicity.
    
    Map<String, String> attribs = Maps.newHashMap();
    if (containers != null) {
      attribs.put("container", containers);
    }
    
    Uri nodepUri = expectResource(xml(NODEP_TPL, type, null, "nodep", attribs));
    Uri topUri = expectResource(xml(TOP_TPL, type, null, "top", attribs));
    Uri midAUri = expectResource(xml(MID_A_TPL, type, null, "mid_a", attribs));
    Uri midBUri = expectResource(xml(MID_B_TPL, type, null, "mid_b", attribs));
    Uri bottomUri = expectResource(xml(BOTTOM_TPL, type, null, "bottom", attribs));
    Uri txtFile = expectResource(nodepUri.toString() + "\n" + topUri.toString() + "\n" +
        midAUri.toString() + "\n" + midBUri.toString() + "\n" + bottomUri.toString(), ".txt");
    registry.register(txtFile.toString());
  }
  
  private Uri expectResource(String content) {
    return expectResource(content, ".xml");
  }
  
  private Uri expectResource(String content, String suffix) {
    Uri res = makeResourceUri(suffix);
    resourceMock.put(res.getPath(), content);
    return res;
  }
  
  private static String getFeatureTpl(String name, String[] deps) {
    StringBuilder sb = new StringBuilder();
    sb.append("<feature><name>").append(name).append("</name>");
    for (String dep : deps) {
      sb.append("<dependency>").append(dep).append("</dependency>");
    }
    sb.append("<%type% %type_attribs%><script %uri%>%content%</script></%type%>");
    sb.append("</feature>");
    return sb.toString();
  }
  
  private static String xml(String tpl, String type, String uri, String content) {
    return xml(tpl, type, uri, content, Maps.<String, String>newHashMap());
  }
  
  private static String xml(String tpl, String type, String uri, String content,
      Map<String, String> attribs) {
    StringBuilder sb = new StringBuilder();
    for (Map.Entry<String, String> entry : attribs.entrySet()) {
      sb.append(entry.getKey()).append("=\"").append(entry.getValue()).append("\" ");
    }
    return tpl.replaceAll("%type%", type)
        .replaceAll("%uri%", uri != null ? "src=\"" + uri + "\"" : "")
        .replaceAll("%content%", content != null ? content : "")
        .replaceAll("%type_attribs%", sb.toString());
  }
  
  private static Uri makeFile(String content) throws Exception {
    // .xml suffix used even for js -- should be OK per FeatureResourceLoader tests
    // which simply indicate not to attempt .opt.js loading in this case.
    File file = File.createTempFile("feat", ".xml");
    file.deleteOnExit();
    BufferedWriter out = new BufferedWriter(new FileWriter(file));
    out.write(content);
    out.close();
    return new UriBuilder().setScheme("file").setPath(file.getPath()).toUri();
  }
  
  private static Uri makeResourceUri(String suffix) {
    return Uri.parse("res://" + RESOURCE_BASE_PATH + "/file" + (++resourceIdx) + suffix);
  }
  
  private static class ResourceMock {
    private final Map<String, String> resourceMap;
    
    private ResourceMock() {
      this.resourceMap = Maps.newHashMap();
    }
    
    private void put(String key, String value) {
      resourceMap.put(clean(key), value);
    }
    
    private String get(String key) throws IOException {
      key = clean(key);
      if (!resourceMap.containsKey(key)) {
        throw new IOException("Missing resource: " + key);
      }
      return resourceMap.get(key); 
    }
    
    private String clean(String key) {
      // Resource loading doesn't support leading '/'
      return key.startsWith("/") ? key.substring(1) : key;
    }
  }
}