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
package org.apache.shindig.gadgets.rewrite;

import org.apache.commons.lang.StringUtils;
import org.apache.shindig.common.JsonSerializer;
import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.common.util.ResourceLoader;
import org.apache.shindig.common.xml.DomUtil;
import org.apache.shindig.common.xml.XmlException;
import org.apache.shindig.common.xml.XmlUtil;
import org.apache.shindig.config.ContainerConfig;
import org.apache.shindig.expressions.Expressions;
import org.apache.shindig.gadgets.Gadget;
import org.apache.shindig.gadgets.GadgetContext;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.MessageBundleFactory;
import org.apache.shindig.gadgets.render.SanitizingGadgetRewriter;
import org.apache.shindig.gadgets.spec.Feature;
import org.apache.shindig.gadgets.spec.MessageBundle;
import org.apache.shindig.gadgets.templates.CompositeTagRegistry;
import org.apache.shindig.gadgets.templates.DefaultTagRegistry;
import org.apache.shindig.gadgets.templates.MessageELResolver;
import org.apache.shindig.gadgets.templates.NullTemplateLibrary;
import org.apache.shindig.gadgets.templates.TagHandler;
import org.apache.shindig.gadgets.templates.TagRegistry;
import org.apache.shindig.gadgets.templates.TemplateBasedTagHandler;
import org.apache.shindig.gadgets.templates.TemplateContext;
import org.apache.shindig.gadgets.templates.TemplateLibrary;
import org.apache.shindig.gadgets.templates.TemplateLibraryFactory;
import org.apache.shindig.gadgets.templates.TemplateParserException;
import org.apache.shindig.gadgets.templates.TemplateProcessor;
import org.apache.shindig.gadgets.templates.TemplateResource;
import org.apache.shindig.gadgets.templates.XmlTemplateLibrary;
import org.w3c.dom.DocumentFragment;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.google.common.base.Function;
import com.google.common.base.Predicate;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.MapMaker;
import com.google.inject.Inject;
import com.google.inject.Provider;

/**
 * This ContentRewriter uses a TemplateProcessor to replace os-template
 * tag contents of a gadget spec with their rendered equivalents.
 *
 * Only templates without the @name and @tag attributes are processed
 * automatically.
 */
public class TemplateRewriter implements GadgetRewriter {

  public final static Set<String> TAGS = ImmutableSet.of("script");

  /** Set to true to block auto-processing of templates */
  static final Object DISABLE_AUTO_PROCESSING_PARAM = "disableAutoProcessing";
  
  /** Specifies what template libraries to load */
  static final Object REQUIRE_LIBRARY_PARAM = "requireLibrary";

  static private final Logger logger = Logger.getLogger(TemplateRewriter.class.getName());
  
  /**
   * Provider of the processor.  TemplateRewriters are stateless and multithreaded,
   * processors are not.
   */
  private final Provider<TemplateProcessor> processor;
  private final MessageBundleFactory messageBundleFactory;
  private final Expressions expressions;
  private final TagRegistry baseTagRegistry;
  private final TemplateLibraryFactory libraryFactory;
  private final ContainerConfig config;
  
  private final ConcurrentMap<String, TemplateLibrary> osmlLibraryCache = 
    new MapMaker().makeComputingMap(
        new Function<String, TemplateLibrary>() {
          public TemplateLibrary apply(String resourceName) {
            return loadTrustedLibrary(resourceName);
          }
        });

  @Inject
  public TemplateRewriter(Provider<TemplateProcessor> processor,
      MessageBundleFactory messageBundleFactory, Expressions expressions, 
      TagRegistry baseTagRegistry, TemplateLibraryFactory libraryFactory,
      ContainerConfig config) {
    this.processor = processor;
    this.messageBundleFactory = messageBundleFactory;
    this.expressions = expressions;
    this.baseTagRegistry = baseTagRegistry;
    this.libraryFactory = libraryFactory;
    this.config = config;
  }

  private TemplateLibrary getOsmlLibrary(Gadget gadget) {
    String library = config.getString(gadget.getContext().getContainer(),
        "${Cur['gadgets.features'].osml.library}");
    if (StringUtils.isEmpty(library)) {
      return NullTemplateLibrary.INSTANCE;
    }
    
    return osmlLibraryCache.get(library);
  }
  
  static private TemplateLibrary loadTrustedLibrary(String resource) {
    try {
      String content = ResourceLoader.getContent(resource);
      return new XmlTemplateLibrary(Uri.parse("#OSML"), XmlUtil.parse(content), 
          content, true);
    } catch (IOException ioe) {
      logger.log(Level.WARNING, null, ioe);
    } catch (XmlException xe) {
      logger.log(Level.WARNING, null, xe);
    } catch (GadgetException tpe) {
      logger.log(Level.WARNING, null, tpe);
    }

    return NullTemplateLibrary.INSTANCE;
  }
  
  public void rewrite(Gadget gadget, MutableContent content) {
    Feature f = gadget.getSpec().getModulePrefs().getFeatures()
        .get("opensocial-templates");
    if (f != null && isServerTemplatingEnabled(f)) {
      try {
        rewriteImpl(gadget, f, content);
      } catch (GadgetException ge) {
        // TODO: Rewriter interface needs to be modified to handle GadgetException or
        // RewriterException or something along those lines.
        throw new RuntimeException(ge);
      }
    }
  }

  /**
   * Disable server-side templating when the feature contains:
   * <pre>
   *   &lt;Param name="disableAutoProcessing"&gt;true&lt;/Param&gt;
   * </pre>
   */
  private boolean isServerTemplatingEnabled(Feature f) {
    return (!"true".equalsIgnoreCase(f.getParams().get(DISABLE_AUTO_PROCESSING_PARAM)));
  }

  private void rewriteImpl(Gadget gadget, Feature f, MutableContent content)
      throws GadgetException {   
    List<TagRegistry> registries = Lists.newArrayList();
    List<TemplateLibrary> libraries = Lists.newArrayList();
   
    // TODO: Add View-specific library as Priority 0
    
    // Built-in Java-based tags - Priority 1
    registries.add(baseTagRegistry);
    
    TemplateLibrary osmlLibrary = getOsmlLibrary(gadget);
    // OSML Built-in tags - Priority 2
    registries.add(osmlLibrary.getTagRegistry());
    libraries.add(osmlLibrary);

    List<Element> templates = ImmutableList.copyOf(
        Iterables.filter(
            DomUtil.getElementsByTagNameCaseInsensitive(content.getDocument(), TAGS),
            new Predicate<Element>() {
              public boolean apply(Element element) {
                return "text/os-template".equals(element.getAttribute("type"));
              }
            }));
    
    // User-defined custom tags - Priority 3
    registries.add(registerCustomTags(templates));
    
    // User-defined libraries - Priority 4
    loadTemplateLibraries(gadget.getContext(), f, registries, libraries);
    
    TagRegistry registry = new CompositeTagRegistry(registries);
    
    TemplateContext templateContext = new TemplateContext(gadget, content.getPipelinedData());    
    boolean needsFeature = executeTemplates(templateContext, content, templates, registry);

    Element head = (Element) DomUtil.getFirstNamedChildNode(
        content.getDocument().getDocumentElement(), "head");
    postProcess(templateContext, needsFeature, head, templates, libraries);
  }

  /**
   * Post-processes the gadget content after rendering templates.
   * 
   * @param templateContext TemplateContext to operate on
   * @param needsFeature Should the templates feature be made available to 
   * client?
   * @param head Head element of the gadget's document
   * @param libraries Keeps track of all libraries, and which got used
   * @param allTemplates A list of all the template nodes
   * @param libraries A list of all registered libraries
   */
  private void postProcess(TemplateContext templateContext, boolean needsFeature, Element head,
      List<Element> allTemplates, List<TemplateLibrary> libraries) {
    // Inject all the needed library assets.
    // TODO: inject library assets that aren't used on the server, but will
    // be needed on the client
    for (TemplateResource resource : templateContext.getResources()) {
      injectTemplateLibraryAssets(resource, head);
    }

    // If we don't need the feature, remove it and all templates from the gadget
    if (!needsFeature) {
      templateContext.getGadget().removeFeature("opensocial-templates");
      for (Element template : allTemplates) {
        Node parent = template.getParentNode();
        if (parent != null) {
          parent.removeChild(template);
        }
      }
    } else {
      // If the feature is to be kept, inject the libraries.
      // Library assets will be generated on the client.
      // TODO: only inject the templates, not the full scripts/styles
      for (TemplateLibrary library : libraries) {
        injectTemplateLibrary(library, head);
      }
    }
  }

  private void loadTemplateLibraries(GadgetContext context,
      Feature f, List<TagRegistry> registries, List<TemplateLibrary> libraries)  throws GadgetException {
    // TODO: Support multiple values when Shindig does
    String url = f.getParams().get(REQUIRE_LIBRARY_PARAM);
    if (url != null) {
      Uri uri = Uri.parse(url.trim());
      uri = context.getUrl().resolve(uri);
      
      try {
        TemplateLibrary library = libraryFactory.loadTemplateLibrary(context, uri);
        registries.add(library.getTagRegistry());
        libraries.add(library);
      } catch (TemplateParserException te) {
        // Suppress exceptions due to malformed template libraries
        logger.log(Level.WARNING, null, te);
      }
    }
  }
  
  private void injectTemplateLibraryAssets(TemplateResource resource, Element head) {
    Element contentElement;
    switch (resource.getType()) {
      case JAVASCRIPT:
        contentElement = head.getOwnerDocument().createElement("script");
        contentElement.setAttribute("type", "text/javascript");
        break;
      case STYLE:
        contentElement = head.getOwnerDocument().createElement("style");
        contentElement.setAttribute("type", "text/css");
        break;
      default:
        throw new IllegalStateException("Unhandled type");  
    }

    if (resource.isSafe()) {
      SanitizingGadgetRewriter.bypassSanitization(contentElement, false);
    }
    contentElement.setTextContent(resource.getContent());
    head.appendChild(contentElement);    
  }
  
  private void injectTemplateLibrary(TemplateLibrary library, Element head) {
    try {
      String libraryContent = library.serialize();
      if (StringUtils.isEmpty(libraryContent)) {
        return;
      }
      
      Element scriptElement = head.getOwnerDocument().createElement("script");
      scriptElement.setAttribute("type", "text/javascript");
      StringBuilder buffer = new StringBuilder();
      buffer.append("opensocial.template.Loader.loadContent(");
      JsonSerializer.appendString(buffer, library.serialize());
      buffer.append(",");
      JsonSerializer.appendString(buffer, library.getLibraryUri().toString());
      buffer.append(");");       
      scriptElement.setTextContent(buffer.toString());
      head.appendChild(scriptElement);
    } catch (IOException ioe) {
      // This should never happen.
    }
  }
  
  /**
   * Register templates with a "tag" attribute.
   */
  private TagRegistry registerCustomTags(List<Element> allTemplates) {
    ImmutableSet.Builder<TagHandler> handlers = ImmutableSet.builder();
    for (Element template : allTemplates) {
      // Only process templates with a tag attribute
      if (template.getAttribute("tag").length() == 0) {
        continue;
      }
      
      // TODO: split() is a regex compile, and should be avoided
      String [] nameParts = template.getAttribute("tag").split(":");
      // At this time, we only support 
      if (nameParts.length != 2) {
        continue;
      }
      String namespaceUri = template.lookupNamespaceURI(nameParts[0]);      
      if (namespaceUri != null) {
        handlers.add(new TemplateBasedTagHandler(template, namespaceUri, nameParts[1]));
      }
    }
    
    return new DefaultTagRegistry(handlers.build());
  }
  
  /**
   * Processes and renders inline templates.
   * @return Do we think the templates feature is still needed on the client?
   */
  private boolean executeTemplates(TemplateContext templateContext, MutableContent content,
      List<Element> allTemplates, TagRegistry registry) throws GadgetException {
    Map<String, Object> pipelinedData = content.getPipelinedData();

    // If true, client-side processing will be needed
    boolean needsFeature = false;
    List<Element> templates = Lists.newArrayList();
    for (Element element : allTemplates) {
      String name = element.getAttribute("name");
      String tag = element.getAttribute("tag");
      String require = element.getAttribute("require");

      if (!"".equals(name) ||
          !checkRequiredData(require, pipelinedData.keySet())) {
        // Can't be processed on the server at all;  keep client-side processing
        needsFeature = true;
      } else if ("".equals(tag)) {
        templates.add(element);
      }
    }
    
    if (!templates.isEmpty()) {
      Gadget gadget = templateContext.getGadget();
      
      MessageBundle bundle = messageBundleFactory.getBundle(gadget.getSpec(),
          gadget.getContext().getLocale(), gadget.getContext().getIgnoreCache());
      MessageELResolver messageELResolver = new MessageELResolver(expressions, bundle);
  
      for (Element template : templates) {
        DocumentFragment result = processor.get().processTemplate(
            template, templateContext, messageELResolver, registry);
        template.getParentNode().insertBefore(result, template);
        // TODO: sanitized renders should ignore this value
        if ("true".equals(template.getAttribute("autoUpdate"))) {
          // autoUpdate requires client-side processing.
          // TODO: give client-side processing some hope of finding the pre-rendered content
          needsFeature = true;
        } else {
          template.getParentNode().removeChild(template);
        }
      } 
      MutableContent.notifyEdit(content.getDocument());
    } 
    return needsFeature;
  }
  
  /**
   * Checks that all the required data is available at rewriting time.
   * @param requiredData A string of comma-separated data set names
   * @param availableData A map of available data sets
   * @return true if all required data sets are present, false otherwise
   */
  private static boolean checkRequiredData(String requiredData, Set<String> availableData) {
    if ("".equals(requiredData)) {
      return true;
    }
    StringTokenizer st = new StringTokenizer(requiredData, ",");
    while (st.hasMoreTokens()) {
      if (!availableData.contains(st.nextToken().trim())) {
        return false;
      }
    }
    return true;
  }
}
