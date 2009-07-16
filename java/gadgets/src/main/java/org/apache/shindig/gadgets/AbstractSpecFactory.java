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
package org.apache.shindig.gadgets;

import org.apache.shindig.common.cache.Cache;
import org.apache.shindig.common.cache.SoftExpiringCache;
import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.common.xml.XmlException;
import org.apache.shindig.config.ContainerConfig;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.http.RequestPipeline;
import org.apache.shindig.gadgets.spec.SpecParserException;

import java.util.concurrent.ExecutorService;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Basis for implementing GadgetSpec and MessageBundle factories.
 *
 * Automatically updates objects as needed asynchronously to provide optimal throughput.
 */
public abstract class AbstractSpecFactory<T> {
  private static final Logger logger = Logger.getLogger(AbstractSpecFactory.class.getName());
  private final Class<T> clazz;
  private final ExecutorService executor;
  private final RequestPipeline pipeline;
  final SoftExpiringCache<Uri, Object> cache;
  private final long refresh;

  /**
   * @param clazz the class for spec objects.
   * @param executor for asynchronously updating specs
   * @param pipeline the request pipeline for fetching new specs
   * @param cache a cache for parsed spec objects
   * @param refresh the frequency at which to update specs, independent of cache expiration policy
   */
  public AbstractSpecFactory(Class<T> clazz, ExecutorService executor, RequestPipeline pipeline,
      Cache<Uri, Object> cache, long refresh) {
    this.clazz = clazz;
    this.executor = executor;
    this.pipeline = pipeline;
    this.cache = new SoftExpiringCache<Uri, Object>(cache);
    this.refresh = refresh;
  }

  /**
   * Attempt to fetch a spec, either from cache or from the network.
   *
   * Note that the {@code query} passed here will always be passed, unmodified, to
   * {@link #parse(String, Query)}. This can be used to carry additional context information
   * during parsing.
   */
  protected T getSpec(Query query) throws GadgetException {
    Object obj = null;
    if (!query.ignoreCache) {
      SoftExpiringCache.CachedObject<Object> cached = cache.getElement(query.specUri);
      if (cached != null) {
        obj = cached.obj;
        if (cached.isExpired) {
          // We write to the cache to avoid any race conditions with multiple writers.
          // This causes a double write, but that's better than a write per thread or synchronizing
          // this block.
          cache.addElement(query.specUri, obj, refresh);
          executor.execute(new SpecUpdater(query, obj));
        }
      }
    }

    if (obj == null) {
      try {
        obj = fetchFromNetwork(query);
      } catch (GadgetException e) {
        obj = e;
      }
      cache.addElement(query.specUri, obj, refresh);
    }

    if (obj instanceof GadgetException) {
      throw (GadgetException) obj;
    }

    // If there's a bug that puts the wrong object in here, we'll get a ClassCastException.
    return clazz.cast(obj);
  }

  /**
   * Retrieves a spec from the network, parses, and adds it to the cache.
   */
  protected T fetchFromNetwork(Query query) throws GadgetException {
    HttpRequest request = new HttpRequest(query.specUri)
        .setIgnoreCache(query.ignoreCache)
        .setGadget(query.gadgetUri)
        .setContainer(query.container);

    // Since we don't allow any variance in cache time, we should just force the cache time
    // globally. This ensures propagation to shared caches when this is set.
    request.setCacheTtl((int) (refresh / 1000));

    HttpResponse response = pipeline.execute(request);
    if (response.getHttpStatusCode() != HttpResponse.SC_OK) {
      throw new GadgetException(GadgetException.Code.FAILED_TO_RETRIEVE_CONTENT,
                                "Unable to retrieve spec for " + query.specUri + ". HTTP error " +
                                response.getHttpStatusCode());
    }

    try {
      String content = response.getResponseAsString();
      return parse(content, query);
    } catch (XmlException e) {
      throw new SpecParserException(e);
    }
  }

  /**
   * Parse and return a new spec object from the network.
   *
   * @param content the content located at specUri
   * @param query same as was passed {@link #getSpec(Query)}
   */
  protected abstract T parse(String content, Query query) throws XmlException, GadgetException;

  /**
   * Holds information used to fetch a spec.
   */
  protected static class Query {
    private Uri specUri = null;
    private String container = ContainerConfig.DEFAULT_CONTAINER;
    private Uri gadgetUri = null;
    private boolean ignoreCache = false;

    public Query setSpecUri(Uri specUri) {
      this.specUri = specUri;
      return this;
    }

    public Query setContainer(String container) {
      this.container = container;
      return this;
    }

    public Query setGadgetUri(Uri gadgetUri) {
      this.gadgetUri = gadgetUri;
      return this;
    }

    public Query setIgnoreCache(boolean ignoreCache) {
      this.ignoreCache = ignoreCache;
      return this;
    }

    public Uri getSpecUri() {
      return specUri;
    }

    public String getContainer() {
      return container;
    }

    public Uri getGadgetUri() {
      return gadgetUri;
    }

    public boolean getIgnoreCache() {
      return ignoreCache;
    }
  }

  private class SpecUpdater implements Runnable {
    private final Query query;
    private final Object old;

    public SpecUpdater(Query query, Object old) {
      this.query = query;
      this.old = old;
    }

    public void run() {
      try {
        T newSpec = fetchFromNetwork(query);
        cache.addElement(query.specUri, newSpec, refresh);
      } catch (GadgetException e) {
        if (old != null) {
          logger.log(Level.INFO, "Failed to update {0}. Using cached version.", query.specUri);
          cache.addElement(query.specUri, old, refresh);
        } else {
          logger.log(Level.INFO, "Failed to update {0}. Applying negative cache.", query.specUri);
          cache.addElement(query.specUri, e, refresh);
        }
      }
    }
  }
}
