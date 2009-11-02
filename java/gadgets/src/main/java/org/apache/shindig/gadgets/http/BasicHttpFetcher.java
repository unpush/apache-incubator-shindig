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
package org.apache.shindig.gadgets.http;

import com.google.inject.internal.Preconditions;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.DeleteMethod;
import org.apache.commons.httpclient.methods.EntityEnclosingMethod;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.HeadMethod;
import org.apache.commons.httpclient.methods.InputStreamRequestEntity;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.PutMethod;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.io.output.ByteArrayOutputStream;

import com.google.common.collect.Maps;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import com.google.inject.name.Named;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 * A very primitive HTTP fetcher implementation. Not recommended for production deployments until
 * the following issues are addressed:
 *
 * 1. This class potentially allows access to resources behind an organization's firewall.
 * 2. This class does not handle most advanced HTTP functionality correctly (SSL, etc.)
 * 3. This class does not enforce any limits on what is fetched from remote hosts.
 */
@Singleton
public class BasicHttpFetcher implements HttpFetcher {
  private static final int DEFAULT_CONNECT_TIMEOUT_MS = 5000;
  private static final int DEFAULT_MAX_OBJECT_SIZE = 0;  // no limit
  private static final int DEFAULT_BUFFER_SIZE = 1024 * 4;

  // mutable fields must be volatile
  private volatile int maxObjSize; 
  private volatile int connectionTimeoutMs;

  /**
   * Creates a new fetcher for fetching HTTP objects.  Not really suitable
   * for production use. Use of an HTTP proxy for security is also necessary
   * for production deployment.
   *
   * @param maxObjSize Maximum size, in bytes, of the object we will fetch, 0 if no limit..
   * @param connectionTimeoutMs timeout, in milliseconds, for requests.
   */
  public BasicHttpFetcher(int maxObjSize, int connectionTimeoutMs) {
    setMaxObjectSizeBytes(maxObjSize);
	  setConnectionTimeoutMs(connectionTimeoutMs);
  }

  /**
   * Creates a new fetcher using the default maximum object size and timeout --
   * no limit and 5 seconds.
   */
  public BasicHttpFetcher() {
    this(DEFAULT_MAX_OBJECT_SIZE, DEFAULT_CONNECT_TIMEOUT_MS);
  }

  /**
   * Change the global maximum fetch size (in bytes) for all fetches. 
   *
   * @param maxObjectSizeBytes value for maximum number of bytes, or 0 for no limit
   */
  @Inject(optional = true)
  public void setMaxObjectSizeBytes(@Named("shindig.http.client.max-object-size-bytes") int maxObjectSizeBytes) {
    this.maxObjSize = maxObjectSizeBytes;
  }

  /**
   * Change the global connection timeout for all fetchs.
   *
   * @param connectionTimeoutMs new connection timeout in milliseconds
   */
  @Inject(optional = true)
  public void setConnectionTimeoutMs(@Named("shindig.http.client.connection-timeout-ms") int connectionTimeoutMs) {
    Preconditions.checkArgument(connectionTimeoutMs > 0, "connection-timeout-ms must be greater than 0");
    this.connectionTimeoutMs = connectionTimeoutMs;
  }

  /**
   * @param httpMethod
   * @param responseCode
   * @return A HttpResponse object made by consuming the response of the
   *     given HttpMethod.
   * @throws java.io.IOException
   */
  private HttpResponse makeResponse(HttpMethod httpMethod, int responseCode) throws IOException {
    Map<String, String> headers = Maps.newHashMap();

    if (httpMethod.getResponseHeaders() != null) {
      for (Header h : httpMethod.getResponseHeaders()) {
        headers.put(h.getName(), h.getValue());
      }
    }

    // The first header is always null here to provide the response body.
    headers.remove(null);

    // Find the response stream - the error stream may be valid in cases
    // where the input stream is not.
    InputStream responseBodyStream = null;
    try {
      responseBodyStream = httpMethod.getResponseBodyAsStream();
    } catch (IOException e) {
      // normal for 401, 403 and 404 responses, for example...
    }

    if (responseBodyStream == null) {
      // Fall back to zero length response.
      responseBodyStream = new ByteArrayInputStream(ArrayUtils.EMPTY_BYTE_ARRAY);
    }

    String encoding = headers.get("Content-Encoding");

    // Create the appropriate stream wrapper based on the encoding type.
    InputStream is = responseBodyStream;
    if (encoding == null) {
      is = responseBodyStream;
    } else if (encoding.equalsIgnoreCase("gzip")) {
      is = new GZIPInputStream(responseBodyStream);
    } else if (encoding.equalsIgnoreCase("deflate")) {
      Inflater inflater = new Inflater(true);
      is = new InflaterInputStream(responseBodyStream, inflater);
    }

    ByteArrayOutputStream output = new ByteArrayOutputStream();
    byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
    int totalBytesRead = 0;
    int currentBytesRead;

    while ((currentBytesRead = is.read(buffer)) != -1) {
      output.write(buffer, 0, currentBytesRead);
      totalBytesRead += currentBytesRead;

      if(maxObjSize > 0 && totalBytesRead > maxObjSize) {
        IOUtils.closeQuietly(is);
        IOUtils.closeQuietly(output);
        // Exceeded max # of bytes
        return HttpResponse.badrequest("Exceeded maximum number of bytes - " + this.maxObjSize);
      }
    }

    return new HttpResponseBuilder()
        .setHttpStatusCode(responseCode)
        .setResponse(output.toByteArray())
        .addHeaders(headers)
        .create();
  }

  /** {@inheritDoc} */
  public HttpResponse fetch(HttpRequest request) {
    HttpClient httpClient = new HttpClient();
    HttpMethod httpMethod;
    String methodType = request.getMethod();
    String requestUri = request.getUri().toString();

    // Select a proxy based on the URI. May be Proxy.NO_PROXY
    Proxy proxy = ProxySelector.getDefault().select(request.getUri().toJavaUri()).get(0);

    if (proxy != Proxy.NO_PROXY) {
      InetSocketAddress address = (InetSocketAddress) proxy.address();
      httpClient.getHostConfiguration().setProxy(address.getHostName(), address.getPort());
    }


    // true for non-HEAD requests
    boolean requestCompressedContent = true;

    if ("POST".equals(methodType) || "PUT".equals(methodType)) {
      EntityEnclosingMethod enclosingMethod = ("POST".equals(methodType))
              ? new PostMethod(requestUri)
              : new PutMethod(requestUri);

      if (request.getPostBodyLength() > 0) {
        enclosingMethod.setRequestEntity(new InputStreamRequestEntity(request.getPostBody()));
        enclosingMethod.setRequestHeader("Content-Length",
            String.valueOf(request.getPostBodyLength()));
      }
      httpMethod = enclosingMethod;
    } else if ("DELETE".equals(methodType)) {
      httpMethod = new DeleteMethod(requestUri);
    } else if ("HEAD".equals(methodType)) {
      httpMethod = new HeadMethod(requestUri);
    } else {
      httpMethod = new GetMethod(requestUri);
    }

    httpMethod.setFollowRedirects(false);
    httpMethod.getParams().setSoTimeout(connectionTimeoutMs);

    if (requestCompressedContent)
      httpMethod.setRequestHeader("Accept-Encoding", "gzip, deflate");

    for (Map.Entry<String, List<String>> entry : request.getHeaders().entrySet()) {
      httpMethod.setRequestHeader(entry.getKey(), StringUtils.join(entry.getValue(), ','));
    }

    try {

      int statusCode = httpClient.executeMethod(httpMethod);

      // Handle redirects manually
      if (request.getFollowRedirects() &&
          ((statusCode == HttpStatus.SC_MOVED_TEMPORARILY) ||
          (statusCode == HttpStatus.SC_MOVED_PERMANENTLY) ||
          (statusCode == HttpStatus.SC_SEE_OTHER) ||
          (statusCode == HttpStatus.SC_TEMPORARY_REDIRECT))) {

        Header header = httpMethod.getResponseHeader("location");
        if (header != null) {
            String redirectUri = header.getValue();

            if ((redirectUri == null) || (redirectUri.equals(""))) {
                redirectUri = "/";
            }
            httpMethod.releaseConnection();
            httpMethod = new GetMethod(redirectUri);

            statusCode = httpClient.executeMethod(httpMethod);
        }
      }

      return makeResponse(httpMethod, statusCode);

    } catch (IOException e) {
      if (e instanceof java.net.SocketTimeoutException ||
          e instanceof java.net.SocketException) {
        return HttpResponse.timeout();
      }

      return HttpResponse.error();

    } finally {
      httpMethod.releaseConnection();
    }
  }
}
