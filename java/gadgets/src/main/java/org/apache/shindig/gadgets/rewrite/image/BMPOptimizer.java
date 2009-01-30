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
package org.apache.shindig.gadgets.rewrite.image;

import org.apache.shindig.gadgets.http.HttpResponse;

import java.awt.image.BufferedImage;
import java.io.IOException;

import javax.imageio.ImageIO;

/**
 * Optimize BMP by converting to PNG
 */
public class BMPOptimizer extends PNGOptimizer {

  public BMPOptimizer(OptimizerConfig config, HttpResponse original)
      throws IOException {
    super(config, original);
  }

  protected void rewriteImpl(BufferedImage image) throws IOException {
    writer = ImageIO.getImageWritersByFormatName("png").next();
    super.rewriteImpl(image);
  }

  protected String getOriginalContentType() {
    return "image/bmp";
  }

  @Override
  protected String getOriginalFormatName() {
    return "bmp";
  }
}
