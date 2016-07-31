/*
 * (C) Copyright 2016 Fluenda.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package com.fluenda.parcefone.event;

import java.util.Map;

public abstract class CommonEvent {
    // Implements a " struct like"  class that implements the Common Event
    // Format v23 as described here:
    // https://www.protect724.hpe.com/servlet/JiveServlet/downloadBody/1072-102-9-20354/CommonEventFormatv23.pdf

    // Define getters and seters
    public abstract void setHeader(Map<String, Object> headers) throws CEFHandlingException;

    public abstract void setExtension(Map<String, String> extensions) throws CEFHandlingException;

    public abstract Map<String, Object> getHeader() throws CEFHandlingException;

    public abstract Map<String, Object> getExtensions(boolean populatedOnly) throws CEFHandlingException;
}
