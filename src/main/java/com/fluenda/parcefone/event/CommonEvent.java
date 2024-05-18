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

/**
 * Implements a <i>struct like</i> class that holds headers and extension fields defined in the Common Event Format
 * maintained by HP Enterprise and used by a number of cyber security solutions.
 */
public abstract class CommonEvent {
    /**
     * Default constructor for Common Events
     */
    public CommonEvent() {

    }

    /**
     * Set headers using named key to object value
     *
     * @param headers A map containing the  keys and values of headers of CEF event
     * @throws CEFHandlingException when it has issues writing the values of the headers
     */
    public abstract void setHeader(Map<String, Object> headers) throws CEFHandlingException;

    /**
     * Set extensions using named key to object value
     *
     * @param extensions A map containing the keys and values of extensions of CEF event
     * @throws CEFHandlingException when it has issues populating the extensions
     */
    public abstract void setExtension(Map<String, String> extensions) throws CEFHandlingException;

    /**
     * Set extensions using named key to object value with specified handling for null values
     *
     * @param extensions A map containing the keys and values of extensions of CEF event
     * @param allowNulls If true, extensions with an empty value will be seen as null. If false, parsing may fail depending on extension types
     * @throws CEFHandlingException when it has issues populating the extensions
     */
    public abstract void setExtension(Map<String, String> extensions, final boolean allowNulls) throws CEFHandlingException;

    /**
     * Get map of named headers
     *
     * @return A map containing the keys and values of headers
     * @throws CEFHandlingException when it has issues reading the headers of CEF event
     */
    public abstract Map<String, Object> getHeader() throws CEFHandlingException;

    /**
     * Get map of named extensions
     *
     * @param populatedOnly Boolean defining if Map should include all fields supported by the <b>supported</b> CEF standard
     * @return A map containing the keys and values of CEF extensions
     * @throws CEFHandlingException when it hits issues (e.g. IllegalAccessException) reading the extensions
     */
    public abstract Map<String, Object> getExtension(boolean populatedOnly) throws CEFHandlingException;


    /**
     * Get map of named extensions after applying specified filtering
     *
     * @param populatedOnly Boolean defining if Map should include all fields supported by {@link com.fluenda.parcefone.event.CefRev23}
     * @param includeCustomExtensions Boolean defining if Map should include parsed keys that are not supported part of the base CEF Rev23 specification
     * @return A map containing the keys and values of CEF extensions
     * @throws CEFHandlingException when it hits issues (e.g. IllegalAccessException) reading the extensions
     */
    public abstract Map<String, Object> getExtension(boolean populatedOnly, boolean includeCustomExtensions) throws CEFHandlingException;
}
