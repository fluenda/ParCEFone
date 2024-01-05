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

/**
 * Common Event Format Handling Exception thrown on parsing failures
 */
public class CEFHandlingException extends Exception {
    /**
     * Default constructor with no arguments
     */
    public CEFHandlingException() {

    }

    /**
     * Standard constructor with required message
     *
     * @param message Message describing failure
     */
    public CEFHandlingException(String message) {
        super(message);
    }

    /**
     * Standard constructor with required message and cause
     *
     * @param message Message describing failure
     * @param cause Throwable cause of parsing failure
     */
    public CEFHandlingException(String message, Throwable cause) {
        super(message,cause);
    }
}
