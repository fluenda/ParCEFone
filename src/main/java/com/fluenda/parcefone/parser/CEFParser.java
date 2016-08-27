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

package com.fluenda.parcefone.parser;

import com.fluenda.parcefone.event.CEFHandlingException;
import com.fluenda.parcefone.event.CefRev23;
import com.fluenda.parcefone.event.CommonEvent;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CEFParser {
    final static Logger logger = LoggerFactory.getLogger(CEFParser.class);



    /**
     * @return CommonEvent
     * @param cefByteArray byte [] containing the CEF message to be parsed - Array will be converted String using UTF-8
     */
    public CommonEvent parse(byte [] cefByteArray)  {
        String cefString;
        cefString = new String(cefByteArray, Charset.forName("UTF-8"));
        return this.parse(cefString, false);
    }

    /**
     * @return CommonEvent
     * @param cefByteArray byte [] containing the CEF message to be parsed - Array will be converted String using UTF-8
     * @param validate Boolean if parser should validate values beyond type compatibility (e.g. Values within acceptable lengths, value lists, etc)
     */
    public CommonEvent parse(byte [] cefByteArray, boolean validate)  {
        String cefString;
        cefString = new String(cefByteArray, Charset.forName("UTF-8"));
        return this.parse(cefString, validate);
    }

    /**
     * @param cefString String containing the CEF message to be parsed
     * @return CommonEvent
     */
    public CommonEvent parse(String cefString)  {
        return this.parse(cefString, false);
    }


    /**
     * @param cefString String containing the CEF message to be parsed
     * @param validate Boolean if parser should validate values beyond type compatibility (e.g. Values within acceptable lengths, value lists, etc)
     * @return CommonEvent
     */
    public CommonEvent parse(String cefString, final boolean validate)  {

        int cefHeaderSize = 7;
        CommonEvent cefEvent = new CefRev23();

        // Note how split number of splits is cefHeaderSize + 1. This is because the final split
        // should be the body of the CEF message
        // Compiled pattern is equivalent to "(?<!\\\\)" + Pattern.quote("|")
        final String[] extractedMessage = cefString.split("(?<!\\\\)" + Pattern.quote("|"), cefHeaderSize + 1);

        // CEF header misses values
        if (extractedMessage.length < cefHeaderSize) {
            if (logger.isDebugEnabled()) {
                logger.debug("CEF message failed validation");
            }
            return null;
        }

        final HashMap<String, Object> headers = new HashMap<String, Object>();
        headers.put("version", Integer.valueOf(extractedMessage[0].substring(extractedMessage[0].length() - 1)));
        headers.put("deviceVendor", extractedMessage[1]);
        headers.put("deviceProduct", extractedMessage[2]);
        headers.put("deviceVersion", extractedMessage[3]);
        headers.put("deviceEventClassId", extractedMessage[4]);
        headers.put("name", extractedMessage[5]);
        headers.put("severity", extractedMessage[6]);

        final HashMap<String, String> extensions = new HashMap<String, String>();


        final String ext = extractedMessage[7];

        // Compiled pattern is equivalent to String extensionRegex = "(?<!\\\\)" + Pattern.quote("=");
        final Matcher matcher = Pattern.compile("(?<!\\\\)" + Pattern.quote("=")).matcher(ext);
        final Matcher valueMatcher = Pattern.compile("(?<!\\\\)" + Pattern.quote("=")).matcher(ext);
        int index = 0;

        while (matcher.find()) {
            String key = ext.substring(index, matcher.end() - 1);

            // Capture the start of the value (first char after delimiter match);
            int valueStart = matcher.end();

            // Handle all but last extension
            if (valueMatcher.find(valueStart)) {
                // FInd the next match to determine the maximum length of the value
                int nextMatch = valueMatcher.start();
                // Find the last space prior to next match (i.e. last char before next key)
                int lastSpace = ext.lastIndexOf(" ", nextMatch);

                // Copy the value between the value start (i.e. this match)
                // and the lastSpace (i.e. last char prior to next key)
                String value = ext.substring(valueStart, lastSpace);

                // Put to map.
                extensions.put(key, value);

                // Update index to the last character before the next key
                index = lastSpace + 1;

                // Treat the last KV (if match is true)
            } else if (valueMatcher.find(valueStart - 1)) {
                // We are handling the final character, value end if newline at the
                // end of string
                int valueEnd = ext.length();

                String value = ext.substring(valueStart, valueEnd);
                extensions.put(key, value);
                // Update the index to the end of the string so no matches are possible
                index = valueEnd;
            }
        }

        try {
            cefEvent.setHeader(headers);
            cefEvent.setExtension(extensions);

        } catch (CEFHandlingException e) {
            logger.error(e.toString());
            return null;
        }

        final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
        Set<ConstraintViolation<CommonEvent>> validationResult = validator.validate(cefEvent);

        if (validate && (validationResult.size() > 0)) {
            if (logger.isDebugEnabled()) {
                logger.debug("CEF message failed validation");
            }
                return null;
        } else {
            return cefEvent;
        }
    }
}

