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

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A Common Event Format (CEF) parser used to convert String or byte array into a Map containing the <b>parsed and
 * validated</b> CEF fields
 * The parser does not make any assertion in regards to thread safety. Proceed with care.
 */
public class CEFParser {
    final static Logger logger = LoggerFactory.getLogger(CEFParser.class);

    final static Pattern extensionPattern = Pattern.compile("(?<!\\\\)" + Pattern.quote("="));

    Validator validator;


    /**
    *  Creates a CEFParser instance utilizing the default Bean Validator.
     */
    public CEFParser() {

    }

    /**
     *  Creates a CEFParser instance utilizing thread-safe Beans Validator. The use of this constructor should result in significantly higher
     *  throughput when performing multiple instatiations of CEFParser.
     * @param validator A JSR-303 complianceValidator such as Hibernate or Apache bVal
     */
    public CEFParser(Validator validator) {
        this.validator = validator;
    }

    /**
     * Parse byte array after converting to UTF-8 string with validation disabled
     *
     * @return CommonEvent
     * @param cefByteArray byte [] containing the CEF message to be parsed - Array will be converted String using UTF-8
     */
    public CommonEvent parse(byte [] cefByteArray)  {
        String cefString;
        cefString = new String(cefByteArray, StandardCharsets.UTF_8);
        return this.parse(cefString, false);
    }

    /**
     * Parse byte array after converting to UTF-8 string with validation enabled or disabled
     *
     * @return CommonEvent
     * @param cefByteArray byte [] containing the CEF message to be parsed - Array will be converted String using UTF-8
     * @param validate Boolean if parser should validate values beyond type compatibility (e.g. Values within acceptable lengths, value lists, etc)
     */
    public CommonEvent parse(byte [] cefByteArray, boolean validate)  {
        String cefString;
        cefString = new String(cefByteArray, StandardCharsets.UTF_8);
        return this.parse(cefString, validate);
    }

    /**
     * Parse byte array after converting to UTF-8 string using specified Locale and with validation enabled or disabled
     *
     * @return CommonEvent
     * @param cefByteArray byte [] containing the CEF message to be parsed - Array will be converted String using UTF-8
     * @param validate Boolean if parser should validate values beyond type compatibility (e.g. Values within acceptable lengths, value lists, etc)
     * @param locale The locale to be used when parsing dates (so that parser can handle both jul (en_US) and juil.(fr_FR)
     */
    public CommonEvent parse(byte [] cefByteArray, boolean validate, Locale locale)  {
        String cefString;
        cefString = new String(cefByteArray, StandardCharsets.UTF_8);
        return this.parse(cefString, validate, locale);
    }

    /**
     * Parse byte array after converting to UTF-8 string using specified Locale and with validation and allow nulsl enabled or disabled
     *
     * @return CommonEvent
     * @param cefByteArray byte [] containing the CEF message to be parsed - Array will be converted String using UTF-8
     * @param validate Boolean if parser should validate values beyond type compatibility (e.g. Values within acceptable lengths, value lists, etc)
     * @param allowNulls If true, extensions with an empty value will be seen as null. If false, parsing may fail depending on extension types
     * @param locale The locale to be used when parsing dates (so that parser can handle both jul (en_US) and juil.(fr_FR)
     */
    public CommonEvent parse(byte [] cefByteArray, boolean validate, final boolean allowNulls, Locale locale)  {
        String cefString;
        cefString = new String(cefByteArray, StandardCharsets.UTF_8);
        return this.parse(cefString, validate, allowNulls, locale);
    }


    /**
     * <p>
     * Converts a CEF formatted String into a {@link CommonEvent} object without enforcing strict validation.
     * <p>
     * The use of this method is discouraged and future versions may deprecate its use.
     * @param cefString String containing the CEF message to be parsed
     * @return CommonEvent
     */
    public CommonEvent parse(String cefString)  {
        return this.parse(cefString, false);
    }

    /**
     * <p>
     * Converts a CEF formatted String into a {@link CommonEvent} object with exposed control over strict validation.
     * <p>
     * All CEF extension fields containing Dates are processed with the {@link Locale Locale.ENGLISH}.
     * @param cefString String containing the CEF message to be parsed
     * @param validate Boolean if parser should validate values beyond type compatibility (e.g. Values within acceptable lengths, value lists, etc)
     * @return CommonEvent
     */
    public CommonEvent parse(String cefString, final boolean validate)  {
        return this.parse(cefString, validate, Locale.ENGLISH);
    }

    /**
     * Converts a CEF formatted String into a {@link CommonEvent} object with exposed control over validation and the
     * {@link Locale} used to parse fields containing {@link Date Dates}
     * @param cefString String containing the CEF message to be parsed
     * @param validate Boolean if parser should validate values beyond type compatibility (e.g. Values within acceptable lengths, value lists, etc)
     * @param locale The locale to be used when parsing dates (so that parser can handle both jul (en_US) and juil.(fr_FR)
     * @return CommonEvent
     */
    public CommonEvent parse(String cefString, final boolean validate, Locale locale)  {
        return this.parse(cefString, validate, false, locale);
    }

    /**
     * Converts a CEF formatted String into a {@link CommonEvent} object with exposed control over validation and the
     * {@link Locale} used to parse fields containing {@link Date Dates}
     * @param cefString String containing the CEF message to be parsed
     * @param validate Boolean if parser should validate values beyond type compatibility (e.g. Values within acceptable lengths, value lists, etc)
     * @param allowNulls If true, extensions with an empty value will be seen as null. If false, parsing may fail depending on extension types
     * @param locale The locale to be used when parsing dates (so that parser can handle both jul (en_US) and juil.(fr_FR)
     * @return CommonEvent
     */
    public CommonEvent parse(String cefString, final boolean validate, final boolean allowNulls, Locale locale)  {

        int cefHeaderSize = 7;
        CommonEvent cefEvent = new CefRev23(locale);

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

        final HashMap<String, Object> headers = new HashMap<>();
        headers.put("version", Integer.valueOf(extractedMessage[0].substring(extractedMessage[0].length() - 1)));
        headers.put("deviceVendor", extractedMessage[1]);
        headers.put("deviceProduct", extractedMessage[2]);
        headers.put("deviceVersion", extractedMessage[3]);
        headers.put("deviceEventClassId", extractedMessage[4]);
        headers.put("name", extractedMessage[5]);
        headers.put("severity", extractedMessage[6]);

        final HashMap<String, String> extensions = new HashMap<>();


        final String ext = extractedMessage[7];

        // Compiled pattern is equivalent to String extensionRegex = "(?<!\\\\)" + Pattern.quote("=");
        final Matcher matcher = extensionPattern.matcher(ext);
        final Matcher valueMatcher = extensionPattern.matcher(ext);

        int index = 0;

        while (matcher.find()) {
            String key = ext.substring(index, matcher.end() - 1).replace(" ", "");

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
            cefEvent.setExtension(extensions, allowNulls);

        } catch (CEFHandlingException e) {
            logger.error(e.toString());
            return null;
        }

        if (validate) {
            if (validator == null) {
                // Since the validator wasn't initiated previously, create a new one;
                this.validator = Validation.buildDefaultValidatorFactory().getValidator();
            }

            Set<ConstraintViolation<CommonEvent>> validationResult = validator.validate(cefEvent);

            if (!validationResult.isEmpty()) {
                if (logger.isDebugEnabled()) {
                    for(ConstraintViolation<CommonEvent> v : validationResult) {
                        logger.debug("CEF message failed validation: " + v.getMessage());
                    }
                }
                return null;
            } else {
                return cefEvent;
            }
        } else {
            return cefEvent;
        }
    }
}

