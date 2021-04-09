/*
 * (C) Copyright 2021 Fluenda.
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

import java.util.Arrays;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Media Access Control Address based on com.martiansoftware.macnificent.MacAddress
 */
public class MacAddress implements Comparable<MacAddress> {
    private static final int ADDRESS_LENGTH = 6;

    private static final byte MUTLTICAST_FLAG = 0x01;

    private static final byte LOCAL_FLAG = 0x02;

    private static final char STANDARD_SEPARATOR = ':';

    private static final Pattern ADDRESS_PATTERN;

    static {
        final StringBuilder patternBuilder = new StringBuilder("^\\s*");
        for (int i = 1; i <= ADDRESS_LENGTH; i++) {
            patternBuilder.append("([0-9a-fA-F]{2})");
            if (i != ADDRESS_LENGTH) {
                patternBuilder.append("(?:[\\s-:._]?)"); // Ignore element separators
            }
        }
        patternBuilder.append("\\s*$");
        ADDRESS_PATTERN = Pattern.compile(patternBuilder.toString());
    }

    private final byte[] address;

    /**
     * MAC Address constructor capable of parsing hexadecimal encoded values with or without separators
     *
     * @param macAddress Hexadecimal encoded address
     */
    public MacAddress(final String macAddress) {
        address = parseMacAddress(macAddress);
    }

    /**
     * Get Byte Array of Address using Arrays.copyOf()
     *
     * @return Byte Array of Address
     */
    public byte[] getBytes() {
        return Arrays.copyOf(address, ADDRESS_LENGTH);
    }

    /**
     * Is Multicast Address
     *
     * @return Multicast Address status
     */
    public boolean isMulticast() {
        return (address[0] & MUTLTICAST_FLAG) == MUTLTICAST_FLAG;
    }

    /**
     * Is Local Address
     *
     * @return Local Address status
     */
    public boolean isLocal() {
        return (address[0] & LOCAL_FLAG) == LOCAL_FLAG;
    }

    /**
     * Format Address using lowercase hexadecimal encoding with standard separator such as 00:00:00:00:00:00
     *
     * @return Hexadecimal encoded address with standard separator
     */
    @Override
    public String toString() {
        final StringBuilder builder = new StringBuilder();
        for (int i = 0; i < address.length; i++) {
            if (i != 0) {
                builder.append(STANDARD_SEPARATOR);
            }
            builder.append(String.format("%02x", address[i]));

        }
        return builder.toString();
    }

    /**
     * Equals comparison based on address byte array
     *
     * @param object Object for comparison
     * @return Equals status
     */
    @Override
    public boolean equals(final Object object) {
        boolean equals = false;

        if (object instanceof MacAddress) {
            final MacAddress macAddress = (MacAddress) object;
            equals = Arrays.equals(address, macAddress.address);
        }

        return equals;
    }

    /**
     * Hash code based on Arrays.hashCode() of address byte array
     *
     * @return Hash code
     */
    @Override
    public int hashCode() {
        return Arrays.hashCode(address);
    }

    /**
     * Compare to other MAC Address
     *
     * @param macAddress MAC Address for comparison
     * @return Comparison is 0 when equivalent otherwise first difference in address byte values
     */
    @Override
    public int compareTo(final MacAddress macAddress) {
        int comparison = 0;

        for (int i = 0; i < ADDRESS_LENGTH; i++) {
            comparison = address[i] - macAddress.address[i];
            if (comparison != 0) {
                break;
            }
        }

        return comparison;
    }

    private byte[] parseMacAddress(final String macAddress) {
        Objects.requireNonNull(macAddress, "Address required");

        final Matcher matcher = ADDRESS_PATTERN.matcher(macAddress);
        if (matcher.matches()) {
            final byte[] parsedAddress = new byte[ADDRESS_LENGTH];
            for (int group = 1; group <= ADDRESS_LENGTH; group++) {
                final String matchedGroup = matcher.group(group);
                final int parsedGroup = Integer.parseInt(matchedGroup, 16);
                final int index = group - 1;
                parsedAddress[index] = (byte) parsedGroup;
            }
            return parsedAddress;
        } else {
            throw new IllegalArgumentException(String.format("Address not valid [%s]", macAddress));
        }
    }
}
