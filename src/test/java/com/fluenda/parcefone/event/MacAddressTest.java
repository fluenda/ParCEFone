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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class MacAddressTest {

    private static final String NORMALIZED_ADDRESS = "00:ff:00:ff:00:ff";

    private static final String HYPHEN_SEPARATOR = "00-ff-00-ff-00-ff";

    private static final String UNDERSCORE_SEPARATOR = "00_ff_00_ff_00_ff";

    private static final String SPACE_SEPARATOR = "00 ff 00 ff 00 ff";

    private static final String PERIOD_SEPARATOR = "00.ff.00.ff.00.ff";

    private static final String NO_SEPARATOR = "00ff00ff00ff";

    private static final String LOCAL_ADDRESS = "ff:ff:ff:ff:ff:ff";

    private static final String MULTICAST_ADDRESS = "01:80:c2:00:00:00";

    private static final String INVALID_LENGTH = "00:ff:00:ff:00";

    @Test
    public void testAddressNormalizedSeparator() {
        final MacAddress macAddress = new MacAddress(NORMALIZED_ADDRESS);
        assertEquals(NORMALIZED_ADDRESS, macAddress.toString());
    }

    @Test
    public void testAddressHyphenSeparator() {
        final MacAddress macAddress = new MacAddress(HYPHEN_SEPARATOR);
        assertEquals(NORMALIZED_ADDRESS, macAddress.toString());
    }

    @Test
    public void testAddressUnderscoreSeparator() {
        final MacAddress macAddress = new MacAddress(UNDERSCORE_SEPARATOR);
        assertEquals(NORMALIZED_ADDRESS, macAddress.toString());
    }

    @Test
    public void testAddressSpaceSeparator() {
        final MacAddress macAddress = new MacAddress(SPACE_SEPARATOR);
        assertEquals(NORMALIZED_ADDRESS, macAddress.toString());
    }

    @Test
    public void testAddressPeriodSeparator() {
        final MacAddress macAddress = new MacAddress(PERIOD_SEPARATOR);
        assertEquals(NORMALIZED_ADDRESS, macAddress.toString());
    }

    @Test
    public void testAddressNoSeparator() {
        final MacAddress macAddress = new MacAddress(NO_SEPARATOR);
        assertEquals(NORMALIZED_ADDRESS, macAddress.toString());
    }

    @Test
    public void testAddressInvalidLength() {
        assertThrows(IllegalArgumentException.class, () -> new MacAddress(INVALID_LENGTH));
    }

    @Test
    public void testAddressLocal() {
        final MacAddress macAddress = new MacAddress(LOCAL_ADDRESS);
        assertTrue(macAddress.isLocal());
    }

    @Test
    public void testAddressMulticast() {
        final MacAddress macAddress = new MacAddress(MULTICAST_ADDRESS);
        assertTrue(macAddress.isMulticast());
    }

    @Test
    public void testAddressMulticastNotLocal() {
        final MacAddress macAddress = new MacAddress(MULTICAST_ADDRESS);
        assertFalse(macAddress.equals(new MacAddress(LOCAL_ADDRESS)));
    }

    @Test
    public void testAddressGetBytes() {
        final MacAddress macAddress = new MacAddress(MULTICAST_ADDRESS);
        assertNotNull(macAddress.getBytes());
    }

    @Test
    public void testAddressHashCode() {
        final MacAddress macAddress = new MacAddress(MULTICAST_ADDRESS);
        assertNotEquals(0, macAddress.hashCode());
    }

    @Test
    public void testAddressCompareToEqual() {
        final MacAddress macAddress = new MacAddress(MULTICAST_ADDRESS);
        final int comparison = macAddress.compareTo(macAddress);
        assertEquals(0, comparison);
    }

    @Test
    public void testAddressCompareToNotEqual() {
        final MacAddress macAddress = new MacAddress(MULTICAST_ADDRESS);
        final int comparison = macAddress.compareTo(new MacAddress(LOCAL_ADDRESS));
        assertNotEquals(0, comparison);
    }
}
