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

import com.fluenda.parcefone.event.CommonEvent;
import com.fluenda.parcefone.event.MacAddress;

import org.junit.jupiter.api.Test;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import java.net.InetAddress;
import java.nio.charset.Charset;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CEFParserTest {

    @Test
    public void customExtensionsandMappedIPV4Test() throws Exception {
        @SuppressWarnings("checkstyle:LineLength")
        String arcsightSample1 = "CEF:0|McAfee|Endpoint Security|ENS 10.5.3.3264|18055: A suspicious call was detected and blocked|A suspicious call was detected and blocked|High|eventId=239038978360 externalId=18055 msg=A suspicious call was detected and blocked mrt=1536700149348 categoryCustomFormatField=_DB_NAME: modelConfidence=0 c6a3=0:0:0:0:0:ffff:a8e:6cc3";
        CEFParser parser = new CEFParser();

        CommonEvent result;
        result = parser.parse(arcsightSample1, true);
        Map<String, Object> resultMap = result.getExtension(true, true);
        int modelConfidence = Integer.valueOf((String) resultMap.get("modelConfidence"));
        assertEquals(0, modelConfidence, "Custom Extension modelConfidence 0");
        InetAddress inetAddress = (InetAddress) resultMap.get("c6a3");
        assertEquals("/10.142.108.195", inetAddress.toString(), "Mapped IPV4 in IPV6 field: 10.142.108.195");
    }

    @Test
    public void messageTypesTest() throws Exception {
        String sample1 = "CEF:0|TestVendor|TestProduct|TestVersion|TestEventClassID|TestName|Low|" +
                // TimeStamp, String and Long
                "rt=Feb 09 2015 00:27:43 UTC cn3Label=Test Long cn3=9223372036854775807 " +
                // FloatPoint and MacAddress
                "cfp1=1.234 cfp1Label=Test FP Number smac=00:00:0c:07:ac:00 " +
                // IPv6 and String
                "c6a3=2001:cdba::3257:9652 c6a3Label=Test IPv6 " +
                // IPv4
                "destinationTranslatedAddress=123.123.123.123 " +
                // Date (without TZ)
                "deviceCustomDate1=Feb 09 2015 00:27:43 " +
                // Integer  and IP Address (from v4)
                "dpt=1234 agt=123.123.0.124 dlat=40.366633";

        String sample2 = "CEF:0|TestVendor|TestProduct|TestVersion|TestEventClassID|TestName|Low|" +
                // TimeStamp, String and Long
                "rt=Feb 09 2015 00:27:43 UTC cn3Label=Test Long cn3=9223372036854775807 " +
                // FloatPoint and MacAddress
                "cfp1=1.234 cfp1Label=Test FP Number smac=00:00:0c:07:ac:00 " +
                // IPv6 and String
                "c6a3=2001:cdba:0000:0000:0000:0000:3257:9652 c6a3Label=Test IPv6 " +
                // IPv4
                "destinationTranslatedAddress=123.123.123.123 " +
                // Date ((without TZ)
                "deviceCustomDate1=Feb 09 2015 00:27:43 " +
                // Integer  and IP Address (from v6)
                "dpt=1234 agt=2001:cdba:0:0:0:0:3257:9652 dlat=40.366633";

        CEFParser parser = new CEFParser();

        CommonEvent result;

        // Test sample1
        result = parser.parse(sample1, true);
        assertNotNull(result);
        assertEquals("TestVendor" , result.getHeader().get("deviceVendor"));
        assertEquals(new Date(1423441663000L), result.getExtension(true).get("rt"));
        assertEquals("Test Long", result.getExtension(true).get("cn3Label"));
        assertEquals(9223372036854775807L, result.getExtension(true).get("cn3"));
        assertEquals(1.234F, result.getExtension(true).get("cfp1"));
        assertEquals("Test FP Number", result.getExtension(true).get("cfp1Label"));
        assertEquals(new MacAddress("00.00.0c.07.ac.00"), result.getExtension(true).get("smac"));
        assertEquals(InetAddress.getByName("2001:cdba:0000:0000:0000:0000:3257:9652"), result.getExtension(true).get("c6a3"));
        assertEquals("Test IPv6", result.getExtension(true).get("c6a3Label"));
        assertEquals(InetAddress.getByName("123.123.123.123"), result.getExtension(true).get("destinationTranslatedAddress"));
        assertEquals(new SimpleDateFormat("MMM dd yyyy HH:mm:ss").parse("Feb 09 2015 00:27:43"), result.getExtension(true).get("deviceCustomDate1"));
        assertEquals(1234, result.getExtension(true).get("dpt"));
        assertEquals(InetAddress.getByName("123.123.0.124"), result.getExtension(true).get("agt"));
        assertEquals(40.366633D, result.getExtension(true).get("dlat"));

        // Test sample2
        result = parser.parse(sample2, true);
        assertNotNull(result);
        assertEquals("TestVendor" , result.getHeader().get("deviceVendor"));
        assertEquals(new Date(1423441663000L), result.getExtension(true).get("rt"));
        assertEquals("Test Long", result.getExtension(true).get("cn3Label"));
        assertEquals(9223372036854775807L, result.getExtension(true).get("cn3"));
        assertEquals(1.234F, result.getExtension(true).get("cfp1"));
        assertEquals("Test FP Number", result.getExtension(true).get("cfp1Label"));
        assertEquals(new MacAddress("00.00.0c.07.ac.00"), result.getExtension(true).get("smac"));
        assertEquals(InetAddress.getByName("2001:cdba:0:0:0:0:3257:9652"), result.getExtension(true).get("c6a3"));
        assertEquals("Test IPv6", result.getExtension(true).get("c6a3Label"));
        assertEquals(InetAddress.getByName("123.123.123.123"), result.getExtension(true).get("destinationTranslatedAddress"));
        assertEquals(new SimpleDateFormat("MMM dd yyyy HH:mm:ss").parse("Feb 09 2015 00:27:43"), result.getExtension(true).get("deviceCustomDate1"));
        assertEquals(1234, result.getExtension(true).get("dpt"));
        assertEquals(InetAddress.getByName("2001:cdba::3257:9652"), result.getExtension(true).get("agt"));
        assertEquals(40.366633D, result.getExtension(true).get("dlat"));
    }

    @Test
    public void validMessageWithoutValidationTest() throws Exception {
        String sample1 = "CEF:0|FireEye|CMS|7.2.1.244420|DM|domain-match|1|rt=Feb 09 2015 00:27:43 UTC cn3Label=cncPort cn3=53 cn2Label=sid cn2=80494706 shost=dev001srv02.example.com proto=udp cs5Label=cncHost cs5=mfdclk001.org dvchost=DEVFEYE1 spt=61395 dvc=10.100.25.16 smac=00:00:0c:07:ac:00 cn1Label=vlan cn1=0 externalId=851777 cs4Label=link cs4=https://DEVCMS01.example.com/event_stream/events_for_bot?ev_id\\=851777 dmac=00:1d:a2:af:32:a1 cs1Label=sname cs1=Trojan.Generic.DNS ";
        CEFParser parser = new CEFParser();

        // Test sample
        assertNotNull(parser.parse(sample1));
        assertTrue(parser.parse(sample1).getHeader().containsKey("deviceVendor"));
        assertEquals(InetAddress.getByName("10.100.25.16"), parser.parse(sample1).getExtension(true).get("dvc"));
        assertNull(parser.parse(sample1).getExtension(true).get("act"));
    }

    @Test
    public void validMessageWithEmptyExtensions() throws Exception {
        String sample1 = "CEF:0|FireEye|CMS|7.2.1.244420|DM|domain-match|1|rt= cn3Label= cn3= cn2Label= cn2= shost= proto= cs5Label= cs5= dvchost= spt= dvc= smac= cn1Label= cn1= externalId= cs4Label= cs4= dmac= cs1Label= cs1=";
        CEFParser parser = new CEFParser();

        // validation should be disabled if we allow for null values
        // if not disabled, the parsing would be successful but the validation is likely to fail
        CommonEvent result = parser.parse(sample1, false, true, Locale.ENGLISH);

        // Test sample
        assertNotNull(result);
        assertTrue(result.getHeader().containsKey("deviceVendor"));
        assertFalse(result.getExtension(true).containsKey("act"));
        assertTrue(result.getExtension(true).containsKey("cn3") && result.getExtension(true).get("cn3") == null);
        assertTrue(result.getExtension(true).containsKey("dvc") && result.getExtension(true).get("dvc") == null);
        assertTrue(result.getExtension(true).containsKey("smac") && result.getExtension(true).get("smac") == null);
    }

    @Test
    public void validByteArrayMessageWithoutValidationTest() throws Exception {
        String sample1 = "CEF:0|FireEye|CMS|7.2.1.244420|DM|domain-match|1|rt=Feb 09 2015 00:27:43 UTC cn3Label=cncPort cn3=53 cn2Label=sid cn2=80494706 shost=dev001srv02.example.com proto=udp cs5Label=cncHost cs5=mfdclk001.org dvchost=DEVFEYE1 spt=61395 dvc=10.100.25.16 smac=00:00:0c:07:ac:00 cn1Label=vlan cn1=0 externalId=851777 cs4Label=link cs4=https://DEVCMS01.example.com/event_stream/events_for_bot?ev_id\\=851777 dmac=00:1d:a2:af:32:a1 cs1Label=sname cs1=Trojan.Generic.DNS ";
        CEFParser parser = new CEFParser();

        byte[] sample1Array = sample1.getBytes(Charset.forName("UTF-8"));

        // Test sample
        assertNotNull(parser.parse(sample1Array));
        assertTrue(parser.parse(sample1Array).getHeader().containsKey("deviceVendor"));
        assertEquals(InetAddress.getByName("10.100.25.16"), parser.parse(sample1Array).getExtension(true).get("dvc"));
        assertNull(parser.parse(sample1Array).getExtension(true).get("act"));
    }

    @Test
    public void validByteArrayMessageWithValidationTest() throws Exception {
        String sample1 = "CEF:0|FireEye|CMS|7.2.1.244420|DM|domain-match|1|rt=Feb 09 2015 00:27:43 UTC cn3Label=cncPort cn3=53 cn2Label=sid cn2=80494706 shost=dev001srv02.example.com proto=udp cs5Label=cncHost cs5=mfdclk001.org dvchost=DEVFEYE1 spt=61395 dvc=10.100.25.16 smac=00:00:0c:07:ac:00 cn1Label=vlan cn1=0 externalId=851777 cs4Label=link cs4=https://DEVCMS01.example.com/event_stream/events_for_bot?ev_id\\=851777 dmac=00:1d:a2:af:32:a1 cs1Label=sname cs1=Trojan.Generic.DNS ";
        CEFParser parser = new CEFParser();

        byte[] sample1Array = sample1.getBytes(Charset.forName("UTF-8"));

        // Test sample
        assertNotNull(parser.parse(sample1Array, true));
        assertTrue(parser.parse(sample1Array, true).getHeader().containsKey("deviceVendor"));
        assertEquals(InetAddress.getByName("10.100.25.16"), parser.parse(sample1Array, true).getExtension(true).get("dvc"));
        assertNull(parser.parse(sample1Array, true).getExtension(true).get("act"));
    }

    @Test
    public void validByteArrayMessageWithLocaleAndValidationTest() throws Exception {
        String sample1 = "CEF:0|FireEye|CMS|7.2.1.244420|DM|domain-match|1|rt=juil. 09 2015 00:27:43 UTC cn3Label=cncPort cn3=53 cn2Label=sid cn2=80494706 shost=dev001srv02.example.com proto=udp cs5Label=cncHost cs5=mfdclk001.org dvchost=DEVFEYE1 spt=61395 dvc=10.100.25.16 smac=00:00:0c:07:ac:00 cn1Label=vlan cn1=0 externalId=851777 cs4Label=link cs4=https://DEVCMS01.example.com/event_stream/events_for_bot?ev_id\\=851777 dmac=00:1d:a2:af:32:a1 cs1Label=sname cs1=Trojan.Generic.DNS ";
        CEFParser parser = new CEFParser();

        byte[] sample1Array = sample1.getBytes(Charset.forName("UTF-8"));

        // Test sample
        assertNotNull(parser.parse(sample1Array, true, Locale.FRANCE));
        assertTrue(parser.parse(sample1Array, true, Locale.FRANCE).getHeader().containsKey("deviceVendor"));
        assertEquals(new Date(1436401663000L), parser.parse(sample1Array, true, Locale.FRANCE).getExtension(true).get("rt"));
        assertEquals(InetAddress.getByName("10.100.25.16"), parser.parse(sample1Array, true, Locale.FRANCE).getExtension(true).get("dvc"));
        assertNull(parser.parse(sample1Array, true, Locale.FRANCE).getExtension(true).get("act"));
    }

    @Test
    public void validStringMessageWithLocaleAndValidationTest() throws Exception {
        String sample1 = "CEF:0|FireEye|CMS|7.2.1.244420|DM|domain-match|1|rt=1436401663000 cn3Label=cncPort cn3=53 cn2Label=sid cn2=80494706 shost=dev001srv02.example.com proto=udp cs5Label=cncHost cs5=mfdclk001.org dvchost=DEVFEYE1 spt=61395 dvc=10.100.25.16 smac=00:00:0c:07:ac:00 cn1Label=vlan cn1=0 externalId=851777 cs4Label=link cs4=https://DEVCMS01.example.com/event_stream/events_for_bot?ev_id\\=851777 dmac=00:1d:a2:af:32:a1 cs1Label=sname cs1=Trojan.Generic.DNS ";
        CEFParser parser = new CEFParser();

        // Test sample
        assertNotNull(parser.parse(sample1, true, Locale.FRANCE));
        assertTrue(parser.parse(sample1, true, Locale.FRANCE).getHeader().containsKey("deviceVendor"));
        assertEquals(new Date(1436401663000L), parser.parse(sample1, true, Locale.FRANCE).getExtension(true).get("rt"));
        assertEquals(InetAddress.getByName("10.100.25.16"), parser.parse(sample1, true, Locale.FRANCE).getExtension(true).get("dvc"));
        assertNull(parser.parse(sample1, true, Locale.FRANCE).getExtension(true).get("act"));
    }

    @Test
    public void validStringMessageWithoutTZWithLocaleAndValidationTest() throws Exception {
        String sample1 = "CEF:0|FireEye|CMS|7.2.1.244420|DM|domain-match|1|rt=juil. 09 2015 00:27:43 cn3Label=cncPort cn3=53 cn2Label=sid cn2=80494706 shost=dev001srv02.example.com proto=udp cs5Label=cncHost cs5=mfdclk001.org dvchost=DEVFEYE1 spt=61395 dvc=10.100.25.16 smac=00:00:0c:07:ac:00 cn1Label=vlan cn1=0 externalId=851777 cs4Label=link cs4=https://DEVCMS01.example.com/event_stream/events_for_bot?ev_id\\=851777 dmac=00:1d:a2:af:32:a1 cs1Label=sname cs1=Trojan.Generic.DNS ";
        CEFParser parser = new CEFParser();

        // Test sample
        assertNotNull(parser.parse(sample1, true, Locale.FRANCE));
        assertTrue(parser.parse(sample1, true, Locale.FRANCE).getHeader().containsKey("deviceVendor"));
        assertEquals(new SimpleDateFormat("MMM dd yyyy HH:mm:ss").parse("Jul 09 2015 00:27:43"), parser.parse(sample1, true, Locale.FRANCE).getExtension(true).get("rt"));
        assertEquals(InetAddress.getByName("10.100.25.16"), parser.parse(sample1, true, Locale.FRANCE).getExtension(true).get("dvc"));
        assertNull(parser.parse(sample1, true, Locale.FRANCE).getExtension(true).get("act"));
    }

    @Test
    public void validMessagesWithValidationPopulatedExtensionsTest() throws Exception {
        String sample1 = "CEF:0|FireEye|CMS|7.2.1.244420|DM|domain-match|1|rt=Feb 09 2015 00:27:43 UTC cn3Label=cncPort cn3=53 cn2Label=sid cn2=80494706 shost=dev001srv02.example.com proto=udp cs5Label=cncHost cs5=mfdclk001.org dvchost=DEVFEYE1 spt=61395 dvc=10.100.25.16 smac=00:00:0c:07:ac:00 cn1Label=vlan cn1=0 externalId=851777 cs4Label=link cs4=https://DEVCMS01.example.com/event_stream/events_for_bot?ev_id\\=851777 dmac=00:1d:a2:af:32:a1 cs1Label=sname cs1=Trojan.Generic.DNS ";
        String sample2 = "CEF:0|Apache|apache||200|GET /index.html|Unknown|act=block";
        String sample3 = "CEF:0|security|threatmanager|1.0|100|detected a \\| in message|10|src=10.0.0.1 act=blocked a | dst=1.1.1.1";
        String sample4 = "CEF:0|security|threatmanager|1.0|100|detected a \\\\ in packet|10|src=10.0.0.1 act=blocked a \\\\ dst=1.1.1.1";

        @SuppressWarnings("checkstyle:LineLength")
        String sample5 = "CEF:0|Imperva Inc.|SecureSphere|6.0|Protocol|Double URL Encoding|Low| eventId=1032 proto=TCP categorySignificance=/Suspicious categoryBehavior=/Communicate/Query categoryTechnique=/Traffic Anomaly categoryDeviceGroup=/IDS/Network catdt=Network-based IDS/IPS categoryOutcome=/Attempt categoryObject=/Host/Application/Service art=1396036427228 cat=Alert deviceSeverity=Low act=None rt=1396032820000 src=72.238.189.126 sourceZoneURI=/All Zones/ArcSight System/Public Address Space Zones/ARIN/63.0.0.0-76.255.255.255 (ARIN) spt=45694 dst=10.128.10.42 destinationZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 dpt=8080 duser=n/a cs1=Web Protocol Policy cs2=Retail Server Group cs3=Multiple cs4=Multiple cs5=Distributed Double URL Encoding cs1Label=Policy cs2Label=ServerGroup cs3Label=ServiceName cs4Label=ApplicationName cs5Label=Description ahost=prdctapcuacol01.clientaux.local agt=10.135.129.120 agentZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 av=6.0.5.6782.0 atz=America/New_York aid=3ztE6CkUBABD-FjNq0c5CAQ\\\\=\\\\= at=syslog dvchost=prdctrmimpmx01.associateaux.local dvc=10.135.16.29 deviceZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 dtz=America/New_York _cefVer=0.1";

        CEFParser parser = new CEFParser();

        // Test 1st sample
        CommonEvent result = parser.parse(sample1, true);
        assertNotNull(result);
        assertTrue(result.getHeader().containsKey("deviceVendor"));
        assertEquals(InetAddress.getByName("10.100.25.16"), result.getExtension(true).get("dvc"));
        assertEquals(new Date(1423441663000L), result.getExtension(true).get("rt"));
        assertEquals(Long.valueOf("80494706"), result.getExtension(true).get("cn2"));
        assertEquals(Integer.valueOf("61395"), result.getExtension(true).get("spt"));
        assertEquals("udp", result.getExtension(true).get("proto"));
        assertFalse(result.getExtension(true).containsKey("act"));

        // Test 2nd sample
        result = parser.parse(sample2, true);
        assertNotNull(result);
        assertTrue(result.getHeader().containsKey("deviceVendor"));
        assertFalse(result.getExtension(true).containsKey("dvc"));

        // Test 3rd sample
        result = parser.parse(sample3, true);
        assertNotNull(result);
        assertTrue(result.getHeader().containsKey("deviceVendor"));
        assertEquals(InetAddress.getByName("1.1.1.1"),result.getExtension(true).get("dst"));
        assertEquals(InetAddress.getByName("10.0.0.1"),result.getExtension(true).get("src"));
        assertEquals("blocked a |",result.getExtension(true).get("act"));

        // Test 4th sample
        result = parser.parse(sample4, true);
        assertNotNull(result);
        assertTrue(result.getHeader().containsKey("deviceVendor"));
        assertEquals(InetAddress.getByName("1.1.1.1"), result.getExtension(true).get("dst"));
        assertEquals(InetAddress.getByName("10.0.0.1"), result.getExtension(true).get("src"));
        assertEquals("blocked a \\\\", result.getExtension(true).get("act"));

        // Test 5th sample
        result = parser.parse(sample5, true);
        assertNotNull(result);
        assertTrue(result.getHeader().containsKey("deviceVendor"));
        // Test leading space on first KV pair
        assertEquals(1032L, result.getExtension(true).get("eventId"));
        assertEquals(InetAddress.getByName("10.128.10.42"), result.getExtension(true).get("dst"));
        assertEquals(InetAddress.getByName("72.238.189.126"), result.getExtension(true).get("src"));
        assertEquals("/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255", result.getExtension(true).get("deviceZoneURI"));
        assertEquals(new Date(1396032820000L), result.getExtension(true).get("rt"));
   }


    @Test
    public void validMessageValidationAllExtenstionsTest() throws Exception {
        String sample1 = "CEF:0|FireEye|CMS|7.2.1.244420|DM|domain-match|1|rt=Feb 09 2015 00:27:43 UTC cn3Label=cncPort cn3=53 cn2Label=sid cn2=80494706 shost=dev001srv02.example.com proto=udp cs5Label=cncHost cs5=mfdclk001.org dvchost=DEVFEYE1 spt=61395 dvc=10.100.25.16 smac=00:00:0c:07:ac:00 cn1Label=vlan cn1=0 externalId=851777 cs4Label=link cs4=https://DEVCMS01.example.com/event_stream/events_for_bot?ev_id\\=851777 dmac=00:1d:a2:af:32:a1 cs1Label=sname cs1=Trojan.Generic.DNS ";
        CEFParser parser = new CEFParser();

        // Test 1st sample
        assertNotNull(parser.parse(sample1, true));
        assertTrue(parser.parse(sample1).getHeader().containsKey("deviceVendor"));
        assertEquals(InetAddress.getByName("10.100.25.16"), parser.parse(sample1).getExtension(true).get("dvc"));
        assertTrue(parser.parse(sample1).getExtension(false).containsKey("act"));
        assertNull(parser.parse(sample1).getExtension(false).get("act"));
    }

    @Test
    public void invalidMessageValidationTest() throws Exception {
        String sample1 = "CEF:0|security|threatmanager|1.0|100|detected a \\\\ in packet|10|src=10.0.0.1 act=blockedblockedblockedblockedblockedblockedblockedblockedblockedbl a \\\\ dst=1.1.1.1";

        CEFParser parser = new CEFParser();

        CommonEvent event = parser.parse(sample1, true);
        assertNull(event);

        String sample2 = "CEF:0|security|threatmanager|1.0|100|detected a \\\\ in packet|10|src=10.0.0.1 proto=xdp dst=1.1.1.1";
        event = parser.parse(sample2, true);
        assertNull(event);
    }

    @Test
    public void invalidMessageTypesTest() throws Exception {
        String sample1 = "CEF:0|security|threatmanager|1.0|100|detected a \\\\ in packet|10|src=10.0.0.1 rt=Wrong Date Format dst=1.1.1.1";

        CEFParser parser = new CEFParser();

        CommonEvent event = parser.parse(sample1, true);
        assertNull(event);

    }

    @Test
    public void testMissingHeaders() throws Exception {
        String sample1 = "CEF:0||threatmanager|1.0|100|detected a \\\\ in packet|10|src=10.0.0.1";

        CEFParser parser = new CEFParser();

        CommonEvent event = parser.parse(sample1, true);
        assertNotNull(event);
        assertTrue(event.getHeader().containsKey("deviceVendor"));
        assertEquals("", event.getHeader().get("deviceVendor"));
    }

    @Test
    public void junkStringValidationTest() throws Exception {
        String sample1 = "test test test chocolate";

        CEFParser parser = new CEFParser();

        CommonEvent event = parser.parse(sample1, true);
        assertNull(event);
    }

    @Test
    public void testExternallyProvidedValidator() throws Exception {
        String sample1 = "CEF:0|FireEye|CMS|7.2.1.244420|DM|domain-match|1|rt=Feb 09 2015 00:27:43 UTC cn3Label=cncPort cn3=53 cn2Label=sid cn2=80494706 shost=dev001srv02.example.com proto=udp cs5Label=cncHost cs5=mfdclk001.org dvchost=DEVFEYE1 spt=61395 dvc=10.100.25.16 smac=00:00:0c:07:ac:00 cn1Label=vlan cn1=0 externalId=851777 cs4Label=link cs4=https://DEVCMS01.example.com/event_stream/events_for_bot?ev_id\\=851777 dmac=00:1d:a2:af:32:a1 cs1Label=sname cs1=Trojan.Generic.DNS ";


        final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

        CEFParser parser = new CEFParser(validator);

        // Test 1st sample
        assertNotNull(parser.parse(sample1, true));
        assertTrue(parser.parse(sample1).getHeader().containsKey("deviceVendor"));
        assertEquals(InetAddress.getByName("10.100.25.16"), parser.parse(sample1).getExtension(true).get("dvc"));
        assertTrue(parser.parse(sample1).getExtension(false).containsKey("act"));
        assertNull(parser.parse(sample1).getExtension(false).get("act"));
    }
}