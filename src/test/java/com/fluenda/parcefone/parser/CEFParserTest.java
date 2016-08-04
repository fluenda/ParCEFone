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
import com.fluenda.parcefone.formatter.prettyFormal;
import com.martiansoftware.macnificent.MacAddress;
import org.junit.Assert;
import org.junit.Test;

import java.net.InetAddress;
import java.nio.charset.Charset;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class CEFParserTest {

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
                "dpt=1234 agt=123.123.124 dlat=40.366633";

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
        Assert.assertNotNull(result);
        Assert.assertEquals("TestVendor" , result.getHeader().get("deviceVendor"));
        Assert.assertEquals(new Date(1423441663000L), result.getExtension(true).get("rt"));
        Assert.assertEquals("Test Long", result.getExtension(true).get("cn3Label"));
        Assert.assertEquals(9223372036854775807L, result.getExtension(true).get("cn3"));
        Assert.assertEquals(1.234F, result.getExtension(true).get("cfp1"));
        Assert.assertEquals("Test FP Number", result.getExtension(true).get("cfp1Label"));
        Assert.assertEquals(new MacAddress("00.00.0c.07.ac.00"), result.getExtension(true).get("smac"));
        Assert.assertEquals(InetAddress.getByName("2001:cdba:0000:0000:0000:0000:3257:9652"), result.getExtension(true).get("c6a3"));
        Assert.assertEquals("Test IPv6", result.getExtension(true).get("c6a3Label"));
        Assert.assertEquals(InetAddress.getByName("123.123.123.123"), result.getExtension(true).get("destinationTranslatedAddress"));
        Assert.assertEquals(new Date(1423402063000L), result.getExtension(true).get("deviceCustomDate1"));
        Assert.assertEquals(1234, result.getExtension(true).get("dpt"));
        Assert.assertEquals(InetAddress.getByName("123.123.0.124"), result.getExtension(true).get("agt"));
        Assert.assertEquals(40.366633D, result.getExtension(true).get("dlat"));

        // Test sample2
        result = parser.parse(sample2, true);
        Assert.assertNotNull(result);
        Assert.assertEquals("TestVendor" , result.getHeader().get("deviceVendor"));
        Assert.assertEquals(new Date(1423441663000L), result.getExtension(true).get("rt"));
        Assert.assertEquals("Test Long", result.getExtension(true).get("cn3Label"));
        Assert.assertEquals(9223372036854775807L, result.getExtension(true).get("cn3"));
        Assert.assertEquals(1.234F, result.getExtension(true).get("cfp1"));
        Assert.assertEquals("Test FP Number", result.getExtension(true).get("cfp1Label"));
        Assert.assertEquals(new MacAddress("00.00.0c.07.ac.00"), result.getExtension(true).get("smac"));
        Assert.assertEquals(InetAddress.getByName("2001:cdba:0:0:0:0:3257:9652"), result.getExtension(true).get("c6a3"));
        Assert.assertEquals("Test IPv6", result.getExtension(true).get("c6a3Label"));
        Assert.assertEquals(InetAddress.getByName("123.123.123.123"), result.getExtension(true).get("destinationTranslatedAddress"));
        Assert.assertEquals(new Date(1423402063000L), result.getExtension(true).get("deviceCustomDate1"));
        Assert.assertEquals(1234, result.getExtension(true).get("dpt"));
        Assert.assertEquals(InetAddress.getByName("2001:cdba::3257:9652"), result.getExtension(true).get("agt"));
        Assert.assertEquals(40.366633D, result.getExtension(true).get("dlat"));
    }

    @Test
    public void validMessageWithoutValidationTest() throws Exception {
        String sample1 = "CEF:0|FireEye|CMS|7.2.1.244420|DM|domain-match|1|rt=Feb 09 2015 00:27:43 UTC cn3Label=cncPort cn3=53 cn2Label=sid cn2=80494706 shost=dev001srv02.example.com proto=udp cs5Label=cncHost cs5=mfdclk001.org dvchost=DEVFEYE1 spt=61395 dvc=10.100.25.16 smac=00:00:0c:07:ac:00 cn1Label=vlan cn1=0 externalId=851777 cs4Label=link cs4=https://DEVCMS01.example.com/event_stream/events_for_bot?ev_id\\=851777 dmac=00:1d:a2:af:32:a1 cs1Label=sname cs1=Trojan.Generic.DNS ";
        CEFParser parser = new CEFParser();

        // Test sample
        Assert.assertNotNull(parser.parse(sample1));
        Assert.assertTrue(parser.parse(sample1).getHeader().containsKey("deviceVendor"));
        Assert.assertEquals(InetAddress.getByName("10.100.25.16"), parser.parse(sample1).getExtension(true).get("dvc"));
        Assert.assertNull(parser.parse(sample1).getExtension(true).get("act"));
    }

    @Test
    public void validByteArrayMessageWithoutValidationTest() throws Exception {
        String sample1 = "CEF:0|FireEye|CMS|7.2.1.244420|DM|domain-match|1|rt=Feb 09 2015 00:27:43 UTC cn3Label=cncPort cn3=53 cn2Label=sid cn2=80494706 shost=dev001srv02.example.com proto=udp cs5Label=cncHost cs5=mfdclk001.org dvchost=DEVFEYE1 spt=61395 dvc=10.100.25.16 smac=00:00:0c:07:ac:00 cn1Label=vlan cn1=0 externalId=851777 cs4Label=link cs4=https://DEVCMS01.example.com/event_stream/events_for_bot?ev_id\\=851777 dmac=00:1d:a2:af:32:a1 cs1Label=sname cs1=Trojan.Generic.DNS ";
        CEFParser parser = new CEFParser();

        byte[] sample1Array = sample1.getBytes(Charset.forName("UTF-8"));

        // Test sample
        Assert.assertNotNull(parser.parse(sample1Array));
        Assert.assertTrue(parser.parse(sample1Array).getHeader().containsKey("deviceVendor"));
        Assert.assertEquals(InetAddress.getByName("10.100.25.16"), parser.parse(sample1Array).getExtension(true).get("dvc"));
        Assert.assertNull(parser.parse(sample1Array).getExtension(true).get("act"));
    }

    @Test
    public void validByteArrayMessageWithValidationTest() throws Exception {
        String sample1 = "CEF:0|FireEye|CMS|7.2.1.244420|DM|domain-match|1|rt=Feb 09 2015 00:27:43 UTC cn3Label=cncPort cn3=53 cn2Label=sid cn2=80494706 shost=dev001srv02.example.com proto=udp cs5Label=cncHost cs5=mfdclk001.org dvchost=DEVFEYE1 spt=61395 dvc=10.100.25.16 smac=00:00:0c:07:ac:00 cn1Label=vlan cn1=0 externalId=851777 cs4Label=link cs4=https://DEVCMS01.example.com/event_stream/events_for_bot?ev_id\\=851777 dmac=00:1d:a2:af:32:a1 cs1Label=sname cs1=Trojan.Generic.DNS ";
        CEFParser parser = new CEFParser();

        byte[] sample1Array = sample1.getBytes(Charset.forName("UTF-8"));

        // Test sample
        Assert.assertNotNull(parser.parse(sample1Array, true));
        Assert.assertTrue(parser.parse(sample1Array, true).getHeader().containsKey("deviceVendor"));
        Assert.assertEquals(InetAddress.getByName("10.100.25.16"), parser.parse(sample1Array, true).getExtension(true).get("dvc"));
        Assert.assertNull(parser.parse(sample1Array, true).getExtension(true).get("act"));
    }

    @Test
    public void validMessagesWithValidationPopulatedExtensionsTest() throws Exception {
        String sample1 = "CEF:0|FireEye|CMS|7.2.1.244420|DM|domain-match|1|rt=Feb 09 2015 00:27:43 UTC cn3Label=cncPort cn3=53 cn2Label=sid cn2=80494706 shost=dev001srv02.example.com proto=udp cs5Label=cncHost cs5=mfdclk001.org dvchost=DEVFEYE1 spt=61395 dvc=10.100.25.16 smac=00:00:0c:07:ac:00 cn1Label=vlan cn1=0 externalId=851777 cs4Label=link cs4=https://DEVCMS01.example.com/event_stream/events_for_bot?ev_id\\=851777 dmac=00:1d:a2:af:32:a1 cs1Label=sname cs1=Trojan.Generic.DNS ";
        String sample2 = "CEF:0|Apache|apache||200|GET /index.html|Unknown|act=block";
        String sample3 = "CEF:0|security|threatmanager|1.0|100|detected a \\| in message|10|src=10.0.0.1 act=blocked a | dst=1.1.1.1";
        String sample4 = "CEF:0|security|threatmanager|1.0|100|detected a \\\\ in packet|10|src=10.0.0.1 act=blocked a \\\\ dst=1.1.1.1";


        //CHECKSTYLE:OFF
        String sample5 = "CEF:0|Imperva Inc.|SecureSphere|6.0|Protocol|Double URL Encoding|Low| eventId=1032 proto=TCP categorySignificance=/Suspicious categoryBehavior=/Communicate/Query categoryTechnique=/Traffic Anomaly categoryDeviceGroup=/IDS/Network catdt=Network-based IDS/IPS categoryOutcome=/Attempt categoryObject=/Host/Application/Service art=1396036427228 cat=Alert deviceSeverity=Low act=None rt=1396032820000 src=72.238.189.126 sourceZoneURI=/All Zones/ArcSight System/Public Address Space Zones/ARIN/63.0.0.0-76.255.255.255 (ARIN) spt=45694 dst=10.128.10.42 destinationZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 dpt=8080 duser=n/a cs1=Web Protocol Policy cs2=Retail Server Group cs3=Multiple cs4=Multiple cs5=Distributed Double URL Encoding cs1Label=Policy cs2Label=ServerGroup cs3Label=ServiceName cs4Label=ApplicationName cs5Label=Description ahost=prdctapcuacol01.clientaux.local agt=10.135.129.120 agentZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 av=6.0.5.6782.0 atz=America/New_York aid=3ztE6CkUBABD-FjNq0c5CAQ\\\\=\\\\= at=syslog dvchost=prdctrmimpmx01.associateaux.local dvc=10.135.16.29 deviceZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 dtz=America/New_York _cefVer=0.1";
        //CHECKSTYLE:ON
        CEFParser parser = new CEFParser();

//        // Test 1st sample
        CommonEvent result = parser.parse(sample1, true);
        Assert.assertNotNull(result);
        Assert.assertTrue(result.getHeader().containsKey("deviceVendor"));
        Assert.assertEquals(InetAddress.getByName("10.100.25.16"), result.getExtension(true).get("dvc"));
        Assert.assertEquals(new Date(1423441663000L), result.getExtension(true).get("rt"));
        Assert.assertEquals(Long.valueOf("80494706"), result.getExtension(true).get("cn2"));
        Assert.assertEquals(Integer.valueOf("61395"), result.getExtension(true).get("spt"));
        Assert.assertEquals("udp", result.getExtension(true).get("proto"));
        Assert.assertFalse(result.getExtension(true).containsKey("act"));

        // Test 2nd sample
        result = parser.parse(sample2, true);
        Assert.assertNotNull(result);
        Assert.assertTrue(result.getHeader().containsKey("deviceVendor"));
        Assert.assertFalse(result.getExtension(true).containsKey("dvc"));

        // Test 3rd sample
        result = parser.parse(sample3, true);
        Assert.assertNotNull(result);
        Assert.assertTrue(result.getHeader().containsKey("deviceVendor"));
        Assert.assertEquals(InetAddress.getByName("1.1.1.1"),result.getExtension(true).get("dst"));
        Assert.assertEquals(InetAddress.getByName("10.0.0.1"),result.getExtension(true).get("src"));
        Assert.assertEquals("blocked a |",result.getExtension(true).get("act"));

        // Test 4th sample
        result = parser.parse(sample4, true);
        Assert.assertNotNull(result);
        Assert.assertTrue(result.getHeader().containsKey("deviceVendor"));
        Assert.assertEquals(InetAddress.getByName("1.1.1.1"), result.getExtension(true).get("dst"));
        Assert.assertEquals(InetAddress.getByName("10.0.0.1"), result.getExtension(true).get("src"));
        Assert.assertEquals("blocked a \\\\", result.getExtension(true).get("act"));

        // Test 5th sample
        result = parser.parse(sample5, true);
        Assert.assertNotNull(result);
        Assert.assertTrue(result.getHeader().containsKey("deviceVendor"));
        Assert.assertEquals(InetAddress.getByName("10.128.10.42"), result.getExtension(true).get("dst"));
        Assert.assertEquals(InetAddress.getByName("72.238.189.126"), result.getExtension(true).get("src"));
        Assert.assertEquals("/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255", result.getExtension(true).get("deviceZoneURI"));
        Assert.assertEquals(new Date(1396032820000L), result.getExtension(true).get("rt"));
   }


    @Test
    public void validMessageValidationAllExtenstionsTest() throws Exception {
        String sample1 = "CEF:0|FireEye|CMS|7.2.1.244420|DM|domain-match|1|rt=Feb 09 2015 00:27:43 UTC cn3Label=cncPort cn3=53 cn2Label=sid cn2=80494706 shost=dev001srv02.example.com proto=udp cs5Label=cncHost cs5=mfdclk001.org dvchost=DEVFEYE1 spt=61395 dvc=10.100.25.16 smac=00:00:0c:07:ac:00 cn1Label=vlan cn1=0 externalId=851777 cs4Label=link cs4=https://DEVCMS01.example.com/event_stream/events_for_bot?ev_id\\=851777 dmac=00:1d:a2:af:32:a1 cs1Label=sname cs1=Trojan.Generic.DNS ";
        CEFParser parser = new CEFParser();

        // Test 1st sample
        Assert.assertNotNull(parser.parse(sample1, true));
        Assert.assertTrue(parser.parse(sample1).getHeader().containsKey("deviceVendor"));
        Assert.assertEquals(InetAddress.getByName("10.100.25.16"), parser.parse(sample1).getExtension(true).get("dvc"));
        Assert.assertTrue(parser.parse(sample1).getExtension(false).containsKey("act"));
        Assert.assertNull(parser.parse(sample1).getExtension(false).get("act"));
    }

    @Test
    public void invalidMessageValidationTest() throws Exception {
        String sample1 = "CEF:0|security|threatmanager|1.0|100|detected a \\\\ in packet|10|src=10.0.0.1 act=blockedblockedblockedblockedblockedblockedblockedblockedblockedbl a \\\\ dst=1.1.1.1";

        CEFParser parser = new CEFParser();

        CommonEvent event = parser.parse(sample1, true);
        Assert.assertNull(event);

        String sample2 = "CEF:0|security|threatmanager|1.0|100|detected a \\\\ in packet|10|src=10.0.0.1 proto=xdp dst=1.1.1.1";
        event = parser.parse(sample2, true);
        Assert.assertNull(event);
    }

    @Test
    public void invalidMessageTypesTest() throws Exception {
        String sample1 = "CEF:0|security|threatmanager|1.0|100|detected a \\\\ in packet|10|src=10.0.0.1 rt=Wrong Date Format dst=1.1.1.1";

        CEFParser parser = new CEFParser();

        CommonEvent event = parser.parse(sample1, true);
        Assert.assertNull(event);

    }

}