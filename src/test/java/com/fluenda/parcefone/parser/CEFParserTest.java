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
import org.junit.Assert;
import org.junit.Test;

import java.net.InetAddress;
import java.util.Date;

public class CEFParserTest {

    @Test
    public void validMessageWithoutValidationTest() throws Exception {
        String sample1 = "CEF:0|FireEye|CMS|7.2.1.244420|DM|domain-match|1|rt=Feb 09 2015 12:28:26 dvc=10.201.78.57 cn3Label=cncPort cn3=53 cn2Label=sid cn2=80494706 shost=dev001srv02.example.com proto=udp cs5Label=cncHost cs5=mfdclk001.org dvchost=DEVFEYE1 spt=54527 smac=00:00:0c:07:ac:00 cn1Label=vlan cn1=0 externalId=851983 cs4Label=link cs4=https://DEVCMS01.example.com/event_stream/events_for_bot?ev_id\\=851983 dmac=00:1d:a2:af:32:a1 cs1Label=sname cs1=Trojan.Generic.DNSS";

        CEFParser parser = new CEFParser();

        // Test sample
        Assert.assertNotNull(parser.parse(sample1));
        Assert.assertTrue(parser.parse(sample1).getHeader().containsKey("deviceVendor"));
        Assert.assertEquals(InetAddress.getByName("10.201.78.57"), parser.parse(sample1).getExtensions(true).get("dvc"));
        Assert.assertNull(parser.parse(sample1).getExtensions(true).get("act"));
    }

    @Test
    public void validMessagesWithValidationPopulatedExtensionsTest() throws Exception {
        String sample1 = "CEF:0|FireEye|CMS|7.2.1.244420|DM|domain-match|1|rt=Feb 09 2015 12:28:26 dvc=10.201.78.57 cn3Label=cncPort cn3=53 cn2Label=sid cn2=80494706 shost=dev001srv02.example.com proto=udp cs5Label=cncHost cs5=mfdclk001.org dvchost=DEVFEYE1 spt=54527 smac=00:00:0c:07:ac:00 cn1Label=vlan cn1=0 externalId=851983 cs4Label=link cs4=https://DEVCMS01.example.com/event_stream/events_for_bot?ev_id\\=851983 dmac=00:1d:a2:af:32:a1 cs1Label=sname cs1=Trojan.Generic.DNSS";
        String sample2 = "CEF:0|Apache|apache||200|GET /index.html|Unknown|act=block";
        String sample3 = "CEF:0|security|threatmanager|1.0|100|detected a \\| in message|10|src=10.0.0.1 act=blocked a | dst=1.1.1.1";
        String sample4 = "CEF:0|security|threatmanager|1.0|100|detected a \\\\ in packet|10|src=10.0.0.1 act=blocked a \\\\ dst=1.1.1.1";

        CEFParser parser = new CEFParser();

        // Test 1st sample
        CommonEvent result = parser.parse(sample1, true);
        Assert.assertNotNull(result);
        Assert.assertTrue(result.getHeader().containsKey("deviceVendor"));
        Assert.assertEquals(InetAddress.getByName("10.201.78.57"), result.getExtensions(true).get("dvc"));
        Assert.assertEquals(new Date(1423484906000L), result.getExtensions(true).get("rt"));
        Assert.assertEquals(Long.valueOf("80494706"), result.getExtensions(true).get("cn2"));
        Assert.assertEquals(Integer.valueOf("54527"), result.getExtensions(true).get("spt"));
        Assert.assertEquals("udp", result.getExtensions(true).get("proto"));
        Assert.assertFalse(result.getExtensions(true).containsKey("act"));

        // Test 2nd sample
        result = parser.parse(sample2, true);
        Assert.assertNotNull(result);
        Assert.assertTrue(result.getHeader().containsKey("deviceVendor"));
        Assert.assertFalse(result.getExtensions(true).containsKey("dvc"));

        // Test 3rd sample
        result = parser.parse(sample3, true);
        Assert.assertNotNull(result);
        Assert.assertTrue(result.getHeader().containsKey("deviceVendor"));
        Assert.assertEquals(InetAddress.getByName("1.1.1.1"),result.getExtensions(true).get("dst"));
        Assert.assertEquals(InetAddress.getByName("10.0.0.1"),result.getExtensions(true).get("src"));
        Assert.assertEquals("blocked a |",result.getExtensions(true).get("act"));

        // Test 4th sample
        result = parser.parse(sample4, true);
        Assert.assertNotNull(result);
        Assert.assertTrue(result.getHeader().containsKey("deviceVendor"));
        Assert.assertEquals(InetAddress.getByName("1.1.1.1"), result.getExtensions(true).get("dst"));
        Assert.assertEquals(InetAddress.getByName("10.0.0.1"), result.getExtensions(true).get("src"));
        Assert.assertEquals("blocked a \\\\", result.getExtensions(true).get("act"));
   }

    @Test
    public void validMessageValidationAllExtenstionsTest() throws Exception {
        String sample1 = "CEF:0|FireEye|CMS|7.2.1.244420|DM|domain-match|1|rt=Feb 09 2015 12:28:26 dvc=10.201.78.57 cn3Label=cncPort cn3=53 cn2Label=sid cn2=80494706 shost=dev001srv02.example.com proto=udp cs5Label=cncHost cs5=mfdclk001.org dvchost=DEVFEYE1 spt=54527 smac=00:00:0c:07:ac:00 cn1Label=vlan cn1=0 externalId=851983 cs4Label=link cs4=https://DEVCMS01.example.com/event_stream/events_for_bot?ev_id\\=851983 dmac=00:1d:a2:af:32:a1 cs1Label=sname cs1=Trojan.Generic.DNSS";

        CEFParser parser = new CEFParser();

        // Test 1st sample
        Assert.assertNotNull(parser.parse(sample1, true));
        Assert.assertTrue(parser.parse(sample1).getHeader().containsKey("deviceVendor"));
        Assert.assertEquals(InetAddress.getByName("10.201.78.57"), parser.parse(sample1).getExtensions(true).get("dvc"));
        Assert.assertTrue(parser.parse(sample1).getExtensions(false).containsKey("act"));
        Assert.assertNull(parser.parse(sample1).getExtensions(false).get("act"));
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