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

import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.lang.reflect.Field;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;

/**
 * Implements the Common Event Format (CEF) as documented by
 * <a href="https://www.protect724.hpe.com/servlet/JiveServlet/downloadBody/1072-102-9-20354/CommonEventFormatv23.pdf">
 *     revision 23
 * </a>
 * (Retrieved on August 2016).
 *
 */
public class CefRev23 extends CommonEvent {

    // Note the conflict with javax.validation.constraints.Pattern...
    final private java.util.regex.Pattern timeRegex =  java.util.regex.Pattern.compile(
                    "(?<MONTH>\\S+(\\.)?)\\s(?<DAY>\\d{2})\\s(?:(?<YEAR>\\d{4})(?:\\s))?" +
                    "(?<HOUR>[012][0-9]):(?<MINUTE>[0-5][0-9]):(?<SECOND>[0-5][0-9])" +
                    "(?:\\.(?<MILLI>\\d{3}))?(?:\\s(?<TZ>\\w+))?");

    final private Class<?> objClass = this.getClass();
    final private Field[] fields = objClass.getDeclaredFields();
    private ArrayList<String> populatedExtensions = new ArrayList<String>();
    private Map<String, Object> customExtensions = new HashMap<>();

    // Implements a " struct like"  class that implements the Common Event
    // Format v23 as described here:
    // https://www.protect724.hpe.com/servlet/JiveServlet/downloadBody/1072-102-9-20354/CommonEventFormatv23.pdf

    private int version;
    private String deviceVendor;
    private String deviceProduct;
    private String deviceVersion;
    // Device Event Class ID is defined as int or String (yay!) treating as
    // string
    private String deviceEventClassId;
    private String name;
    private String severity;

    // The extension field and its list of KVs

    @Size(max = 63)
    private String act;

    @Size(max = 31)
    private String app;

    private InetAddress c6a1;

    @Size(max = 1023)
    private String c6a1Label;

    private InetAddress c6a2;

    @Size(max = 1023)
    private String c6a2Label;

    private InetAddress c6a3;

    @Size(max = 1023)
    private String c6a3Label;

    private InetAddress c6a4;

    @Size(max = 1023)
    private String c6a4Label;

    private float cfp1;

    @Size(max = 1023)
    private String cfp1Label;

    private float cfp2;

    @Size(max = 1023)
    private String cfp2Label;

    private float cfp3;

    @Size(max = 1023)
    private String cfp3Label;

    private float cfp4;

    @Size(max = 1023)
    private String cfp4Label;

    private long cn1;

    @Size(max = 1023)
    private String cn1Label;

    private long cn2;

    @Size(max = 1023)
    private String cn2Label;

    private long cn3;

    @Size(max = 1023)
    private String cn3Label;

    private long cnt;

    @Size(max = 4000)
    private String cs1;

    @Size(max = 1023)
    private String cs1Label;

    @Size(max = 4000)
    private String cs2;

    @Size(max = 1023)
    private String cs2Label;

    @Size(max = 4000)
    private String cs3;

    @Size(max = 1023)
    private String cs3Label;

    @Size(max = 4000)
    private String cs4;

    @Size(max = 1023)
    private String cs4Label;

    @Size(max = 4000)
    private String cs5;

    @Size(max = 1023)
    private String cs5Label;

    @Size(max = 4000)
    private String cs6;

    @Size(max = 1023)
    private String cs6Label;

    @Size(max = 255)
    private String destinationDnsDomain;

    @Size(max = 1023)
    private String destinationServiceName;

    private Inet4Address destinationTranslatedAddress;

    private int destinationTranslatedPort;

    private Date deviceCustomDate1;

    @Size(max = 1023)
    private String deviceCustomDate1Label;

    private Date deviceCustomDate2;

    @Size(max = 1023)
    private String deviceCustomDate2Label;

    // OMG! Device direction is binary!!!
    // 0 = inbound 1 is outbound
    @Min(0)
    @Max(1)
    private int deviceDirection;

    @Size(max = 255)
    private String deviceDnsDomain;

    @Size(max = 255)
    private String deviceExternalId;

    @Size(max = 1023)
    private String deviceFacility;

    @Size(max = 128)
    private String deviceInboundInterface;

    @Size(max = 255)
    private String deviceNtDomain;

    @Size(max = 128)
    private String deviceOutboundInterface;

    @Size(max = 128)
    private String devicePayloadId;

    @Size(max = 1023)
    private String deviceProcessName;

    private Inet4Address deviceTranslatedAddress;

    @Size(max = 1023)
    private String dhost;

    private MacAddress dmac;

    @Size(max = 255)
    private String dntdom;

    private int dpid;

    @Size(max = 1023)
    private String dpriv;

    @Size(max = 1023)
    private String dproc;

    @Max(65535)
    private int dpt;

    private Inet4Address dst;

    @Size(max = 255)
    private String dtz;

    @Size(max = 1023)
    private String duid;

    @Size(max = 1023)
    private String duser;

    private Inet4Address dvc;

    @Size(max = 100)
    private String dvchost;

    private MacAddress dvcmac;

    private int dvcpid;

    private Date end;

    @Size(max = 40)
    private String externalId;

    private Date fileCreateTime;

    @Size(max = 255)
    private String fileHash;

    @Size(max = 1023)
    private String field;

    private Date fileModificationTime;

    @Size(max = 1023)
    private String filePath;

    @Size(max = 1023)
    private String filePermission;

    @Size(max = 1023)
    private String fileType;

    private Date flexDate1;

    @Size(max = 128)
    private String flexDate1Label;

    private long flexNumber1;

    @Size(max = 128)
    private String flexNumber1Label;

    private long flexNumber2;

    @Size(max = 128)
    private String flexNumber2Label;

    @Size(max = 1023)
    private String flexString1;

    @Size(max = 128)
    private String flexString1Label;

    @Size(max = 1023)
    private String flexString2;

    @Size(max = 128)
    private String flexString2Label;

    @Size(max = 1023)
    private String fname;

    private int fsize;

    private int in;

    @Size(max = 1023)
    private String msg;

    private Date oldFileCreateTime;

    @Size(max = 255)
    private String oldFileHash;

    @Size(max = 1023)
    private String oldField;

    private Date oldFileModificationTime;

    @Size(max = 1023)
    private String oldFileName;

    @Size(max = 1023)
    private String oldFilePath;

    @Size(max = 1023)
    private String oldFilePermission;

    private int oldFileSize;

    @Size(max = 1023)
    private String oldFileType;

    private int out;

    @Size(max = 63)
    private String outcome;

    @Pattern(regexp = "tcp|udp", flags = Pattern.Flag.CASE_INSENSITIVE)
    @Size(max = 31)
    private String proto;

    @Size(max = 1023)
    private String reason;

    @Size(max = 1023)
    private String request;

    @Size(max = 1023)
    private String requestClientApplication;

    @Size(max = 2048)
    private String requestContext;

    @Size(max = 1023)
    private String requestCookies;

    @Size(max = 1023)
    private String requestMethod;

    private Date rt;

    @Size(max = 1023)
    private String shost;

    private MacAddress smac;

    @Size(max = 255)
    private String sntdom;

    @Size(max = 255)
    private String sourceDnsDomain;

    @Size(max = 1023)
    private String sourceServiceName;

    private Inet4Address sourceTranslatedAddress;

    private int sourceTranslatedPort;

    private int spid;

    @Size(max = 1023)
    private String spriv;

    @Size(max = 1023)
    private String sproc;

    @Max(65535)
    private int spt;

    private Inet4Address src;

    private Date start;

    @Size(max = 1023)
    private String suid;

    @Size(max = 1023)
    private String suser;

    @Min(0)
    @Max(3)
    private int type;

    @Size(max = 255)
    private String agentDnsDomain;

    @Size(max = 255)
    private String agentNtDomain;

    private Inet4Address agentTranslatedAddress;

    @Size(max = 200)
    private String agentTranslatedZoneExternalID;

    @Size(max = 2048)
    private String agentTranslatedZoneURI;

    @Size(max = 200)
    private String agentZoneExternalID;

    @Size(max = 2048)
    private String agentZoneURI;

    private InetAddress agt;

    @Size(max = 1023)
    private String ahost;

    @Size(max = 40)
    private String aid;

    private MacAddress amac;

    private Date art;

    @Size(max = 63)
    private String at;

    @Size(max = 255)
    private String atz;

    @Size(max = 31)
    private String av;

    @Size(max = 1023)
    private String cat;

    @Size(max = 200)
    private String customerExternalID;

    @Size(max = 2048)
    private String customerURI;

    @Size(max = 200)
    private String destinationTranslatedZoneExternalID;

    @Size(max = 2048)
    private String destinationTranslatedZoneURI;

    @Size(max = 200)
    private String destinationZoneExternalID;

    @Size(max = 2048)
    private String destinationZoneURI;

    @Size(max = 200)
    private String deviceTranslatedZoneExternalID;

    @Size(max = 2048)
    private String deviceTranslatedZoneURI;

    @Size(max = 200)
    private String deviceZoneExternalID;

    @Size(max = 2048)
    private String deviceZoneURI;

    private double dlat;

    private double dlong;

    private long eventId;

    @Size(max = 4000)
    private String rawEvent;

    private double slat;

    private double slong;

    @Size(max = 200)
    private String sourceTranslatedZoneExternalID;

    @Size(max = 2048)
    private String sourceTranslatedZoneURI;

    @Size(max = 200)
    private String sourceZoneExternalID;

    @Size(max = 2048)
    private String sourceZoneURI;

    private Locale dateLocale;


    public CefRev23(Locale locale) {
        super();
        this.dateLocale = locale;
    }

    public CefRev23() {
        super();

        // Defaults to ENGLISH locale when processing dates
        this.dateLocale = Locale.ENGLISH;
    }

    /**
    * @param headers A map containing the  keys and values of headers of CEF event
    * @throws CEFHandlingException when it has issues writing the values of the headers
    */
    public void setHeader(Map<String, Object> headers)  throws CEFHandlingException {
        for (String key : headers.keySet()) {
            try {
                Field field = objClass.getDeclaredField(key);
                Object value = headers.get(key);
                field.set(this, value);
            } catch (NoSuchFieldException | IllegalAccessException e) {
                throw new CEFHandlingException("Error writing values to headers", e);
            }
        }
    }

    /**
     * @return A map containing the keys and values of headers
     * @throws CEFHandlingException when it has issues reading the headers of CEF event
     */
    public Map<String, Object> getHeader() throws CEFHandlingException {
        final HashMap<String, Object> headers = new HashMap<String, Object>();
        List headersKeys = Arrays.asList(new String[] {"version", "deviceVendor", "deviceProduct", "deviceVersion", "deviceEventClassId", "name", "severity"});

        for (Field f: fields) {
            if (headersKeys.contains(f.getName())) {
                try {
                    headers.put(f.getName(), f.get(this));
                } catch (IllegalAccessException e) {
                    throw new CEFHandlingException("Error harvesting headers, e");
                }
            }
        }
        return headers;
    }


    /**
     * @param extensions A map containing the keys and values of extensions of CEF event
     * @throws CEFHandlingException when it has issues populating the extensions
     */
    public void setExtension(Map<String, String> extensions) throws CEFHandlingException {
        for (String key : extensions.keySet()) {
            try {
                Field field = objClass.getDeclaredField(key);
                String value = extensions.get(key);

                // If the value is null/empty, let's just move on to the next one
                if(value == null || value.isEmpty()) {
                    continue;
                }

                // Treat each Classes in a particular fashion

                // Inet, Inet4 and Inet6 address
                if (field.getType().equals(InetAddress.class) || field.getType().equals(Inet4Address.class) || field.getType().equals(Inet6Address.class)) {
                    try {
                        InetAddress inetAddress = InetAddress.getByName((String) value);
                        field.set(this, inetAddress);
                    } catch (UnknownHostException e) {
                        throw new CEFHandlingException("Error setting value to field " + key, e);
                    }

                // Date (timestamps) - Note we force a particular date format (set as private dateFormat above
                } else if (field.getType().equals(Date.class)) {
                    try {
                        // Use a ": "to match epoch vs. Dateformat
                        if (!value.toString().contains(":")) {
                            // This is epoch
                            field.set(this, new Date(Long.valueOf(value)));
                        } else {
                            // This is one of the remaining 8 possible values, regex it out...
                            Matcher matcher = timeRegex.matcher(value);

                            if (matcher.matches()) {
                                String year = matcher.group("YEAR") == null ? String.valueOf(Calendar.getInstance().get(Calendar.YEAR)) : matcher.group("YEAR") ;
                                String milli = matcher.group("MILLI") == null ? "000" : matcher.group("MILLI");

                                String regexDate =
                                        year + "-" +
                                        matcher.group("MONTH") + "-" +
                                        matcher.group("DAY") + " " +
                                        matcher.group("HOUR") + ":" +
                                        matcher.group("MINUTE") + ":" +
                                        matcher.group("SECOND") + "." +
                                        milli;
                                if (matcher.group("TZ") == null ) {
                                    field.set(this, dateFormat(false).parse(regexDate));
                                } else {
                                    regexDate = regexDate + " " + matcher.group("TZ");
                                    field.set(this, dateFormat(true).parse(regexDate));
                                }
                            }
                        }
                    } catch (ParseException|NumberFormatException e) {
                        throw new CEFHandlingException("Error setting value to field " + key, e);
                    }

                // Mac Addresses
                } else if (field.getType().equals(MacAddress.class)) {
                    field.set(this, new MacAddress(value));

                // Integers
                } else if (field.getType().equals(int.class)) {
                    field.set(this, Integer.valueOf(value));

                // Longs
                } else if (field.getType().equals(long.class)){
                    field.set(this, Long.valueOf(value));

                // Doubles
                } else if (field.getType().equals(double.class)) {
                    field.set(this, Double.valueOf(value));

                // Floats
                } else if (field.getType().equals(float.class)) {
                    field.set(this, Float.valueOf(value));

                // The rest (to be removed)
                } else {
                    field.set(this, value);
                }

                // Add the key to the populate keys list
                populatedExtensions.add(key);
            } catch (NoSuchFieldException e) {
                customExtensions.put(key, extensions.get(key));
                continue;
            } catch (IllegalAccessException e) {
                throw new CEFHandlingException("Error while setting CEF extension values", e);
            }
        }
    }

    /**
     * @param populatedOnly Boolean defining if Map should include all fields supported by {@link com.fluenda.parcefone.event.CefRev23}
     * @return A map containing the keys and values of CEF extensions
     * @throws CEFHandlingException when it hits issues (e.g. IllegalAccessException) reading the extensions
     */
    public Map<String, Object> getExtension(boolean populatedOnly) throws CEFHandlingException {
        return getExtension(populatedOnly, false);
    }

    /**
     * @param populatedOnly Boolean defining if Map should include all fields supported by {@link com.fluenda.parcefone.event.CefRev23}
     * @param includeCustomExtensions Boolean defining if Map should include parsed keys that are not supported part of the base CEF Rev23 specification
     * @return A map containing the keys and values of CEF extensions
     * @throws CEFHandlingException when it hits issues (e.g. IllegalAccessException) reading the extensions
     */
    public Map<String, Object> getExtension(boolean populatedOnly, boolean includeCustomExtensions) throws CEFHandlingException {

        final HashMap<String, Object> extensions = new HashMap<String, Object>();
        List headersKeys = Arrays.asList(new String[] {"version", "deviceVendor", "deviceProduct", "deviceVersion", "deviceEventClassId", "name", "severity"});

        for (Field f: fields) {
            // Exclude header objects
            if (!headersKeys.contains(f.getName())) {
                // check if populatedOnly was requested

                    try {
                        Object value = f.get(this);
                       if (!populatedOnly){
                            extensions.put(f.getName(), value);
                        } else if (populatedOnly && populatedExtensions.contains(f.getName())) {
                           extensions.put(f.getName(), value);
                       }
                    } catch (IllegalAccessException e) {
                        throw new CEFHandlingException("Error while harvesting keys", e);
                    }
                }
            }
        if (includeCustomExtensions) {
            extensions.putAll(customExtensions);
        }

        return extensions;
    }

    private SimpleDateFormat dateFormat(boolean containsTZ) {

        if (containsTZ) {
            return new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss.SSS zzz", this.dateLocale);
        } else {
            return new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss.SSS", this.dateLocale);
        }
    }



}
