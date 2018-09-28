
import org.xbill.DNS.*;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.*;

public class mydigsec {
    private static int nsIndex = 0;
    private static int msgSize = 0;
    private static List<String> nameServerList;
    private static List<Record> finalAnswerList;
    private static List<Record> finalAuthorityList;
    public static void main(String[] args) {
        String domainToQuery = "";
        String typeOfRecordString = "";
        int typeOfRecord = -1;
        // Parse the arguments
        if (args.length > 2) {
            System.out.println("Unknown Arguments");
            return;
        }
        else if (args.length == 2) {
            domainToQuery = args[0];
            typeOfRecordString = args[1];
        }
        else if (args.length == 1) {
            domainToQuery = args[0];
            typeOfRecordString = "A";
        }
        else {
            System.out.println("Too few arguments");
            return;
        }

        switch (typeOfRecordString) {
            case "A":
            case "a":
                typeOfRecord = Type.A;
                break;
            case "MX":
            case "mx":
                typeOfRecord = Type.MX;
                break;
            case "NS":
            case "ns":
                typeOfRecord = Type.NS;
                break;
        }
        createNameServerList();
        fetchDNSQuery(domainToQuery, nameServerList.get(nsIndex), typeOfRecord);
        //fetchDNSQuery("www.dnssec-failed.org", nameServerList.get(nsIndex));
    }

    private enum TypeOfQuery {
        ORIGINAL,
        CNAME,
        NS
    }

    /**
     * Function to query for a domain name and print the answer
     * @param dnsquery The domain name to be queried
     * @param nsIp The nameserver ip address
     * @param requestedType The type of query we are requesting
     */
    private static void fetchDNSQuery(String dnsquery, String nsIp, int requestedType){
        finalAnswerList = new ArrayList<>();
        finalAuthorityList = new ArrayList<>();
        Date date = new Date();
        long startTime = System.nanoTime();
        String gfd = resolveQuery(dnsquery, nsIp, TypeOfQuery.ORIGINAL, requestedType);
        long estimatedTime = (System.nanoTime() - startTime)/1000000;
        System.out.println(gfd);
        if (!Objects.equals(gfd, "")) {
            printRecords(dnsquery, date, estimatedTime, requestedType);
        }
    }

    private static String getDClassName(Record record) {
        switch (record.getDClass()) {
            case DClass.IN: return "IN";
            case DClass.ANY: return "ANY";
            case DClass.CH: return "CH";
            case DClass.HS: return "HS";
            case DClass.NONE: return "NONE";
            default: return "";
        }
    }

    /**
     * Print the answer to the dns query
     * @param dnsquery The web address that we requested dns resolution for
     * @param currentDate The date when the resolution was requested
     * @param queryTime The time it took to resolve the wuery
     */
    private static void printRecords(String dnsquery, Date currentDate, long queryTime, int requestedType) {
        String requestedTypeString = "";
        if (requestedType == Type.A) {
            requestedTypeString = "A";
        }
        else if (requestedType == Type.MX) {
            requestedTypeString = "MX";
        }
        else if (requestedType == Type.NS) {
            requestedTypeString = "NS";
        }
        System.out.println("; <<>> My Dig Tool <<>> " + dnsquery);
        System.out.println(";; QUESTION SECTION:");
        System.out.println(";" + dnsquery + ".\t\tIN\t" + requestedTypeString);

        if (finalAnswerList.size() > 0) {
            System.out.println(";; ANSWER SECTION:");
            for (Record record : finalAnswerList) {
                switch (record.getType()) {
                    case Type.A:
                        String currentIp = ((ARecord) record).getAddress().toString();
                        currentIp = currentIp.substring(currentIp.lastIndexOf('/') + 1);
                        System.out.println(record.getName() + "\t" + record.getTTL() + "\t" + getDClassName(record) + "\t" + "A\t" + currentIp);
                        break;
                    case Type.CNAME:
                        System.out.println(record.getName() + "\t" + record.getTTL() + "\t" + getDClassName(record) + "\t" + "CNAME\t" + ((CNAMERecord) record).getAlias().toString());
                        break;
                    case Type.MX:
                        System.out.println(record.getName() + "\t" + record.getTTL() + "\t" + getDClassName(record) + "\t" + "MX\t" + record.getAdditionalName().toString());
                        break;
                    case Type.NS:
                        System.out.println(record.getName() + "\t" + record.getTTL() + "\t" + getDClassName(record) + "\t" + "NS\t" + record.getAdditionalName().toString());
                        break;
                }
            }
        }

        if (finalAuthorityList.size() > 0) {
            System.out.println(";; AUTHORITY SECTION:");
            for (Record record : finalAuthorityList) {
                switch (record.getType()) {
                    case Type.A:
                        String currentIp = ((ARecord) record).getAddress().toString();
                        currentIp = currentIp.substring(currentIp.lastIndexOf('/') + 1);
                        System.out.println(record.getName() + "\t" + record.getTTL() + "\t" + getDClassName(record) + "\t" + "A\t" + currentIp);
                        break;
                    case Type.CNAME:
                        System.out.println(record.getName() + "\t" + record.getTTL() + "\t" + getDClassName(record) + "\t" + "CNAME\t" + ((CNAMERecord) record).getAlias().toString());
                        break;
                    case Type.MX:
                        System.out.println(record.getName() + "\t" + record.getTTL() + "\t" + getDClassName(record) + "\t" + "MX\t" + record.getAdditionalName().toString());
                        break;
                    case Type.SOA:
                        SOARecord soaRecord = (SOARecord) record;
                        System.out.println(record.getName() + "\t" + record.getTTL() + "\t" + getDClassName(record) + "\t" + "SOA\t"
                                + soaRecord.getHost().toString() + " " + soaRecord.getAdmin().toString() + " " + soaRecord.getSerial()
                                + " " + soaRecord.getRefresh() + " " + soaRecord.getRetry() + " " + soaRecord.getExpire() + " " + soaRecord.getMinimum());
                        break;
                    case Type.NS:
                        System.out.println(record.getName() + "\t" + record.getTTL() + "\t" + getDClassName(record) + "\t" + "NS\t" + record.getAdditionalName().toString());
                        break;
                }
            }
        }

        System.out.println("\n;; Query time: " + queryTime + " msec");
        System.out.println(";; SERVER: " + nameServerList.get(nsIndex));
        System.out.println(";; WHEN: " + currentDate);
        System.out.println(";; MSG SIZE  rcvd: " + msgSize);
    }

    /**
     * This function creates an array list for the name servers in https://www.iana.org/domains/root/servers
     */
    private static void createNameServerList() {
        nameServerList = new ArrayList<>();
        nameServerList.add("198.41.0.4");
        nameServerList.add("199.9.14.201");
        nameServerList.add("192.33.4.12");
        nameServerList.add("199.7.91.13");
        nameServerList.add("192.203.230");
        nameServerList.add("192.5.5.241");
        nameServerList.add("192.112.36.4");
        nameServerList.add("198.97.190.53");
        nameServerList.add("192.36.148.17");
        nameServerList.add("192.58.128.30");
        nameServerList.add("193.0.14.129");
        nameServerList.add("199.7.83.42");
        nameServerList.add("202.12.27.33");
    }

    /**
     * This function verifies if DNSSEC is working for the dns query we made
     * @param allrrsets
     * @return True if DNSSEC works, False if it doesn't work and NULL if it is not supported
     * @throws IOException
     * @throws DNSSEC.DNSSECException
     */
    private static Boolean verifydnsec(RRset[] allrrsets) throws IOException, DNSSEC.DNSSECException {
        Boolean dnsVerified = false;
        Boolean nosigs = false;
        for(RRset currentRRset: allrrsets) {
            if (currentRRset.sigs().hasNext()) {
                nosigs = true;
            }
        }
        if (nosigs == false) {
            return null;
        }

        // Go through the RRSets and get the DNS KEY for each signer
        for(RRset currentRRset: allrrsets) {
            Iterator<Record> sigIter = currentRRset.sigs();
            while (sigIter.hasNext()) {
                final RRSIGRecord rec = (RRSIGRecord) sigIter.next();
                Name signer = rec.getSigner();
                int footprint = rec.getFootprint();

                DNSKEYRecord dnskey = null;
                Record dnskeyrec = Record.newRecord(signer, Type.DNSKEY, DClass.IN);
                Message dnskeyquery = Message.newQuery(dnskeyrec);
                ExtendedResolver dnskeyResolver = new ExtendedResolver();
                dnskeyResolver.setEDNS(0,0,ExtendedFlags.DO,null);
                Message dnskeyresp = dnskeyResolver.send(dnskeyquery);
                RRset[] dnskeyrrsets = dnskeyresp.getSectionRRsets(Section.ANSWER);
                for (RRset dnskeyrrset: dnskeyrrsets) {
                    Iterator<Record> rrIter = dnskeyrrset.rrs();
                    while (rrIter.hasNext()) {
                        Record dnskeyRecordItem = rrIter.next();
                        if (dnskeyRecordItem instanceof DNSKEYRecord) {
                            DNSKEYRecord dnskeyRecord = (DNSKEYRecord)dnskeyRecordItem;
                            if (dnskeyRecord.getFootprint() == footprint) {
                                dnskey = dnskeyRecord;
                                dnsVerified = true;
                            }
                        }
                    }

                    // Verify the footprint of the signer and the signer of the DNS KEY
                    Iterator<Record> sigdnsIter = dnskeyrrset.sigs();
                    while (sigdnsIter.hasNext()) {
                        RRSIGRecord dnskeySigRec = (RRSIGRecord)sigdnsIter.next();
                        if (dnskeySigRec.getFootprint() == footprint) {
                            DNSSEC.verify(dnskeyrrset, dnskeySigRec, dnskey);
                        }
                    }

                }




            }
        }
        return dnsVerified;
    }

    /**
     * The function which does the actual dns resolution. This function gets called recursively to resolve an address
     * @param dnsquery The dns query which is requested
     * @param nsIp The Name server to direct the query to
     * @param queryType The type of query in the current stage of resolution
     * @param requestedType The type of query which was requested
     * @return
     */
    private static String resolveQuery(String dnsquery, String nsIp, TypeOfQuery queryType, int requestedType){
        List<String> nextNStoQuery = new ArrayList<>();
        List<String> nextNS = new ArrayList<>();
        List<String> nextCName = new ArrayList<>();
        try {
            Name name = Name.fromString(dnsquery, Name.root);
            Record rec = Record.newRecord(name, requestedType, DClass.IN);
            Boolean returnFlag = Boolean.FALSE;
            Message query = Message.newQuery(rec);
            SimpleResolver resolver = new SimpleResolver(nsIp);
            resolver.setEDNS(0, 0, ExtendedFlags.DO, null);
            Message response = resolver.send(query);
            Record[] ansrecords = response.getSectionArray(Section.ANSWER);
            Record[] authority = response.getSectionArray(Section.AUTHORITY);
            Record[] additionalrecords = response.getSectionArray(Section.ADDITIONAL);
            RRset[] ansrrsets = response.getSectionRRsets(Section.ANSWER);
            RRset[] authrrsets = response.getSectionRRsets(Section.AUTHORITY);
            if (ansrrsets.length > 0 || authrrsets.length > 0) {
                Boolean verifyStatus = Boolean.FALSE;
                // Verify whether DNSSEC is working
                if (ansrrsets.length > 0) {
                    verifyStatus = verifydnsec(ansrrsets);
                }
                if (verifyStatus == Boolean.FALSE && authrrsets.length > 0) {
                    verifyStatus = verifydnsec(authrrsets);
                }

                // If return status is NULL, exit the program since DNSSEC is not supported
                if (verifyStatus == null) {
                    System.out.println("DNSSEC Not supported");
                    return "";
                }

                // If DNSSEC is supported, but return status is false, exit the program because the verification failed.
                if (verifyStatus == Boolean.FALSE) {
                    System.out.println("DNSSEC verification failed");
                    return "";
                }
                else {
                    // Resolve the query because DNSSEC verification succeeeded
                    Boolean ipflag = Boolean.FALSE;
                    String currentIpAddr = "";

                    // Go through the answer records and add the result to the final answer list
                    for(Record record: ansrecords) {
                        switch (record.getType()) {
                            case Type.A:
                                if (ipflag == Boolean.FALSE) {
                                    currentIpAddr = ((ARecord) record).getAddress().toString();
                                    currentIpAddr = currentIpAddr.substring(currentIpAddr.lastIndexOf('/') + 1);
                                    ipflag = Boolean.TRUE;
                                    msgSize = response.numBytes();
                                }

                                if ((queryType == TypeOfQuery.CNAME || queryType == TypeOfQuery.ORIGINAL) && requestedType == Type.A) {
                                    finalAnswerList.add(record);
                                }
                                break;
                            case Type.CNAME:
                                String currentName = ((CNAMERecord)record).getAlias().toString();
                                currentName = currentName.substring(0, currentName.length() - 1);
                                if ((queryType == TypeOfQuery.CNAME || queryType == TypeOfQuery.ORIGINAL) && requestedType == Type.CNAME) {
                                    finalAnswerList.add(record);
                                }
                                nextCName.add(currentName);
                                break;
                            case Type.MX:
                                if (ipflag == Boolean.FALSE) {
                                    currentIpAddr = record.getAdditionalName().toString();
                                    currentIpAddr = currentIpAddr.substring(0, currentIpAddr.length() - 1);
                                    ipflag = Boolean.TRUE;
                                    msgSize = response.numBytes();
                                }

                                if ((queryType == TypeOfQuery.ORIGINAL) && requestedType == Type.MX) {
                                    finalAnswerList.add(record);
                                }
                                //return currentMxName;
                            case Type.NS:
                                if (ipflag == Boolean.FALSE) {
                                    currentIpAddr = record.getAdditionalName().toString();
                                    currentIpAddr = currentIpAddr.substring(0, currentIpAddr.length() - 1);
                                    ipflag = Boolean.TRUE;
                                    msgSize = response.numBytes();
                                }
                                if ((queryType == TypeOfQuery.ORIGINAL) && requestedType == Type.NS) {
                                    finalAnswerList.add(record);
                                }
                                //nextNS.add(currentName.toLowerCase());
                                break;

                        }

                    }
                    if (ipflag == Boolean.TRUE) {
                        return currentIpAddr;
                    }

                    // Go through the authority list to find the next name server to direct the query at
                    for(Record record: authority) {
                        switch (record.getType()) {
                            case Type.A:
                                String currentIp = ((ARecord) record).getAddress().toString();
                                currentIp = currentIp.substring(currentIp.lastIndexOf('/') + 1);
                                nextNStoQuery.add(currentIp);
                                break;
                            case Type.NS:
                                String currentName = record.getAdditionalName().toString();
                                currentName = currentName.substring(0, currentName.length() - 1);
                                nextNS.add(currentName);
                                break;
                            case Type.SOA:
                                if ((queryType == TypeOfQuery.NS || queryType == TypeOfQuery.ORIGINAL) && requestedType == Type.NS) {
                                    finalAuthorityList.add(record);
                                    msgSize = response.numBytes();
                                    return "";
                                }
                        }
                    }

                    // Match the name server to its IP address from the additional records
                    if (nextNStoQuery.size() == 0) {
                        for(Record record: additionalrecords) {
                            switch (record.getType()) {
                                case Type.A:
                                    String currentName = record.getName().toString();
                                    currentName = currentName.substring(0, currentName.length() - 1);
                                    if (nextNS.contains(currentName)) {
                                        String currentIp = ((ARecord) record).getAddress().toString();
                                        currentIp = currentIp.substring(currentIp.lastIndexOf('/') + 1);

                                        nextNStoQuery.add(currentIp);
                                    }
                                    break;
                                case Type.NS:
                                    nextNS.add(record.getName().toString());
                                    break;

                            }
                        }
                    }

                    // If we got a CNAME in the current stage of resolution, resolve the CNAME with the same name server
                    if (nextCName.size() > 0) {
                        return resolveQuery(nextCName.get(0), nameServerList.get(nsIndex), TypeOfQuery.CNAME, requestedType);
                    }
                    // If we got a new name server to query, direct the next query to this name server
                    else if (nextNStoQuery.size() > 0) {
                        return resolveQuery(dnsquery, nextNStoQuery.get(0), queryType, requestedType);
                    }
                    // If we only have the name of the name server, resolve that first and then resolve the query
                    else if (nextNStoQuery.size() == 0 && nextNS.size() > 0) {
                        String cde = resolveQuery(nextNS.get(0), nameServerList.get(nsIndex), TypeOfQuery.NS, requestedType);
                        return resolveQuery(dnsquery, cde, queryType, requestedType);
                    }
                }
            }
            else {
                System.out.println("DNSSEC is not Supported");
                return "";
            }



        } catch (Exception ex) {
            if (nsIndex < 12) {
                nsIndex++;
                System.out.println("Retrying with " + nameServerList.get(nsIndex) + " for site " + dnsquery);
            }
            else {
                nsIndex = 0;
            }
            fetchDNSQuery(dnsquery, nameServerList.get(nsIndex), requestedType);
        }
        return "";
    }
}
