package artsploit;

import artsploit.annotations.LdapMapping;
import artsploit.controllers.LdapController;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.ReadOnlySearchRequest;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.Socket;
import org.reflections.Reflections;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.lang.reflect.Constructor;
import java.net.InetAddress;
import java.util.Set;
import java.util.TreeMap;

class LdapServer extends InMemoryOperationInterceptor {

    TreeMap<String, LdapController> routes = new TreeMap<>();

    public static void start() {
        try {
            System.out.println("Starting LDAP server on 0.0.0.0:" + Config.ldapPort);
            InMemoryDirectoryServerConfig serverConfig = new InMemoryDirectoryServerConfig("dc=example,dc=com");
            serverConfig.setListenerConfigs(new InMemoryListenerConfig(
                    "listen",
                    InetAddress.getByName("0.0.0.0"),
                    Config.ldapPort,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));

            serverConfig.addInMemoryOperationInterceptor(new LdapServer());
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(serverConfig);
            ds.startListening();
        }
        catch ( Exception e ) {
            e.printStackTrace();
        }
    }

    public LdapServer() throws Exception {

        //find all classes annotated with @LdapMapping
        Set<Class<?>> controllers = new Reflections(this.getClass().getPackage().getName())
                .getTypesAnnotatedWith(LdapMapping.class);

        //instantiate them and store in the routes map
        for(Class<?> controller : controllers) {
            Constructor<?> cons = controller.getConstructor();
            LdapController instance = (LdapController) cons.newInstance();
            String[] mappings = controller.getAnnotation(LdapMapping.class).uri();
            for(String mapping : mappings) {
                if(mapping.startsWith("/"))
                    mapping = mapping.substring(1); //remove first forward slash

                System.out.printf("Mapping ldap://%s:%s/%s to %s\n",
                        Config.hostname, Config.ldapPort, mapping, controller.getName());
                routes.put(mapping, instance);
            }
        }
    }

    /**
     * {@inheritDoc}
     *
     * @see com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor#processSearchResult(com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult)
     */
    @Override
    public void processSearchResult(InMemoryInterceptedSearchResult result) {
        ReadOnlySearchRequest request = result.getRequest();
        System.out.println("request: from: " + getRemoteAddress(result) + " " + request);
        String base = request.getBaseDN();
        System.out.println("base: " + base);
        LdapController controller = null;
        //find controller
        for(String key: routes.keySet()) {
            // compare using contains
            if (base.contains(key) && key.length() > 0 || key.equals(base)) {
                controller = routes.get(key);
                break;
            }
        }
        if (controller == null) {
            System.out.println("No controller for base '" + base + "', falling back to default.");
            controller = routes.get("");
        }
        try {
            controller.sendResult(result, base);
        } catch (Exception e1) {
            e1.printStackTrace();
        }
    }

    // uses reflection to get the remote address of the client
    // since the required method isn't available on the public API
    private String getRemoteAddress(InMemoryInterceptedSearchResult result) {
        if (getSocketMethod == null || getClientConnectionMethod == null) {
            return null;
        }
        try {
            Socket clientConnection = (Socket) getSocketMethod.invoke(getClientConnectionMethod.invoke(result));
            return clientConnection.getRemoteSocketAddress().toString();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static Method getClientConnectionMethod;
    private static Method getSocketMethod;

    static {
        Class<?> interceptedOperationClazz = null;
        try {
            interceptedOperationClazz = Class.forName("com.unboundid.ldap.listener.interceptor.InterceptedOperation");
            getClientConnectionMethod = interceptedOperationClazz.getDeclaredMethod("getClientConnection");
            getClientConnectionMethod.setAccessible(true);
            getSocketMethod = getClientConnectionMethod.getReturnType().getDeclaredMethod("getSocket");
            getSocketMethod.setAccessible(true);
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            e.printStackTrace();
        }
    }
}
