import java.security.Permission;

public class TestingSecurityManager extends SecurityManager {

    String executed;

    @Override
    public void checkExec (String cmd) {
        executed = cmd;
        System.out.println("Executed: " + cmd);
    }

    @Override
    public void checkPermission (Permission perm) {
        //allow everything
    }

    void assertExec() throws Exception {
        if (executed == null)
            throw new Exception("Runtime.exec() is not executed!");
    }
}
