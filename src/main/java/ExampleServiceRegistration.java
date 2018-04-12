import java.io.IOException;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.jmdns.JmDNS;
import javax.jmdns.ServiceInfo;

import org.kohsuke.randname.RandomNameGenerator;

public class ExampleServiceRegistration {
  public static void main(final String[] args) throws InterruptedException {
    JmDNS jmdns = null;
    try {
      // Create a JmDNS instance
      jmdns = JmDNS.create(InetAddress.getLocalHost());
      final Map<String, String> props = new HashMap<>();
      props.put("sofa_version", "5.0.0");
      props.put("accepted_kids", "kid0,kid1,kid2");
      props.put("available_interfaces", "com.zoloz.Iface0,com.zoloz.Iface1");
      final Random random = new SecureRandom();
      final RandomNameGenerator rnd = new RandomNameGenerator(random.nextInt());
      final String name = rnd.next();
      System.out.println(name);
      // Register a service
      final ServiceInfo serviceInfo = ServiceInfo.create("_http._tcp.local.", name, 8080, 100, 100, props);
      jmdns.registerService(serviceInfo);
      // Wait a bit
      // Unregister all services
      Thread.sleep(7000);
    } catch (final IOException e) {
      System.out.println(e.getMessage());
    } finally {
      try {
        jmdns.unregisterAllServices();
        jmdns.close();
      } catch (final IOException e) {
        throw new RuntimeException(e);
      }
    }
  }
}
