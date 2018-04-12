import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import javax.jmdns.JmDNS;
import javax.jmdns.ServiceEvent;
import javax.jmdns.ServiceListener;

public class ExampleServiceDiscovery {
  private static class SampleListener implements ServiceListener {
    @Override
    public void serviceAdded(final ServiceEvent event) {
      System.out.println("Service added: " + event.getInfo());
    }

    @Override
    public void serviceRemoved(final ServiceEvent event) {
      System.out.println("Service removed: " + event.getInfo());
    }

    @Override
    public void serviceResolved(final ServiceEvent event) {
      System.out.println(event.getInfo());
    }
  }

  public static void main(final String[] args) throws InterruptedException {
    try {
      // Create a JmDNS instance
      final JmDNS jmdns = JmDNS.create(InetAddress.getLocalHost());
      // Add a service listener
      jmdns.addServiceListener("_http._tcp.local.", new SampleListener());
      // Wait a bit
      Thread.sleep(30000);
    } catch (final UnknownHostException e) {
      System.out.println(e.getMessage());
    } catch (final IOException e) {
      System.out.println(e.getMessage());
    }
  }
}
