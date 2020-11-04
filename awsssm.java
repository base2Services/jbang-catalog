//usr/bin/env jbang "$0" "$@" ; exit $?
//JAVA 11
//DEPS info.picocli:picocli:4.2.0
//DEPS org.jline:jline:3.16.0
//DEPS software.amazon.awssdk:ec2:2.14.5
//DEPS software.amazon.awssdk:ssm:2.14.5
//DEPS org.bouncycastle:bcprov-jdk12:130
//DEPS org.slf4j:slf4j-nop:1.7.25


import java.awt.Toolkit;
import java.awt.Desktop;
import java.awt.datatransfer.StringSelection;
import java.io.*;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.logging.LogManager;
import java.util.stream.Collectors;

import javax.crypto.Cipher;

import com.fasterxml.jackson.databind.deser.impl.ExternalTypeHandler.Builder;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;

import org.bouncycastle.util.encoders.Base64;

import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.*;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.*;

import static java.lang.System.*;
import static java.lang.System.getProperties;
import static java.lang.System.out;


import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.spec.PKCS8EncodedKeySpec;


@Command(name = "properties", mixinStandardHelpOptions = true, version = "awsssm 0.1",
        description = "AWS SSM Session Tunnel Manager")
public class awsssm implements Callable<Integer> {

  public static void main(final String... args) {
    LogManager.getLogManager().reset();
    java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    final int exitCode = new CommandLine(new awsssm())
      .addSubcommand("list", new ListInstances())
      .addSubcommand("rdp", new Rdp())
      .execute(args);
    exit(exitCode);
  }

  @Spec
  CommandSpec spec;

  @Override
  public Integer call() throws Exception {
    out.println("here");
    return 0;
  }
}

@Command(name = "list", aliases = { "ls" }, description = "Lists running instances")
class ListInstances implements Callable<Integer> {

  @Override
  public Integer call() throws Exception {
    AwsHelper.findRunningInstances()
      .forEach(instances -> instances
        .forEach((name, instance) -> {
          out.printf("%s - %s\n", instance.instanceId(), name);
        }
    ));
    return 0;
  }
}

@Command(name = "rdp", description = "Starts SSM Session for RDP for windows instances")
class Rdp implements Callable<Integer> {

  @Option(names = { "-i", "--instance" }, description = "instance name or instance Id")
  String instanceName;

  @Option(names = { "-k", "--keypair" }, description = "ssm path to the ec2 keypair")
  String keyPairPath;

  @Option(names = {"-p", "--port"}, description = "local rdp port default to random port")
  int localPort =  (new Random().nextInt(59999 - 50000)) + 50000;

  @Override
  public Integer call() throws Exception {
    final Instance instance = AwsHelper.findInstanceByName(instanceName);
    out.printf("Starting RDP ssm session on %s\n", instance.instanceId());
    copyPasswordToClipboard(instance.instanceId());

    final var session = AwsHelper.startSSMSession(instance.instanceId(), localPort);
    Thread.sleep(10000);
    openRDP();

    session.waitFor();
    return 0;
  }

  private void copyPasswordToClipboard(String instanceId) throws Exception {
    final String keypair = AwsHelper.loadKeyPairFromSSM(keyPairPath);
    final String password = AwsHelper.getWindowsPassword(instanceId, keypair);
    final var clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
    clipboard.setContents(new StringSelection(password), null);
    out.println("Copied password to clipboard");
  }

  private void openRDP() throws Exception {
    var rdpUrl = "rdp://full%20address=s:localhost:" + localPort + "&audiomode=i:2&disable%20themes=i:1&username=s:Administrator&prompt%20for%20credentials%20on%20client=i:1";
    out.println("open " + rdpUrl);
    final var process = new ProcessBuilder()
      .command("open", rdpUrl)
      .start();
  }
}

class AwsHelper {

  public static List<Map<String, Instance>> findRunningInstances() {
    final var ec2 = Ec2Client.create();
    final var response = ec2.describeInstances(
      DescribeInstancesRequest.builder()
        .filters(
          Filter.builder()
            .name("instance-state-name")
            .values("running").build()
        )
        .build()
    );
    return response.reservations()
      .stream()
      .map(r -> r.instances().get(0)).map(instance -> {
        final Map<String, Instance> m = new HashMap<>();
        m.put(instance.tags()
          .stream()
          .filter(tag -> "name".equalsIgnoreCase(tag.key()))
          .map(tag -> tag.value())
          .collect(Collectors.joining(","))
          , instance);
      return m;
    }).collect(Collectors.toList());
  }

  public static Instance findInstanceByName(final String instanceName) {
    return findRunningInstances()
      .stream()
      .filter(x -> x.containsKey(instanceName))
      .map(x -> x.get(instanceName))
      .findFirst().get();
  }

  public static String loadKeyPairFromSSM(final String keyPairPath) {
    final var ssm = SsmClient.create();
    final var result = ssm.getParameter(GetParameterRequest.builder()
      .name(keyPairPath)
      .withDecryption(true)
      .build());
    return result.parameter().value()
      .replace("-----BEGIN RSA PRIVATE KEY-----\n", "")
      .replace("-----END RSA PRIVATE KEY-----", "");
  }

  public static String getWindowsPassword(final String instanceId, final String keypair) throws Exception {
    final var ec2 = Ec2Client.create();
    var result = ec2.getPasswordData(GetPasswordDataRequest.builder()
      .instanceId(instanceId)
      .build());
    var passwordData = result.passwordData();

    var spec = new PKCS8EncodedKeySpec(Base64.decode(keypair));
    var privateKey = KeyFactory.getInstance("RSA").generatePrivate(spec);
    var rsa = Cipher.getInstance("RSA");
    rsa.init(Cipher.DECRYPT_MODE, privateKey);
    byte[] cipherText = Base64.decode(passwordData);
    byte[] plainText = rsa.doFinal(cipherText);
    return new String(plainText, Charset.forName("ASCII"));
  }

  public static Process startSSMSession(final String instanceId, int localPort) throws Exception {
    final var params = "{\"portNumber\":[\"3389\"], \"localPortNumber\":[\"" + localPort + "\"]}";
    final var process = new ProcessBuilder()
      .command("aws", "ssm", "start-session", "--document-name=AWS-StartPortForwardingSession", "--target=" + instanceId, "--parameters=" + params)
      .start();
    final var streamGobbler = new StreamGobbler(process.getInputStream(), out::println);
    Executors.newSingleThreadExecutor().submit(streamGobbler);
    return process;
  }
}

class StreamGobbler implements Runnable {
  private final InputStream inputStream;
  private final Consumer<String> consumer;

  public StreamGobbler(final InputStream inputStream, final Consumer<String> consumer) {
      this.inputStream = inputStream;
      this.consumer = consumer;
  }

  @Override
  public void run() {
      new BufferedReader(new InputStreamReader(inputStream)).lines()
        .forEach(consumer);
  }
}
