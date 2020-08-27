//usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.2.0
//DEPS org.jline:jline:3.16.0
//DEPS com.amazonaws:aws-java-sdk-sts:1.11.849
//DEPS com.amazonaws:aws-java-sdk-ec2:1.11.849
//DEPS com.amazonaws:aws-java-sdk-ssm:1.11.849
//DEPS org.bouncycastle:bcprov-jdk12:130

import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.DescribeInstancesRequest;
import com.amazonaws.services.ec2.model.DescribeInstancesResult;
import com.amazonaws.services.ec2.model.Filter;
import com.amazonaws.services.ec2.model.GetPasswordDataRequest;
import com.amazonaws.services.ec2.model.Reservation;
import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.simplesystemsmanagement.*;
import com.amazonaws.services.simplesystemsmanagement.model.*;
import com.amazonaws.util.Base64;

import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.logging.LogManager;
import java.util.stream.Collectors;
import java.io.*;

import javax.crypto.Cipher;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;

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
    final int exitCode = new CommandLine(new awsssm()).addSubcommand("list", new ListInstances())
        .addSubcommand("rdp", new Rdp()).execute(args);
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
    AwsHelper.findRunningInstances().forEach(instances -> instances.forEach((name, instance) -> {
      out.printf("%s - %s\n", instance.getInstanceId(), name);
    }));
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
    out.printf("Starting RDP ssm session on %s\n", instance.getInstanceId());
    copyPasswordToClipboard(instance.getInstanceId());

    final var session = AwsHelper.startSSMSession(instance.getInstanceId(), localPort);
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
    final ProcessBuilder builder = new ProcessBuilder();
    builder.command("open", rdpUrl);
    final var process = builder.start();
  }
}

class AwsHelper {

  public static List<Map<String, Instance>> findRunningInstances() {
    final var ec2 = AmazonEC2ClientBuilder.standard().build();
    final var response = ec2.describeInstances(new DescribeInstancesRequest()
      .withFilters(new Filter("instance-state-name").withValues("running"))
    );
    return response.getReservations()
      .stream()
      .map(r -> r.getInstances().get(0)).map(instance -> {
        final Map<String, Instance> m = new HashMap<>();
        m.put(instance.getTags()
          .stream()
          .filter(tag -> "name".equalsIgnoreCase(tag.getKey()))
          .map(tag -> tag.getValue())
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
    final var ssm = AWSSimpleSystemsManagementClientBuilder.standard().build();
    final var result = ssm.getParameter(new GetParameterRequest()
      .withName(keyPairPath)
      .withWithDecryption(true));
    return result.getParameter().getValue()
      .replace("-----BEGIN RSA PRIVATE KEY-----\n", "")
      .replace("-----END RSA PRIVATE KEY-----", "");
  }

  public static String getWindowsPassword(final String instanceId, final String keypair) throws Exception {
    final var ec2 = AmazonEC2ClientBuilder.standard().build();
    final var result = ec2.getPasswordData(new GetPasswordDataRequest().withInstanceId(instanceId));
    final var passwordData = result.getPasswordData();
    final var spec = new PKCS8EncodedKeySpec(Base64.decode(keypair));
    final var privateKey = KeyFactory.getInstance("RSA").generatePrivate(spec);
    final var rsa = Cipher.getInstance("RSA");
    rsa.init(Cipher.DECRYPT_MODE, privateKey);
    final byte[] cipherText = Base64.decode(passwordData);
    final byte[] plainText = rsa.doFinal(cipherText);
    return new String(plainText, Charset.forName("ASCII"));
  }

  public static Process startSSMSession(final String instanceId, int localPort) throws Exception {
    final ProcessBuilder builder = new ProcessBuilder();
    final var params = "{\"portNumber\":[\"3389\"], \"localPortNumber\":[\"" + localPort + "\"]}";
    builder.command("aws", "ssm", "start-session", "--document-name=AWS-StartPortForwardingSession", "--target=" + instanceId, "--parameters=" + params);
    final var process = builder.start();
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