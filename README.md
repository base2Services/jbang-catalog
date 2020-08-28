# base2Services jbang-catalog

This Repo hold various [J'Bang!](https://github.com/jbangdev/jbang) scripts. You need to have JBang installed to be able to leverage this alias catalog

## Installation
To use jbang Java 11 or higher is recommended.

### SDKMan [linux] / [apple]
To install both java and jbang we recommend sdkman on Linux and OSX.

```bash
curl -s "https://get.sdkman.io" | bash # (1)
source ~/.bash_profile # (2)
```

```bash
sdk install java # (3)
```

Once Java is installed and ready, you install jbang with
```bash
sdk install jbang
```

To test your installation run:
```bash
jbang --help
```

### Running the scripts 

You can run the scripts directly from github uisng the remote catalog features of jbang

```bash
jbang env@base2services
```

The first time you run this it will ask you to trust the remote catalog repo

