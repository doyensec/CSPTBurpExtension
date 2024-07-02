# CSPT - Burp Extension for Client-Site Path Traversal Exploitation

[![Doyensec Research Island](https://img.shields.io/static/v1?logo=data:image/png;base64,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&link=https://doyensec.com/research.html&message=Research%20Island&&label=Doyensec&color=purple)](https://doyensec.com/research.html)


## :rocket: Introduction

Welcome to the **CSPT Burp Suite extension**, a tool that provides advanced capabilities and automation for finding and exploiting Client-Side Path Traversal.

This extension is a Burp Suite Passive Scanner. It reads your proxy history and looks for query parameters reflected inside the path of any other query. Please note that it will not find any DOM-based or stored CSPT until you use the canary token feature.

We appreciate your trust in this extension. Happy testing!

## :star2: Features

The CSPT user interface is equipped with two primary components: the *CSPT* Tab and the *False Positive List*.

### :mag_right: CSPT

This tab is the core of the extension.

#### :mag_right:  How to use it

1. Browse your target application
1. Go to the CSPT tab
2. Verify that the source and sink scopes are correct
3. Check the sink HTTP methods you want to search
4. Click on Scan

#### :crossed_swords:  Understanding the scan results

- The reflected values are on the left. Click one to see the associated sources and the potential sinks.
- To confirm it is not a false positive, you can right-click on a source and use the "Copy URL With Canary" feature. Then copy this URL inside your browser. If this URL triggers a request with the canary token inside the path, it means that a CSPT is present and an issue will be created.
- Instead of testing all the sources one-by-one, you can use the "Export Sources With Canary". It will copy all potential sources with canaries. Then you just need to open all the links with your browser (some browser extensions are able to do that).
- You can also modify or regenerate a new canary token.
- In case some results are false positives, you can discard them. They will not be displayed in the next scan.

#### :crossed_swords:  Finding sinks
If you have identified a CSPT, you will want to find exploitable sinks. The extension can help you to do it by right-clicking on a sink to "Send sinks(host/method) To Organizer".

Note: Now that [Bambdas](https://portswigger.net/blog/introducing-bambdas) are implemented in Burp Proxy, this may be a more convenient way to find sinks.

### :memo: False Positives List
- To discard false positives, you just need to right-click on a source and set either the Parameter or URL as a false positive.
- The "False Positive List" summarizes all defined rules and can be modified.
  
# :arrow_down: Installation
To successfully install the CSPT extension, ensure you meet the following requirements:

Burp:
- Most recent version of "Professional" or "Community" (older versions not supported).

Java:
- The Montoya API needs Java 17 or later.

# :computer: Building the CSPT extension from git

1. Install Java 17+. For example, in Debian-based distros:

```bash
$ sudo apt install -y openjdk-17-jdk
$ java --version
openjdk 17.0.6 2023-01-17
```

2. Clone the repo:

```bash
$ git clone https://github.com/doyensec/CSPTBurpExtension
$ cd CSPTBurpExtension
```

3. Build the CSPT extension:

```bash
$ ./gradlew build
```

Load the file `build/CSPTBurpExtension.jar` into Burp as a Java extension.

# :scroll: Developing

The CSPT Burp Extension uses IntelliJ Forms for its UI. The `.form` files contain the actual UI layouts, while the associated `.java` files are partially auto-generated and the UI methods should not be modified directly, as all modifications are lost at compile time.

While developing, to make sure IntelliJ IDEA generates updated `.java` files, set it as follows:
- Go to `Settings` > `Build, Execution, Deployment` > `Build Tools` > `Gradle` and set `Buiild and run using:` to `IntelliJ IDEA`
- Go to `Settings` > `Editor` > `GUI Designer` and set `Generate GUI into:` to `Java source code`

After editing a form, if the Java file is not generated automatically, click on `Build` > `Recompile <file>.form` while in form editor.

# :handshake: Contributing

CSPT Burp Extension thrives on community contributions. Whether you're a developer, researcher, designer, or bug hunter, your expertise is invaluable to us. We welcome bug reports, feedback, and pull requests. Your participation helps us continue to improve the extension, making it a stronger tool for the community.

Interactions are best carried out through the GitHub issue tracker, but you can also reach us on social media ([@Doyensec](https://twitter.com/Doyensec)). We look forward to hearing from you!

# :busts_in_silhouette: Contributors

A special thanks to our contributors. Your dedication and commitment have been instrumental in making this extension what it is today.

Current:
- **Maintainer:** Maxence Schmitt [@maxenceschmitt (Twitter)](https://twitter.com/maxenceschmitt)
- **Contributor:** Savio Sisco [@lokiuox (Github)](https://github.com/lokiuox)

This project was made with support of [Doyensec](https://doyensec.com/research.html).


![Doyensec Research](docs/doyensec_logo.svg)   


