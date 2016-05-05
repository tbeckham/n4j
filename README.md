# n4j
n4j is a test framework for building and running tests against AWS compatible clouds. It is written in java and is based on the Amazon Java SDK. It is possile to run tests as java applications but TestNG is also supported as a test runner. Test can be written in Java or Groovy.

Prerequisites
------
1. Java (JDK8)

2. apache ant

3. access to a cloud

Installation
------
1. git clone https://github.com/eucalyptus/n4j.git

2. cd n4j

3. ant -Dclcip=your_cloudcontroller_ip -Duser=user_to_log_into_host_as -Dpassword=host_user_password

(The default ant target will download all the dependencies required and run the test suite "AllTestsSuite.xml")

Development
------
1. fork the repository to your own account

2. create branch for your changes

3. submit pull request

The project includes many tests written in both java and groovy. They are in the com/eucalyptus/tests/awssdk/ direcory. There is a sample test "N4jTest.java" that demonstrates the basic test structure for creating a TestNG test. IntelliJ CE works great for an IDE to develope new tests/features with.

How does it work?
------
The most basic element for starting any test is getting an authorized users credentials and making some connections to service endpoints such as ec3, s3, asutoscaling, etc. In order to achieve this for a private cloud such as Eucalyptus, we start by connecting to the Cloud Controller. From there we look to see if the test runner has already created cloud admin creds for itself. If it has, we pull down the ini file and parse it for the info we need. If we do not find test runner created creds, we generate a new key and write out the ini file and we pull that down to consume. Now that the setup can get admin creds anything is possible. It is recommended to create a new account and user in your test(s) and to use that user to perform the tests.
