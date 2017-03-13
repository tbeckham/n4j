package com.eucalyptus.tests.awssdk

import com.amazonaws.AmazonServiceException
import com.amazonaws.ClientConfiguration
import com.amazonaws.auth.AWSCredentials
import com.amazonaws.auth.AWSCredentialsProvider
import com.amazonaws.auth.AnonymousAWSCredentials
import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.auth.BasicSessionCredentials
import com.amazonaws.internal.StaticCredentialsProvider
import com.amazonaws.services.ec2.AmazonEC2
import com.amazonaws.services.ec2.AmazonEC2Client
import com.amazonaws.services.ec2.model.CreateSecurityGroupRequest
import com.amazonaws.services.ec2.model.DeleteSecurityGroupRequest
import com.amazonaws.services.ec2.model.DescribeSecurityGroupsResult
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClient
import com.amazonaws.services.identitymanagement.model.CreateOpenIDConnectProviderRequest
import com.amazonaws.services.identitymanagement.model.CreateRoleRequest
import com.amazonaws.services.identitymanagement.model.DeleteOpenIDConnectProviderRequest
import com.amazonaws.services.identitymanagement.model.DeleteRolePolicyRequest
import com.amazonaws.services.identitymanagement.model.DeleteRoleRequest
import com.amazonaws.services.identitymanagement.model.GetOpenIDConnectProviderRequest
import com.amazonaws.services.identitymanagement.model.PutRolePolicyRequest
import com.amazonaws.services.s3.AmazonS3
import com.amazonaws.services.s3.AmazonS3Client
import com.amazonaws.services.s3.S3ClientOptions
import com.amazonaws.services.s3.model.CannedAccessControlList
import com.amazonaws.services.s3.model.ObjectMetadata
import com.amazonaws.services.s3.model.PutObjectRequest
import com.amazonaws.services.securitytoken.AWSSecurityTokenService
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient
import com.amazonaws.services.securitytoken.model.AssumeRoleWithWebIdentityRequest
import com.github.sjones4.youcan.youprop.YouProp
import com.github.sjones4.youcan.youprop.YouPropClient
import com.github.sjones4.youcan.youprop.model.DescribePropertiesRequest
import com.github.sjones4.youcan.youprop.model.ModifyPropertyValueRequest
import org.testng.annotations.AfterClass
import org.testng.annotations.Test

import static com.eucalyptus.tests.awssdk.N4j.getCloudInfo
import static com.eucalyptus.tests.awssdk.N4j.CLC_IP
import static com.eucalyptus.tests.awssdk.N4j.ACCESS_KEY
import static com.eucalyptus.tests.awssdk.N4j.SECRET_KEY
import static com.eucalyptus.tests.awssdk.N4j.NAME_PREFIX


import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import javax.xml.bind.DatatypeConverter
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.RSAPrivateKeySpec

/**
 * Test STS AssumeRoleWithWebIdentity action for OpenID Connect providers.
 *
 * Related issues:
 *   https://eucalyptus.atlassian.net/browse/EUCA-12564
 *   https://eucalyptus.atlassian.net/browse/EUCA-12566
 *   https://eucalyptus.atlassian.net/browse/EUCA-12717
 *   https://eucalyptus.atlassian.net/browse/EUCA-13007
 *
 * Related AWS doc:
 *   http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html
 *   http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html
 *   http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#condition-keys-wif
 */
class TestSTSAssumeRoleWithWebIdentity {

  private final String host
  private final String path
  private final String domainAndPort
  private final String domain
  private final String thumbprint
  private final String testAcct
  private final String testUser
  private final AWSCredentialsProvider credentials
  private final AWSCredentialsProvider adminCredentials

  // arbitrary values for oidc registration / identity
  private final String aud = 'c6845610-9b57-4386-a1c4-7ffe45d03c92'
  private final String sub = '7277dd17-cc4e-4b24-8830-ccdafca56241'
  private final String altAud = '08493485-7ad5-4f3a-8de3-bc746d9c5c5b'
  private final String altSub = 'f64a0a9b-57af-4b2b-9967-1e0a8b51a40d'
  private final String kid = 'edec04463e2049969f3bf45bf17bb1f3'

  // oidc provider private key
  private final Integer exponent = 65537
  private final String modulus = '''\
      00:cd:6a:17:66:19:4a:e1:40:0b:a4:26:93:5a:25:
      3b:56:9c:34:d8:7c:a9:e8:92:6b:d4:55:6c:a1:a4:
      06:de:18:51:5d:c6:30:1b:ac:cc:fe:b5:79:2b:dd:
      75:f7:f4:83:77:9f:4a:55:e4:0f:4c:c6:ee:e8:07:
      7c:e9:1c:fd:56:84:a8:e6:59:de:ce:4f:7b:b1:ad:
      f4:21:ca:e8:65:46:a9:36:c8:71:8f:af:f6:1c:58:
      89:f7:b8:54:86:4f:64:e3:67:04:65:fe:02:9a:60:
      f9:74:8d:f3:5a:00:c3:02:43:be:51:2e:7d:53:99:
      cd:07:99:0c:13:f6:a9:dc:70:06:63:99:bd:de:a7:
      bb:6d:31:8a:d3:d1:3e:56:ad:25:64:4e:fe:e6:46:
      32:db:a3:6d:02:7e:f1:42:d1:ed:1a:91:82:27:cc:
      80:67:96:de:b2:9b:5a:93:33:f7:5c:e8:e7:e7:3c:
      03:4d:53:38:57:91:b1:52:92:c2:57:c4:71:aa:85:
      4a:75:82:37:b6:dc:a7:7f:42:c6:58:c1:1e:21:87:
      6c:fc:3c:22:fa:94:1e:56:b2:7b:f8:c2:b8:bc:90:
      ec:ce:fb:95:f4:77:c5:9e:6d:51:d6:e9:70:ea:08:
      89:cc:82:18:22:91:85:29:88:f6:45:7b:9e:d1:0c:
      3b:97'''.stripIndent()
  private final String privateExponent = '''\
      30:87:5e:ed:cd:0d:e6:b7:55:c8:bb:20:56:cc:b2:
      ff:1c:3a:53:e6:e7:d1:3d:3e:62:54:a8:2c:6b:ee:
      ff:6b:69:55:a9:2b:d6:6d:f5:a4:3b:45:5c:3a:9e:
      d3:2c:9e:1e:95:b0:5f:28:59:00:ff:82:93:a8:a9:
      36:fd:95:50:6a:58:e8:ca:d4:9b:93:25:9a:ed:88:
      de:ae:ec:46:78:f2:23:32:29:ba:13:8d:26:57:38:
      89:20:b0:3f:66:e4:63:e1:03:a6:00:e3:a6:8b:40:
      83:eb:c1:51:43:1a:cf:1f:28:08:4f:de:65:f0:d1:
      02:79:82:e3:f8:83:5a:c3:63:f4:d8:62:72:52:61:
      10:ad:36:f6:89:88:fb:a0:7c:ec:9b:b3:76:14:8c:
      68:67:4e:2e:de:6c:58:b1:dc:9b:43:44:1c:b0:5e:
      74:1f:42:3d:3e:61:7b:e9:72:89:7f:0d:6d:99:6a:
      0e:ad:07:66:04:a1:61:73:4d:81:d2:00:cd:35:43:
      bb:f5:75:c6:d9:3f:67:15:11:12:ae:ae:f0:83:5a:
      0f:45:2f:b9:9a:0b:58:5b:d7:cf:b1:1c:f9:e3:f8:
      7d:9f:4d:20:49:ec:8a:46:8a:ec:99:dc:5d:20:8b:
      3e:5a:d5:df:da:dc:07:e0:71:77:1e:69:65:d4:e3:
      79
    '''.stripIndent()
  private final byte[] modulusBytes =
      new BigInteger(modulus.replace(':', '').replace('\n', ''), 16).toByteArray()
  private final byte[] privateExponentBytes =
      new BigInteger(privateExponent.replace(':', '').replace('\n', ''), 16).toByteArray()

  public TestSTSAssumeRoleWithWebIdentity( ) {
    getCloudInfo( )

    this.adminCredentials = new StaticCredentialsProvider( new BasicAWSCredentials( ACCESS_KEY, SECRET_KEY ) )
    testAcct= "${NAME_PREFIX}test-acct"
    testUser= "${NAME_PREFIX}test-user"

    // create a new user with all IAM permissions
    N4j.createAccount(testAcct)
    N4j.createUser(testAcct,testUser)
    N4j.createIAMPolicy(testAcct,testUser, "allow-all",null)
    this.credentials = new StaticCredentialsProvider( N4j.getUserCreds(testAcct, testUser) )

    // configurable / detected values
    host = CLC_IP
    path = '/pathhere'
    domainAndPort = "s3.${sniffDomain()}:8773".toString( )
    domain = domainAndPort.contains(':') ?
        domainAndPort.substring(0, domainAndPort.indexOf(':')) :
        domainAndPort
    thumbprint = sniffThumbprint("https://${domainAndPort}")
  }

  /**
   * Called after all the tests in a class
   *
   * @throws java.lang.Exception
   */
  @AfterClass
  public void tearDownAfterClass() throws Exception {
    N4j.deleteAccount(testAcct)
  }

  private String cloudUri(String servicePath) {
    URI.create("http://${host}:8773/")
            .resolve(servicePath)
            .toString()
  }

  private AWSSecurityTokenService getStsClient() {
    final AWSSecurityTokenService sts = new AWSSecurityTokenServiceClient(new AnonymousAWSCredentials())
    sts.setEndpoint(cloudUri('/services/Tokens'))
    sts
  }

  private AmazonS3 getS3Client(final AWSCredentialsProvider credentials) {
    final AmazonS3 s3 = new AmazonS3Client(credentials, new ClientConfiguration(signerOverride: 'S3SignerType'))
    s3.setS3ClientOptions(new S3ClientOptions(pathStyleAccess: true))
    s3.setEndpoint(cloudUri("/services/objectstorage"))
    s3
  }

  private AmazonIdentityManagement getIamClient(final AWSCredentialsProvider credentials) {
    final AmazonIdentityManagement iam = new AmazonIdentityManagementClient(credentials)
    iam.setEndpoint(cloudUri('/services/Euare'))
    iam
  }

  private AmazonEC2 getEC2Client(final AWSCredentialsProvider credentials) {
    final AmazonEC2 ec2 = new AmazonEC2Client(credentials)
    ec2.setEndpoint(cloudUri("/services/compute"))
    ec2
  }

  private YouProp getYouPropClient(final AWSCredentialsProvider credentials) {
    new YouPropClient(credentials).with {
      setEndpoint(cloudUri("/services/Properties"))
      it
    }
  }

  private String sniffDomain( ) {
    getYouPropClient(adminCredentials)?.with {
      describeProperties(new DescribePropertiesRequest(
              properties: ['system.dns.dnsdomain']
      )).with {
        properties[0].value
      }
    }
  }

  private static String sniffThumbprint(final String url) {
    List<X509Certificate> certificates = []
    SSLContext context = SSLContext.getInstance("TLS")
    context.init(null, [
            new X509TrustManager() {
              @Override
              void checkClientTrusted(final X509Certificate[] x509Certificates, final String s) {}

              @Override
              void checkServerTrusted(final X509Certificate[] x509Certificates, final String s) {
                certificates << x509Certificates[0]
              }

              @Override
              X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0] }
            }] as TrustManager[]
            , null)
    SSLSocketFactory socketFactory = context.getSocketFactory()
    HttpsURLConnection urlConnection1 = (HttpsURLConnection) new URL(url).openConnection()
    urlConnection1.setSSLSocketFactory(socketFactory)
    try {
      urlConnection1.getResponseCode()
    } catch (Exception) {
    }
    byte[] digest = MessageDigest.getInstance("SHA-1").digest(certificates[0].encoded)
    DatatypeConverter.printHexBinary(digest)
  }

  @Test
  public void testAssumeRoleWithWebIdentity( ) throws Exception {
    final String namePrefix = NAME_PREFIX
    N4j.print( "Using resource prefix for test: ${namePrefix}" )

    final List<Runnable> cleanupTasks = [] as List<Runnable>
    try {
      // By default we cannot use s3 for OIDC provider discovery as the host
      // will not match the certificate. This disables hostname checks during
      // the test if necessary
      getYouPropClient(adminCredentials)?.with {
        N4j.print "Checking bootstrap.webservices.ssl.user_ssl_enable_hostname_verification cloud property"
        final String hostnameVerificationEnabled = describeProperties(new DescribePropertiesRequest(
                properties: ['bootstrap.webservices.ssl.user_ssl_enable_hostname_verification']
        )).with {
          properties[0].value
        }
        N4j.print "Found bootstrap.webservices.ssl.user_ssl_enable_hostname_verification = ${hostnameVerificationEnabled}"

        if ('false' != hostnameVerificationEnabled) {
          N4j.print "Setting cloud property bootstrap.webservices.ssl.user_ssl_enable_hostname_verification=false"
          modifyPropertyValue(new ModifyPropertyValueRequest(
                  name: 'bootstrap.webservices.ssl.user_ssl_enable_hostname_verification',
                  value: 'false'
          ))
          cleanupTasks.add {
            N4j.print "Setting cloud property bootstrap.webservices.ssl.user_ssl_enable_hostname_verification=true"
            modifyPropertyValue(new ModifyPropertyValueRequest(
                    name: 'bootstrap.webservices.ssl.user_ssl_enable_hostname_verification',
                    value: 'true'
            ))
          }
        }

        N4j.print "Checking tokens.rolearnaliaswhitelist cloud property"
        final String roleArnWhitelist = describeProperties(new DescribePropertiesRequest(
                properties: ['tokens.rolearnaliaswhitelist']
        )).with {
          properties[0].value
        }
        N4j.print "Found tokens.rolearnaliaswhitelist = ${roleArnWhitelist}"

        if ('*' != roleArnWhitelist) {
          N4j.print "Setting cloud property tokens.rolearnaliaswhitelist=*"
          modifyPropertyValue(new ModifyPropertyValueRequest(
                  name: 'tokens.rolearnaliaswhitelist',
                  value: '*'
          ))
          cleanupTasks.add {
            N4j.print "Setting cloud property tokens.rolearnaliaswhitelist=${roleArnWhitelist}"
            modifyPropertyValue(new ModifyPropertyValueRequest(
                    name: 'tokens.rolearnaliaswhitelist',
                    value: roleArnWhitelist
            ))
          }
        }
        void
      }

      // OIDC configuration for discovery. We put OIDC discovery configuration
      // in a random s3 bucket where it can be accessed by the tokens service.
      final String bucket = UUID.randomUUID().toString() // random bucket for fake oidc provider
      final String issuerIdentifier = "https://${bucket}.${domainAndPort}${path}"
      final String configuration = """\
        {
            "issuer": "${issuerIdentifier}",
            "authorization_endpoint": "https://${bucket}.${domainAndPort}${path}/authorization",
            "token_endpoint": "https://${bucket}.${domainAndPort}${path}/token",
            "jwks_uri": "https://${bucket}.${domainAndPort}${path}/jwks.json",
            "response_types_supported": [
                "code",
                "token",
                "id_token",
                "code token",
                "code id_token",
                "token id_token",
                "code token id_token"
            ],
            "subject_types_supported": [
                "public"
            ],
            "id_token_signing_alg_values_supported": [
                "RS256"
            ],
            "scopes_supported": [
                "openid"
            ],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post"
            ],
            "claims_supported": [
                "aud",
                "email",
                "email_verified",
                "exp",
                "family_name",
                "given_name",
                "iat",
                "iss",
                "locale",
                "name",
                "sub",
                "auth_time"
            ]
        }
      """.stripIndent()
      final String jwks = """\
        {
            "keys": [
                {
                    "kty": "RSA",
                    "alg": "RS512",
                    "use": "sig",
                    "kid": "${kid}",
                    "n": "${Base64.urlEncoder.encodeToString(modulusBytes)}",
                    "e": "${Base64.urlEncoder.encodeToString(exponent.toBigInteger().toByteArray())}"
                }
            ]
        }
      """.stripIndent()

      // create bucket to set up oidc discovery
      getS3Client(credentials).with {
        N4j.print "Creating bucket for oidc discovery info: ${bucket}"
        createBucket(bucket)
        cleanupTasks.add {
          N4j.print "Deleting bucket ${bucket}"
          deleteBucket(bucket)
        }

        N4j.print "Creating object for oidc jwks: jwks.json"
        String jwksObject = "${path.empty ? '' : path.substring(1) + '/'}jwks.json"
        putObject(new PutObjectRequest(
                bucket,
                jwksObject,
                new ByteArrayInputStream(jwks.getBytes(StandardCharsets.UTF_8)),
                new ObjectMetadata(

                        contentType: 'application/json'
                )
        ).withCannedAcl(CannedAccessControlList.PublicRead))
        cleanupTasks.add {
          N4j.print "Deleting ${jwksObject} object from ${bucket}"
          deleteObject(bucket, jwksObject)
        }
        N4j.print "Creating object for oidc configuration: .well-known/openid-configuration"
        String oidcConfigurationObject = "${path.empty ? '' : path.substring(1) + '/'}.well-known/openid-configuration"
        putObject(new PutObjectRequest(
                bucket,
                oidcConfigurationObject,
                new ByteArrayInputStream(configuration.getBytes(StandardCharsets.UTF_8)),
                new ObjectMetadata(
                        contentType: 'application/json'
                )
        ).withCannedAcl(CannedAccessControlList.PublicRead))
        cleanupTasks.add {
          N4j.print "Deleting ${oidcConfigurationObject} object from ${bucket}"
          deleteObject(bucket, oidcConfigurationObject)
        }
        N4j.print "Bucket created for oidc discovery info: ${bucket}"
      }

      String accountAlias = ''
      String roleArn = ''
      String providerArn = ''
      getIamClient(credentials).with {
        N4j.print "Getting account alias"
        listAccountAliases( ).with {
          accountAlias = accountAliases?.getAt( 0 )
        }
        N4j.print "Account alias : ${accountAlias}"

        N4j.print "Creating IAM resources for assuming role"
        N4j.print "Creating oidc provider"
        providerArn = createOpenIDConnectProvider(new CreateOpenIDConnectProviderRequest(
                url: "https://${bucket}.${domainAndPort}${path}",
                clientIDList: [
                        aud, altAud
                ],
                thumbprintList: [
                        thumbprint
                ]
        ))?.with {
          openIDConnectProviderArn
        }
        N4j.print "Created oidc provider: ${providerArn}"
        cleanupTasks.add {
          N4j.print "Deleting oidc provider: ${providerArn}"
          deleteOpenIDConnectProvider(new DeleteOpenIDConnectProviderRequest(
                  openIDConnectProviderArn: providerArn
          ))
        }

        getOpenIDConnectProvider(new GetOpenIDConnectProviderRequest(
                openIDConnectProviderArn: providerArn
        ))?.with {
          N4j.print "Provider details : ${it}"
        }

        final String trustPolicy = """\
          {
            "Version": "2012-10-17",
            "Statement": [
              {
                "Effect": "Allow",
                "Principal": {
                  "Federated": "${providerArn}"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                  "StringEquals": {
                    "${bucket}.${domain}${path}:aud": [ "${aud}", "${altAud}" ],
                    "${bucket}.${domain}${path}:sub": [ "${sub}", "${altSub}" ]
                  }
                }
              }
            ]
          }
        """.stripIndent()

        final String permissionPolicy = """\
          {
            "Version": "2012-10-17",
            "Statement": [
              {
                "Effect": "Allow",
                "Action": "ec2:*SecurityGroup*",
                "Resource": "*",
                "Condition": {
                  "StringEquals": {
                    "aws:FederatedProvider": "${providerArn}",
                    "${bucket}.${domain}${path}:aud": "${aud}",
                    "${bucket}.${domain}${path}:sub": "${sub}"
                  }
                }
              }
            ]
          }
        """.stripIndent()

        String roleName = "${bucket}-role"
        N4j.print "Creating role for use use with provider: ${roleName}"
        roleArn = createRole(new CreateRoleRequest(
                path: '/',
                roleName: roleName,
                assumeRolePolicyDocument: trustPolicy
        ))?.with {
          role?.arn
        }
        N4j.print "Created role: ${roleArn}"
        cleanupTasks.add {
          N4j.print "Deleting role: ${roleArn}"
          deleteRole(new DeleteRoleRequest(
                  roleName: roleName
          ))
        }

        N4j.print "Creating role permission policy: ${roleName}/role-policy"
        putRolePolicy(new PutRolePolicyRequest(
                roleName: roleName,
                policyName: 'role-policy',
                policyDocument: permissionPolicy
        ))
        N4j.print "Created iam resources for assuming role"
        cleanupTasks.add {
          N4j.print "Deleting role policy: ${roleName}/role-policy"
          deleteRolePolicy(new DeleteRolePolicyRequest(
                  roleName: roleName,
                  policyName: 'role-policy',
          ))
        }
      }

      // ensure iam resources available
      final int sleepSecs = 15
      N4j.print "Sleeping ${sleepSecs} seconds to ensure iam resources are available for use"
      N4j.sleep sleepSecs

      // create token for assuming role
      N4j.print "Generating oidc token for assume role use"
      final String tokenString = generateIdentityToken( System.currentTimeMillis( ), issuerIdentifier, aud, sub )
      N4j.print "Generated oidc id token: ${tokenString}"

      Map<String, Object> validParameters = [
              durationSeconds: 971,
              roleArn: roleArn,
              roleSessionName: 'session',
              webIdentityToken: tokenString
      ]

      getStsClient( ).with {
        [
                [durationSeconds: 899],
                [durationSeconds: 3601],
                [roleSessionName: 'a'],
                [roleSessionName: 'a' * 65],
                [webIdentityToken: '1'],
                [webIdentityToken: ('ICAg' * (2048 / 3)) + tokenString],
        ].each { invalidParameters ->
          try {
            Map<String, Object> parameters = [:]
            parameters << validParameters
            parameters << invalidParameters
            N4j.print "Testing assume role with web identity using invalid parameters: ${parameters}"
            assumeRoleWithWebIdentity(new AssumeRoleWithWebIdentityRequest(parameters))
            N4j.assertThat( false, 'Expected assume role with web identity failure due to invalid parameters' )
          } catch (AmazonServiceException e) {
            N4j.print e.toString()
            N4j.assertThat(e.statusCode == 400, "Expected status code 400, but was: ${e.statusCode}")
            N4j.assertThat(e.errorCode == 'ValidationError', "Expected error code ValidationError, but was: ${e.errorCode}")
          }
        }
        [
                tokenString.replace('.', ''),
                'ICAg' + tokenString,
                generateIdentityToken( System.currentTimeMillis( ), issuerIdentifier, UUID.randomUUID().toString(), sub ),
        ].each { invalidTokenParameter ->
          try {
            Map<String, Object> parameters = [:]
            parameters << validParameters
            parameters << [webIdentityToken: invalidTokenParameter]
            N4j.print "Testing assume role with web identity using invalid parameters: ${parameters}"
            assumeRoleWithWebIdentity( new AssumeRoleWithWebIdentityRequest( parameters ) )
            N4j.assertThat( false, 'Expected assume role with web identity failure due to invalid token parameter' )
          } catch (AmazonServiceException e) {
            N4j.print e.toString( )
            N4j.assertThat( e.statusCode == 400, "Expected status code 400, but was: ${e.statusCode}")
            N4j.assertThat( e.errorCode == 'InvalidIdentityToken', "Expected error code InvalidIdentityToken, but was: ${e.errorCode}")
          }
        }
        try {
          Map<String, Object> parameters = [:]
          parameters << validParameters
          parameters << [webIdentityToken: generateIdentityToken( System.currentTimeMillis( ), issuerIdentifier, aud, UUID.randomUUID().toString() )]
          N4j.print "Testing assume role with web identity using token with incorrect subject, parameters: ${parameters}"
          assumeRoleWithWebIdentity( new AssumeRoleWithWebIdentityRequest( parameters ) )
          N4j.assertThat( false, 'Expected assume role with web identity failure due to assume role policy failure' )
        } catch (AmazonServiceException e) {
          N4j.print e.toString( )
          N4j.assertThat( e.statusCode == 403, "Expected status code 403, but was: ${e.statusCode}")
          N4j.assertThat( e.errorCode == 'AccessDenied', "Expected error code AccessDenied, but was: ${e.errorCode}")
        }
        try {
          Map<String, Object> parameters = [:]
          parameters << validParameters
          parameters << [roleArn: "${roleArn}Invalid"]
          N4j.print "Testing assume role with web identity using invalid role arn, parameters: ${parameters}"
          assumeRoleWithWebIdentity( new AssumeRoleWithWebIdentityRequest( parameters ) )
          N4j.assertThat( false, 'Expected assume role with web identity failure due to invalid role arn' )
        } catch (AmazonServiceException e) {
          N4j.print e.toString( )
          N4j.assertThat( e.statusCode == 403, "Expected status code 403, but was: ${e.statusCode}")
          N4j.assertThat( e.errorCode == 'AccessDenied', "Expected error code AccessDenied, but was: ${e.errorCode}")
        }
        try {
          Map<String, Object> parameters = [:]
          parameters << validParameters
          parameters << [webIdentityToken: generateIdentityToken( System.currentTimeMillis( ) - ( 20 * 60 * 1000 ), issuerIdentifier, aud, sub )]
          N4j.print "Testing assume role with web identity using expired token, parameters: ${parameters}"
          assumeRoleWithWebIdentity( new AssumeRoleWithWebIdentityRequest( parameters ) )
          N4j.assertThat( false, 'Expected assume role with web identity failure due to expired token' )
        } catch (AmazonServiceException e) {
          N4j.print e.toString( )
          N4j.assertThat( e.statusCode == 400, "Expected status code 400, but was: ${e.statusCode}")
          N4j.assertThat( e.errorCode == 'ExpiredTokenException', "Expected error code ExpiredTokenException, but was: ${e.errorCode}")
        }
      }

      final AWSCredentialsProvider roleCredentialsProvider = new AWSCredentialsProvider() {
        AWSCredentials awsCredentials = null
        @Override
        public AWSCredentials getCredentials( ) {
          if ( awsCredentials == null ) {
            N4j.print "Getting credentials using assume role with web identity"
            awsCredentials = getStsClient( ).with {
              assumeRoleWithWebIdentity( new AssumeRoleWithWebIdentityRequest( validParameters ) ).with {
                N4j.assertThat(assumedRoleUser != null, "Expected assumedRoleUser")
                N4j.assertThat(assumedRoleUser.arn != null, "Expected assumedRoleUser.arn")
                N4j.assertThat(assumedRoleUser.assumedRoleId != null, "Expected assumedRoleUser.assumedRoleId")
                N4j.assertThat(packedPolicySize == null, "Unexpected packedPolicySize")
                N4j.assertThat(providerArn == provider, "Expected provider ${providerArn}, but was: ${provider}")
                N4j.assertThat(aud == audience, "Expected audience ${aud}, but was: ${audience}")
                N4j.assertThat(
                        sub == subjectFromWebIdentityToken,
                        "Expected subjectFromWebIdentityToken ${sub}, but was: ${subjectFromWebIdentityToken}")

                N4j.assertThat(credentials != null, "Expected credentials")
                N4j.assertThat(credentials.expiration != null, "Expected credentials expiration")
                N4j.assertThat(
                        Math.abs(Math.abs((credentials.expiration.time - System.currentTimeMillis()) / 1000l) - 971) < 30,
                        "Expected credentials to respect duration")
                new BasicSessionCredentials(
                        credentials.accessKeyId,
                        credentials.secretAccessKey,
                        credentials.sessionToken
                )
              }
            }
          }
          awsCredentials
        }

        @Override
        public void refresh( ) {
          awsCredentials = null
        }
      }

      getEC2Client( roleCredentialsProvider ).with {
        N4j.print "Describing security groups using assumed role credentials"
        N4j.print describeSecurityGroups( ).with { DescribeSecurityGroupsResult result ->
          N4j.assertThat( securityGroups!=null && securityGroups.size()>0, "Expected visible security groups" )
          result.toString( )
        }

        N4j.print "Switching to use account alias in role arn"
        N4j.print "was : ${validParameters['roleArn']}"
        validParameters['roleArn'] = validParameters['roleArn'].toString( ).replaceFirst( '[0-9]{12}', accountAlias )
        N4j.print "now : ${validParameters['roleArn']}"
        roleCredentialsProvider.refresh( )

        String groupName = "${namePrefix}group-1"
        N4j.print "Creating security group ${groupName} using assumed role credentials"
        createSecurityGroup( new CreateSecurityGroupRequest( groupName: groupName, description: 'STS assume role with web identity test group' ) )

        N4j.print "Deleting security group ${groupName} using assumed role credentials"
        deleteSecurityGroup( new DeleteSecurityGroupRequest( groupName: groupName ) )
      }

      N4j.print "Testing access denied using alternative aud/sub values"
      [
              [
                      aud: aud,
                      sub: altSub
              ],
              [
                      aud: altAud,
                      sub: sub
              ],
              [
                      aud: altAud,
                      sub: altSub
              ]
      ].each { parameters ->
        String testAud = parameters.get('aud')
        String testSub = parameters.get('sub')
        getEC2Client( new AWSCredentialsProvider( ) {
          AWSCredentials awsCredentials = null
          @Override
          public AWSCredentials getCredentials( ) {
            if ( awsCredentials == null ) {
              awsCredentials = getStsClient( ).with {
                N4j.print "Getting credentials using assume role with web identity using aud:${testAud} sub:${testSub}"
                Map<String, Object> assumeRoleParameters = [:]
                assumeRoleParameters << validParameters
                assumeRoleParameters << [webIdentityToken: generateIdentityToken( System.currentTimeMillis( ), issuerIdentifier, testAud, testSub )]
                assumeRoleWithWebIdentity( new AssumeRoleWithWebIdentityRequest( assumeRoleParameters ) ).with {
                  N4j.assertThat(testAud == audience, "Expected audience ${testAud}, but was: ${audience}")
                  N4j.assertThat(
                          testSub == subjectFromWebIdentityToken,
                          "Expected subjectFromWebIdentityToken ${testSub}, but was: ${subjectFromWebIdentityToken}")
                  N4j.assertThat(credentials != null, "Expected credentials")
                  new BasicSessionCredentials(
                          credentials.accessKeyId,
                          credentials.secretAccessKey,
                          credentials.sessionToken
                  )
                }
              }
            }
            awsCredentials
          }

          @Override
          public void refresh() {
            awsCredentials = null
          }
        } ).with {
          N4j.print "Describing security groups using assumed role credentials with invalid aud and/or sub"
          try {
            N4j.print describeSecurityGroups().with { DescribeSecurityGroupsResult result ->
              N4j.assertThat(securityGroups==null || securityGroups.empty, "Expected no visible security groups")
              result.toString( )
            }
          } catch ( AmazonServiceException e ) {
            N4j.print e.toString( )
            N4j.assertThat( e.statusCode >= 403, "Expected status code >=403, but was: ${e.statusCode}")
          }

          String groupName = "${namePrefix}group-2"
          cleanupTasks.add{
            N4j.print "Deleting security group ${groupName} using assumed role credentials"
            deleteSecurityGroup( new DeleteSecurityGroupRequest( groupName: groupName ) )
          }
          try {
            N4j.print "Creating security group ${groupName} using assumed role credentials with invalid aud and/or sub (should fail)"
            createSecurityGroup( new CreateSecurityGroupRequest( groupName: groupName, description: 'STS assume role with web identity test group' ) )
            N4j.assertThat( false, "Expected security group creation failure due to invalid aud and/or sub")
          } catch ( AmazonServiceException e ) {
            N4j.print e.toString( )
            N4j.assertThat( e.statusCode >= 403, "Expected status code >=403, but was: ${e.statusCode}")
          }
        }
      }

      N4j.print "Test complete"
    } finally {
      // Attempt to clean up anything we created
      cleanupTasks.reverseEach { Runnable cleanupTask ->
        try {
          cleanupTask.run()
        } catch ( AmazonServiceException e ) {
          N4j.print "Error in clean up: ${e}"
        } catch ( Exception e ) {
          e.printStackTrace()
        }
      }
    }
  }

  private String generateIdentityToken( final long tokenIssueTime, final String issuerIdentifier, final String aud, final String sub ) {
    final KeyFactory factory = KeyFactory.getInstance("RSA")
    final PrivateKey key = factory.generatePrivate(new RSAPrivateKeySpec(new BigInteger(modulusBytes), new BigInteger(privateExponentBytes)))
    final String headerB64 = Base64.urlEncoder.encodeToString("""{"typ":"JWT", "alg":"RS512", "kid":"${kid}"}""".getBytes(StandardCharsets.UTF_8))
    final String body = """\
      {
        "iss": "${issuerIdentifier}",
        "exp": ${((long) (tokenIssueTime / 1000l)) + 900},
        "iat": ${(long) (tokenIssueTime / 1000l)},
        "aud": "${aud}",
        "sub": "${sub}"
      }
      """.stripIndent()
    final String bodyB64 = Base64.urlEncoder.encodeToString(body.getBytes(StandardCharsets.UTF_8))
    final Signature signer = Signature.getInstance("SHA512withRSA")
    signer.initSign(key)
    signer.update(headerB64.getBytes(StandardCharsets.UTF_8))
    signer.update('.'.getBytes(StandardCharsets.UTF_8))
    signer.update(bodyB64.getBytes(StandardCharsets.UTF_8))
    final String signature = Base64.urlEncoder.encodeToString(signer.sign())
    headerB64 + '.' + bodyB64 + '.' + signature
  }
}
