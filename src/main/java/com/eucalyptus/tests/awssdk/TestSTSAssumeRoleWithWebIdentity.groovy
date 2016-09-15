package com.eucalyptus.tests.awssdk

import com.amazonaws.AmazonServiceException
import com.amazonaws.ClientConfiguration
import com.amazonaws.auth.AWSCredentials
import com.amazonaws.auth.AWSCredentialsProvider
import com.amazonaws.auth.AnonymousAWSCredentials
import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.auth.BasicSessionCredentials
import com.amazonaws.internal.StaticCredentialsProvider
import com.amazonaws.regions.Region
import com.amazonaws.regions.Regions
import com.amazonaws.services.ec2.AmazonEC2
import com.amazonaws.services.ec2.AmazonEC2Client
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
import org.testng.annotations.Test

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
 *
 * Related AWS doc:
 *   http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html
 *   http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html
 */
class TestSTSAssumeRoleWithWebIdentity {

  // use host setting to switch between aws and qa, TODO:update all CHANGEME before testing
  private static final String host = '10.X.Y.Z'            // TODO:CHANGEME ufs host ip
  private static final AWSCredentialsProvider credentials = new StaticCredentialsProvider( new BasicAWSCredentials(
      "AKI...",
      "..."  ) ) // TODO:CHANGEME creds for s3/iam use
  private static final AWSCredentialsProvider adminCredentials = new StaticCredentialsProvider( new BasicAWSCredentials(
      "AKIA...",
      "..."  ) ) // TODO:CHANGEME creds for properties

  // configurable / detected values
  private final Region region = Region.getRegion(Regions.US_WEST_1)
  private final String path = '/pathhere'
  private final String domainAndPort = host == null ?
      's3-us-west-1.amazonaws.com' : // aws s3
      "s3.${sniffDomain()}:8773".toString()
  private final String domain = domainAndPort.contains(':') ?
      domainAndPort.substring(0, domainAndPort.indexOf(':')) :
      domainAndPort
  private final String thumbprint = host == null ?
      'A9D53002E97E00E043244F3D170D6F4C414104FD' : // aws s3
      sniffThumbprint("https://${domainAndPort}")

  // arbitrary values for oidc registration / identity
  private final String aud = 'c6845610-9b57-4386-a1c4-7ffe45d03c92'
  private final String sub = '7277dd17-cc4e-4b24-8830-ccdafca56241'
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


  private static String cloudUri(String servicePath) {
    URI.create("http://${host}:8773/")
        .resolve(servicePath)
        .toString()
  }

  private AWSSecurityTokenService getStsClient() {
    final AWSSecurityTokenService sts = new AWSSecurityTokenServiceClient(new AnonymousAWSCredentials())
    if (host) { // qa
      sts.setEndpoint(cloudUri('/services/Tokens'))
    } else { // aws
      if (region) sts.setRegion(region)
    }
    sts
  }

  private AmazonS3 getS3Client(final AWSCredentialsProvider credentials) {
    final AmazonS3 s3 = new AmazonS3Client(credentials, new ClientConfiguration(signerOverride: 'S3SignerType'))
    if (host) { // qa
      s3.setS3ClientOptions(new S3ClientOptions(pathStyleAccess: true))
      s3.setEndpoint(cloudUri("/services/objectstorage"))
    } else { // aws
      if (region) s3.setRegion(region)
    }
    s3
  }

  private AmazonIdentityManagement getIamClient(final AWSCredentialsProvider credentials) {
    final AmazonIdentityManagement iam = new AmazonIdentityManagementClient(credentials);
    if (host) { // qa
      iam.setEndpoint(cloudUri('/services/Euare'))
    } else { // aws
      // no region for iam
    }
    return iam;
  }

  private AmazonEC2 getEC2Client(final AWSCredentialsProvider credentials) {
    final AmazonEC2 ec2 = new AmazonEC2Client(credentials)
    if (host) { // qa
      ec2.setEndpoint(cloudUri("/services/compute"))
    } else { // aws
      if (region) ec2.setRegion(region)
    }
    ec2
  }

  private static YouProp getYouPropClient(final AWSCredentialsProvider credentials) {
    if (host) {
      new YouPropClient(credentials).with {
        setEndpoint(cloudUri("/services/Properties"))
        it
      }
    } else {
      null
    }
  }

  private static String sniffDomain() {
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
  public void test() throws Exception {
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
          deleteObject(bucket, jwksObject);
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
          deleteObject(bucket, oidcConfigurationObject);
        }
        N4j.print "Bucket created for oidc discovery info: ${bucket}"
      }

      String roleArn = ''
      String providerArn = ''
      getIamClient(credentials).with {
        N4j.print "Creating IAM resources for assuming role"
        N4j.print "Creating oidc provider"
        providerArn = createOpenIDConnectProvider(new CreateOpenIDConnectProviderRequest(
            url: "https://${bucket}.${domainAndPort}${path}",
            clientIDList: [
                aud
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
                    "${bucket}.${domain}${path}:aud": "${aud}",
                    "${bucket}.${domain}${path}:sub": "${sub}"
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
                "Action": "ec2:Describe*",
                "Resource": "*"
              }
            ]
          }
        """.stripIndent()
        // TODO: Eucalyptus does not yet implement
        //      final String permissionPolicy = """\
        //        {
        //          "Version": "2012-10-17",
        //          "Statement": [
        //            {
        //              "Effect": "Allow",
        //              "Action": "ec2:Describe*",
        //              "Resource": "*",
        //              "Condition": {
        //                "StringEquals": {
        //                  "aws:FederatedProvider": "${providerArn}",
        //                  "${bucket}.${domainAndPort}:aud": "${audience}",
        //                  "${bucket}.${domainAndPort}:sub": "${sub}"
        //                }
        //              }
        //            }
        //          ]
        //        }
        //      """.stripIndent()

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
            [roleArn: 'arn:aws:iam:::role/r'],
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

      getEC2Client(new AWSCredentialsProvider() {
        @Override
        public AWSCredentials getCredentials( ) {
          N4j.print "Getting credentials using assume role with web identity"
          getStsClient( ).with {
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
              );
            }
          }
        }

        @Override
        public void refresh() {
        }
      }).with {
        N4j.print "Describing security groups using assumed role credentials"
        N4j.print describeSecurityGroups().toString()
      }

      N4j.print "Test complete"
    } finally {
      // Attempt to clean up anything we created
      cleanupTasks.reverseEach { Runnable cleanupTask ->
        try {
          cleanupTask.run()
        } catch ( Exception e ) {
          e.printStackTrace()
        }
      }
    }
  }

  private String generateIdentityToken( final long tokenIssueTime, final String issuerIdentifier, final String aud, final String sub ) {
    final KeyFactory factory = KeyFactory.getInstance("RSA")
    final PrivateKey key = factory.generatePrivate(new RSAPrivateKeySpec(new BigInteger(modulusBytes), new BigInteger(privateExponentBytes)));
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
