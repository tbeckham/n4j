package com.eucalyptus.tests.awssdk

import com.amazonaws.AmazonServiceException
import com.amazonaws.ClientConfiguration
import com.amazonaws.Request
import com.amazonaws.auth.AWSCredentials
import com.amazonaws.auth.AWSCredentialsProvider
import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.auth.BasicSessionCredentials
import com.amazonaws.handlers.RequestHandler2
import com.amazonaws.internal.StaticCredentialsProvider
import com.amazonaws.services.identitymanagement.model.*
import com.amazonaws.services.s3.AmazonS3
import com.amazonaws.services.s3.AmazonS3Client
import com.amazonaws.services.s3.S3ClientOptions
import com.amazonaws.services.s3.model.ListObjectsRequest
import com.amazonaws.services.s3.model.ObjectMetadata
import com.amazonaws.services.securitytoken.AWSSecurityTokenService
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest
import com.github.sjones4.youcan.youare.YouAreClient
import com.github.sjones4.youcan.youare.model.CreateAccountRequest
import com.github.sjones4.youcan.youare.model.DeleteAccountRequest
import org.testng.annotations.Test

import static com.eucalyptus.tests.awssdk.N4j.ACCESS_KEY
import static com.eucalyptus.tests.awssdk.N4j.CLC_IP
import static com.eucalyptus.tests.awssdk.N4j.SECRET_KEY
import static com.eucalyptus.tests.awssdk.N4j.minimalInit
import static com.eucalyptus.tests.awssdk.N4j.testInfo

/**
 * Tests IAM policy variables for S3.
 *
 * Covers user having their own area in a bucket.
 *
 * Related issue:
 *   https://eucalyptus.atlassian.net/browse/EUCA-8582
 *   https://eucalyptus.atlassian.net/browse/EUCA-12802
 *
 * Related AWS doc:
 *   http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html
 *   http://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_examples.html#iam-policy-example-s3-home-directory
 */
class TestIAMPolicyVariablesS3 {

  private final String host;
  private final AWSCredentialsProvider credentials;

  TestIAMPolicyVariablesS3( ) {
    minimalInit()
    this.host=CLC_IP
    this.credentials = new StaticCredentialsProvider( new BasicAWSCredentials( ACCESS_KEY, SECRET_KEY ) )
  }

  private String cloudUri(String host, String servicePath ) {
    URI.create( "http://${host}:8773/" )
        .resolve( servicePath )
        .toString( )
  }

  private YouAreClient getYouAreClient( AWSCredentialsProvider clientCredentials = credentials  ) {
    final YouAreClient euare = new YouAreClient( clientCredentials )
    euare.setEndpoint( cloudUri( host, '/services/Euare' ) )
    euare
  }

  private AWSSecurityTokenService getStsClient( AWSCredentialsProvider clientCredentials = credentials  ) {
    final AWSSecurityTokenService sts = new AWSSecurityTokenServiceClient( clientCredentials )
    sts.setEndpoint(cloudUri( host, '/services/Tokens' ))
    sts
  }

  private AmazonS3 getS3Client( AWSCredentialsProvider clientCredentials = credentials ) {
    final AmazonS3Client s3 =
        new AmazonS3Client( clientCredentials, new ClientConfiguration( ).withSignerOverride("S3SignerType") )
    s3.setEndpoint( cloudUri( host, '/services/objectstorage' ) )
    s3.setS3ClientOptions( new S3ClientOptions( ).builder( ).setPathStyleAccess( true ).build( ) )
    s3
  }

  @Test
  public void testIAMPolicyVariablesS3( ) throws Exception {
    testInfo(this.getClass().getSimpleName());
    final String namePrefix = UUID.randomUUID().toString().substring(0,8) + "-"
    N4j.print( "Using resource prefix for test: ${namePrefix}" )

    final List<Runnable> cleanupTasks = [] as List<Runnable>
    final String accountName = "${namePrefix}account1"
    final String userName = "${namePrefix}user1"
    final String roleName = "${namePrefix}role1"
    final String roleSessionName = "role-session-name-here"
    final String bucketName = "${namePrefix}bucket1"
    String accountId = null
    String userId = null
    String roleArn = null
    String roleId = null
    try {
      AWSCredentialsProvider adminCredentials = getYouAreClient( ).with {
        N4j.print("Creating test account: ${accountName}")
        String adminAccountNumber = createAccount(new CreateAccountRequest(accountName: accountName)).with {
          account?.accountId
        }
        N4j.assertThat( adminAccountNumber != null, "Expected account number" )
        N4j.print( "Created test account with number: ${adminAccountNumber}" )
        cleanupTasks.add {
          N4j.print("Deleting test account: ${accountName}")
          deleteAccount(new DeleteAccountRequest(accountName: accountName, recursive: true))
        }

        N4j.print("Creating access key for test account admin user: ${accountName}")
        getYouAreClient( ).with {
          addRequestHandler(new RequestHandler2() {
            public void beforeRequest(final Request<?> request) {
              request.addParameter("DelegateAccount", accountName)
            }
          })
          createAccessKey(new CreateAccessKeyRequest(userName: "admin")).with {
            accessKey?.with {
              new StaticCredentialsProvider( new BasicAWSCredentials( accessKeyId, secretAccessKey ) )
            }
          }
        }
      }

      AWSCredentialsProvider userCredentials = getYouAreClient( adminCredentials ).with {
        cleanupTasks.add{
          N4j.print( "Deleting user ${userName}" )
          deleteUser( new DeleteUserRequest(
              userName: userName
          ) )
        }
        N4j.print( "Creating user ${userName}" )
        userId = createUser( new CreateUserRequest(
            userName: userName,
            path: '/'
        ) ).with {
          accountId = user?.arn?.substring( 13,25 )
          user?.userId
        }
        N4j.assertThat( userId != null, "Expected user id")
        N4j.assertThat( accountId != null, "Expected account id")
        N4j.print( "Created user ${userName} with id ${userId} in account ${accountId}" )

        String policyName = "${namePrefix}policy1"
        String policyDoc = """\
              {
                "Version": "2012-10-17",
                "Statement": [
                  {
                    "Effect": "Allow",
                    "Action": [
                      "s3:ListAllMyBuckets",
                      "s3:GetBucketLocation"
                    ],
                    "Resource": "arn:aws:s3:::*"
                  },
                  {
                    "Effect": "Allow",
                    "Action": "s3:ListBucket",
                    "Resource": "arn:aws:s3:::${bucketName}",
                    "Condition": {"StringEquals": {
                      "s3:prefix": [ "", "home/" ],
                      "s3:delimiter": ["/"]
                    }}
                  },
                  {
                    "Effect": "Allow",
                    "Action": "s3:ListBucket",
                    "Resource": "arn:aws:s3:::${bucketName}",
                    "Condition": {"StringLike": {
                      "s3:prefix": [ "home/\${aws:username}/*", "home/\${aws:userid}/*" ]
                    }}
                  },
                  {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": [
                      "arn:aws:s3:::${bucketName}/home/\${aws:username}",
                      "arn:aws:s3:::${bucketName}/home/\${aws:username}/*",
                      "arn:aws:s3:::${bucketName}/home/\${aws:userid}",
                      "arn:aws:s3:::${bucketName}/home/\${aws:userid}/*",
                    ]
                  }
                ]
              }
              """.stripIndent( )
        N4j.print( "Creating user policy ${policyName}" )
        putUserPolicy( new PutUserPolicyRequest(
            userName: userName,
            policyName: policyName,
            policyDocument: policyDoc
        ) )

        cleanupTasks.add{
          N4j.print( "Deleting user policy ${policyName}" )
          deleteUserPolicy( new DeleteUserPolicyRequest(
              userName: userName,
              policyName: policyName
          ) )
        }

        final String trustPolicy = """\
          {
            "Version": "2012-10-17",
            "Statement": [
              {
                "Effect": "Allow",
                "Principal": {
                  "AWS": [ "arn:aws:iam::${accountId}:user/admin" ]
                },
                "Action": "sts:AssumeRole"
              }
            ]
          }
        """.stripIndent()

        N4j.print "Creating role: ${roleName}"
        roleArn = createRole(new CreateRoleRequest(
            path: '/',
            roleName: roleName,
            assumeRolePolicyDocument: trustPolicy
        ))?.with {
          roleId = role?.roleId
          role?.arn
        }
        N4j.print "Created role: ${roleArn} / ${roleId}"
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
            policyDocument: """\
              {
                "Version": "2012-10-17",
                "Statement": [
                  {
                    "Effect": "Allow",
                    "Action": [
                      "s3:ListAllMyBuckets",
                      "s3:GetBucketLocation"
                    ],
                    "Resource": "arn:aws:s3:::*"
                  },
                  {
                    "Effect": "Allow",
                    "Action": "s3:ListBucket",
                    "Resource": "arn:aws:s3:::${bucketName}",
                    "Condition": {"StringEquals": {
                      "s3:prefix": [ "", "home/" ],
                      "s3:delimiter": ["/"]
                    }}
                  },
                  {
                    "Effect": "Allow",
                    "Action": "s3:ListBucket",
                    "Resource": "arn:aws:s3:::${bucketName}",
                    "Condition": {"StringLike": {
                      "s3:prefix": [ "home/\${aws:userid}/*" ]
                    }}
                  },
                  {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": [
                      "arn:aws:s3:::${bucketName}/home/\${aws:userid}",
                      "arn:aws:s3:::${bucketName}/home/\${aws:userid}/*",
                    ]
                  }
                ]
              }
              """.stripIndent( )
        ))
        N4j.print "Created iam resources for assuming role"
        cleanupTasks.add {
          N4j.print "Deleting role policy: ${roleName}/role-policy"
          deleteRolePolicy(new DeleteRolePolicyRequest(
              roleName: roleName,
              policyName: 'role-policy',
          ))
        }

        N4j.print( "Creating access key for user ${userName}" )
        AWSCredentialsProvider userCredentials = createAccessKey( new CreateAccessKeyRequest(
            userName: userName
        ) ).with {
          accessKey.with {
            new StaticCredentialsProvider( new BasicAWSCredentials( accessKeyId, secretAccessKey ) )
          }
        }

        cleanupTasks.add {
          N4j.print( "Deleting access key for user ${userName}" )
          deleteAccessKey( new DeleteAccessKeyRequest(
              userName: userName,
              accessKeyId: userCredentials.credentials.AWSAccessKeyId
          ) )
        }

        userCredentials
      }

      getS3Client( adminCredentials ).with {
        N4j.print( "Creating bucket ${bucketName}" )
        createBucket( bucketName )
        cleanupTasks.add{
          N4j.print( "Deleting bucket ${bucketName}" )
          deleteBucket( bucketName )
        }

        N4j.print( "Putting blah object to ${bucketName} home/someotheruser directory" )
        putObject( bucketName, "home/someotheruser/blah", new ByteArrayInputStream( "DATA".getBytes( "utf-8" ) ), new ObjectMetadata( ) );
        cleanupTasks.add{
          N4j.print( "Deleting blah object from ${bucketName} home/someotheruser directory" )
          deleteObject( bucketName, "home/someotheruser/blah"  );
        }
      }

      final AWSCredentialsProvider roleCredentialsProvider = new AWSCredentialsProvider( ) {
        AWSCredentials awsCredentials = null
        @Override
        public AWSCredentials getCredentials( ) {
          if ( awsCredentials == null ) {
            N4j.print "Getting credentials using assume role with web identity"
            awsCredentials = getStsClient( adminCredentials ).with {
              assumeRole( new AssumeRoleRequest(
                  roleArn: roleArn,
                  roleSessionName: roleSessionName,
                  durationSeconds: 900
              ) ).with {
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
      getS3Client( roleCredentialsProvider ).with {
        N4j.print("Putting foo1 object to ${bucketName} home/${roleId}:${roleSessionName} directory")
        putObject(bucketName, "home/${roleId}:${roleSessionName}/foo1", new ByteArrayInputStream("DATA".getBytes("utf-8")), new ObjectMetadata());

        N4j.print("Deleting object foo1 from ${bucketName} home/${roleId}:${roleSessionName} directory")
        deleteObject(bucketName, "home/${roleId}:${roleSessionName}/foo1");
      }

      getS3Client( userCredentials ).with {
        N4j.print( "Putting foo1 object to ${bucketName} home/${userId} directory" )
        putObject( bucketName, "home/${userId}/foo1", new ByteArrayInputStream( "DATA".getBytes( "utf-8" ) ), new ObjectMetadata( ) );

        N4j.print( "Deleting object foo1 from ${bucketName} home/${userId} directory" )
        deleteObject( bucketName, "home/${userId}/foo1"  );

        N4j.print( "Putting foo1 object to ${bucketName}/${userName} home directory" )
        putObject( bucketName, "home/${userName}/foo1", new ByteArrayInputStream( "DATA".getBytes( "utf-8" ) ), new ObjectMetadata( ) );

        N4j.print( "Copying object foo1 to copy1 in ${bucketName} home directory" )
        copyObject( bucketName, "home/${userName}/foo1", bucketName, "home/${userName}/copy1" );

        N4j.print( "Listing bucket root" )
        N4j.print( listObjects( new ListObjectsRequest(
            bucketName: bucketName,
            prefix: '',
            delimiter: '/'
        ) ).with{
          N4j.assertThat( [ 'home/' ] == commonPrefixes, "bucket root listing" )
          objectSummaries*.key + commonPrefixes
        }.toString( ) )

        N4j.print( "Listing bucket home" )
        N4j.print( listObjects( new ListObjectsRequest(
            bucketName: bucketName,
            prefix: 'home/',
            delimiter: '/'
        ) ).with{
          N4j.assertThat( [ "home/${userName}/", 'home/someotheruser/' ] == commonPrefixes, "bucket home listing" )
          objectSummaries*.key + commonPrefixes
        }.toString( ) )

        N4j.print( "Listing bucket home/${userName}" )
        N4j.print( listObjects(  new ListObjectsRequest(
            bucketName: bucketName,
            prefix: "home/${userName}/",
            delimiter: '/'
        )  ).with{
          N4j.assertThat(
              [ "home/${userName}/copy1" as String, "home/${userName}/foo1" as String ] == objectSummaries*.key,
              "bucket user listing" )
          objectSummaries*.key + commonPrefixes
        }.toString( ) )

        try {
          N4j.print( "Listing bucket home/someotheruser" )
          N4j.print( listObjects(  new ListObjectsRequest(
              bucketName: bucketName,
              prefix: 'home/someotheruser/',
              delimiter: '/'
          )  ).with{ objectSummaries*.key + commonPrefixes }.toString( ) )
          N4j.assertThat( false, 'Expected failure listing bucket prefix without permission' )
        } catch ( AmazonServiceException e ) {
          N4j.print( "Expected error list bucket prefix without permission: ${e}" )
        }

        N4j.print( "Deleting object foo1 from ${bucketName} home/${userName} directory" )
        deleteObject( bucketName, "home/${userName}/foo1"  );

        N4j.print( "Deleting object copy1 from ${bucketName} home/${userName} directory" )
        deleteObject( bucketName, "home/${userName}/copy1"  );

        try {
          N4j.print( "Putting object to ${bucketName} outside of home directory, should fail" )
          putObject( bucketName, "foo1", new ByteArrayInputStream( "DATA".getBytes( "utf-8" ) ), new ObjectMetadata( ) );
          N4j.assertThat( false, "Expected put object to fail for admin user due to permissions" )
        } catch ( AmazonServiceException e ) {
          N4j.print( "Expected error putting object without permission: ${e}" )
        }

        void
      }

      N4j.print( "Test complete" )
    } finally {
      // Attempt to clean up anything we created
      cleanupTasks.reverseEach { Runnable cleanupTask ->
        try {
          cleanupTask.run()
        } catch ( NoSuchEntityException e ) {
          N4j.print( "Entity not found during cleanup." )
        } catch ( AmazonServiceException e ) {
          N4j.print( "Service error during cleanup; code: ${e.errorCode}, message: ${e.message}" )
        } catch ( Exception e ) {
          e.printStackTrace()
        }
      }
    }
  }
}
