package com.eucalyptus.tests.awssdk

import com.amazonaws.AmazonServiceException
import com.amazonaws.Request
import com.amazonaws.auth.AWSCredentialsProvider
import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.handlers.RequestHandler2
import com.amazonaws.internal.StaticCredentialsProvider
import com.amazonaws.services.identitymanagement.model.*
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
 * Tests IAM policy variables.
 *
 * Covers user managing their own credentials.
 *
 * Related issues:
 *   https://eucalyptus.atlassian.net/browse/EUCA-8582
 *
 * Related AWS doc:
 *   http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html
 *   http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_delegate-permissions_examples.html
 */
class TestIAMPolicyVariables {

  private final String host;
  private final AWSCredentialsProvider credentials;

  TestIAMPolicyVariables( ) {
    minimalInit()
    this.host=CLC_IP
    this.credentials = new StaticCredentialsProvider( new BasicAWSCredentials( ACCESS_KEY, SECRET_KEY ) )
  }

  private String cloudUri( String host, String servicePath ) {
    URI.create( "http://${host}:8773/" )
        .resolve( servicePath )
        .toString( )
  }

  private YouAreClient getYouAreClient( final AWSCredentialsProvider clientCredentials = credentials  ) {
    final YouAreClient euare = new YouAreClient( clientCredentials )
    euare.setEndpoint( cloudUri( host, '/services/Euare' ) )
    euare
  }

  @Test
  public void testIAMPolicyVariables( ) throws Exception {
    testInfo(this.getClass().getSimpleName());
    final String namePrefix = UUID.randomUUID().toString().substring(0,8) + "-"
    N4j.print( "Using resource prefix for test: ${namePrefix}" )

    final List<Runnable> cleanupTasks = [] as List<Runnable>
    final String accountName = "${namePrefix}account1"
    final String userName = "${namePrefix}user1"
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
        String accountNumber = getUser( ).with {
          user.getArn( ).split(":")[4]
        }
        N4j.print( "Detected account number ${accountNumber}" )

        cleanupTasks.add{
          N4j.print( "Deleting user ${userName}" )
          deleteUser( new DeleteUserRequest(
              userName: userName
          ) )
        }
        N4j.print( "Creating user ${userName}" )
        createUser( new CreateUserRequest(
            userName: userName,
            path: '/'
        ) )

        String policyName = "${namePrefix}policy1"
        N4j.print( "Creating user policy ${policyName}" )
        putUserPolicy( new PutUserPolicyRequest(
            userName: userName,
            policyName: policyName,
            policyDocument: """\
              {
                "Version": "2012-10-17",
                "Statement": [{
                  "Action": [
                    "iam:*AccessKey*",
                    "iam:*LoginProfile"
                  ],
                  "Effect": "Allow",
                  "Resource": ["arn:aws:iam::${accountNumber}:user/\${aws:username}"]
                }]
              }
              """.stripIndent( )
        ) )
        cleanupTasks.add{
          N4j.print( "Deleting user policy ${policyName}" )
          deleteUserPolicy( new DeleteUserPolicyRequest(
              userName: userName,
              policyName: policyName
          ) )
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

      getYouAreClient( userCredentials ).with {
        N4j.print( "Creating access key using users credentials" )
        String keyId = createAccessKey( new CreateAccessKeyRequest( ) ).with {
          accessKey.accessKeyId
        }
        N4j.print( "Created access key: ${keyId}" )

        N4j.print( "Listing access keys using user credentials" )
        listAccessKeys( ).with {
          N4j.assertThat( !accessKeyMetadata.isEmpty( ), "Expected access key" )
          accessKeyMetadata.each { AccessKeyMetadata key ->
            N4j.print( "Listed access key: ${key.accessKeyId}" )
          }
        }

        N4j.print( "Deleting access key ${keyId} using users credentials" )
        deleteAccessKey( new DeleteAccessKeyRequest(
            accessKeyId: keyId
        ) )

        try {
          N4j.print( "Creating access key for admin using users credentials, should fail" )
          createAccessKey( new CreateAccessKeyRequest( userName: 'admin' ) )
          N4j.assertThat( false, "Expected key creation to fail for admin user due to permissions" )
        } catch ( AmazonServiceException e ) {
          N4j.print( "Expected error creating key without permission: ${e}" )
        }

        N4j.print( "Creating login profile using users credentials" )
        createLoginProfile( new CreateLoginProfileRequest( userName: userName, password: "p@55w0Rd!" ) )

        N4j.print( "Getting login profile using users credentials" )
        getLoginProfile( new GetLoginProfileRequest( userName: userName ) ).with {
          N4j.print( "Login profile create date: ${loginProfile.createDate}" )
        }

        N4j.print( "Updating login profile using users credentials" )
        updateLoginProfile( new UpdateLoginProfileRequest( userName: userName, password: "Upd@T3d_p@55w0Rd" ) )

        N4j.print( "Deleting login profile using users credentials" )
        deleteLoginProfile( new DeleteLoginProfileRequest( userName: userName ) )

        try {
          N4j.print( "Creating login profile for admin using users credentials, should fail" )
          createLoginProfile( new CreateLoginProfileRequest( userName: 'admin', password: "p@55w0Rd!" ) )
          N4j.assertThat( false, "Expected login profile creation to fail for admin user due to permissions" )
        } catch ( AmazonServiceException e ) {
          N4j.print( "Expected error creating login profile without permission: ${e}" )
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
