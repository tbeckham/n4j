package com.eucalyptus.tests.awssdk

import com.amazonaws.AmazonServiceException
import com.amazonaws.auth.AWSCredentials
import com.amazonaws.auth.AWSCredentialsProvider
import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.auth.BasicSessionCredentials
import com.amazonaws.internal.StaticCredentialsProvider
import com.amazonaws.services.ec2.AmazonEC2
import com.amazonaws.services.ec2.AmazonEC2Client
import com.amazonaws.services.ec2.model.CreateSecurityGroupRequest
import com.amazonaws.services.ec2.model.DeleteSecurityGroupRequest
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement
import com.amazonaws.services.identitymanagement.model.*
import com.amazonaws.services.securitytoken.AWSSecurityTokenService
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient
import com.github.sjones4.youcan.youare.YouAre
import com.github.sjones4.youcan.youare.YouAreClient
import org.testng.annotations.Test
import static com.eucalyptus.tests.awssdk.N4j.minimalInit
import static com.eucalyptus.tests.awssdk.N4j.CLC_IP
import static com.eucalyptus.tests.awssdk.N4j.ACCESS_KEY
import static com.eucalyptus.tests.awssdk.N4j.SECRET_KEY

import java.text.SimpleDateFormat

/**
 * Tests functionality for aws:TokenIssueTime and aws:SecureTransport condition keys.
 *
 * This test must be run as a regular user (i.e. non-system) with full permissions.
 *
 * Related issues:
 *   https://eucalyptus.atlassian.net/browse/EUCA-12758
 *
 * Related AWS doc:
 *   http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#AvailableKeys
 *   http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html#policy-vars-infotouse
 *   http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_disable-perms.html#denying-access-to-credentials-creator
 */
class TestSTSConditionKeys {

  public TestSTSConditionKeys( ) {
    minimalInit()
    this.host = CLC_IP
    this.credentials = new StaticCredentialsProvider( new BasicAWSCredentials( ACCESS_KEY, SECRET_KEY ) )
  }

  private final String host
  private final AWSCredentialsProvider credentials

  private String cloudUri( String host, String servicePath ) {
    URI.create( "http://${host}:8773/" )
        .resolve( servicePath )
        .toString( )
  }

  private AmazonIdentityManagement getIamClient( AWSCredentialsProvider credentialsProvider = credentials ) {
    final YouAre youAre = new YouAreClient( credentialsProvider );
    youAre.setEndpoint( cloudUri( host, '/services/Euare' ) );
    youAre
  }

  private AWSSecurityTokenService getStsClient( AWSCredentialsProvider credentialsProvider = credentials ) {
    final AWSSecurityTokenService sts = new AWSSecurityTokenServiceClient( credentialsProvider )
    sts.setEndpoint( cloudUri( host, '/services/Tokens') )
    sts
  }

  private AmazonEC2 getEc2Client( AWSCredentialsProvider credentialsProvider = credentials ) {
    final AmazonEC2 ec2 = new AmazonEC2Client( credentialsProvider )
    ec2.setEndpoint( cloudUri( host, '/services/compute') )
    ec2
  }

  private boolean assertThat( boolean condition,
                              String message ){
    N4j.assertThat( condition, message )
    true
  }

  @Test
  public void test( ) throws Exception {
    N4j.testInfo( TestSTSConditionKeys.simpleName )
    final String namePrefix = UUID.randomUUID().toString().substring(0,8) + "-"
    N4j.print "Using resource prefix for test: ${namePrefix}"

    final List<Runnable> cleanupTasks = [] as List<Runnable>
    try {
      String userName = "${namePrefix}user-1"
      AWSCredentialsProvider userCreds = getIamClient( ).with {
        N4j.print "Creating user ${userName}"
        createUser( new CreateUserRequest(
            path: '/',
            userName: userName
        ) )
        cleanupTasks.add{
          N4j.print "Deleting user ${userName}"
          deleteUser( new DeleteUserRequest( userName: userName ) )
        }
        N4j.print "Putting user policy for secure transport"
        putUserPolicy( new PutUserPolicyRequest(
            userName: userName,
            policyName: 'transport-policy',
            policyDocument: '''\
            {
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": "iam:*",
                  "Resource": "*"
                },
                {
                  "Effect": "Allow",
                  "Action": "ec2:*",
                  "Resource": "*"
                },
                {
                  "Effect": "Deny",
                  "Action": "iam:GetUser",
                  "Resource": "*",
                  "Condition": {
                    "Bool": {
                      "aws:SecureTransport": "false"
                    }
                  }
                },
                {
                  "Effect": "Deny",
                  "Action": "iam:GetUserPolicy",
                  "Resource": "*",
                  "Condition": {
                    "Bool": {
                      "aws:SecureTransport": "true"
                    }
                  }
                }
              ]
            }
            '''.stripIndent( )
        ))
        cleanupTasks.add{
          N4j.print "Deleting user policy for secure transport"
          deleteUserPolicy( new DeleteUserPolicyRequest(
              userName: userName,
              policyName: 'transport-policy'
          ))
        }
        createAccessKey( new CreateAccessKeyRequest(
            userName: userName
        ) ).with {
          accessKey.with {
            cleanupTasks.add{
              N4j.print "Deleting access key ${accessKeyId} for user ${userName}"
              deleteAccessKey( new DeleteAccessKeyRequest( userName: userName, accessKeyId: accessKeyId ) )
            }
            new StaticCredentialsProvider( new BasicAWSCredentials( accessKeyId, secretAccessKey ) )
          }
        }
      }

      int sleepSeconds = 15
      N4j.print "Waiting ${sleepSeconds} seconds for credentials to be recognised"
      sleep sleepSeconds * 1000

      getIamClient( userCreds ).with {
        N4j.print "Verifying access by listing account alias"
        N4j.print listAccountAliases( ).toString( )

        N4j.print "Verifying access denied for incorrect transport security"
        boolean getUserFailed = true
        boolean getUserPolicyFailed = true
        try {
          N4j.print "Getting user"
          N4j.print getUser( new GetUserRequest( userName: userName ) ).toString( )
          getUserFailed = false
        } catch( AmazonServiceException e ) {
          N4j.print e.toString( )
          assertThat( e.statusCode == 403, "Expected status code 403, but was: ${e.statusCode}")
          assertThat( e.errorCode == 'NotAuthorized', "Expected error code NotAuthorized, but was: ${e.errorCode}")
        }
        try {
          N4j.print "Getting user policy"
          N4j.print getUserPolicy( new GetUserPolicyRequest( userName: userName, policyName: 'transport-policy' ) ).toString( )
          getUserPolicyFailed = false
        } catch( AmazonServiceException e ) {
          N4j.print e.toString( )
          assertThat( e.statusCode == 403, "Expected status code 403, but was: ${e.statusCode}")
          assertThat( e.errorCode == 'NotAuthorized', "Expected error code NotAuthorized, but was: ${e.errorCode}")
        }
        assertThat( getUserFailed != getUserPolicyFailed, "Expected one action to fail, but was: ${getUserFailed}/${getUserPolicyFailed}")
      }

      N4j.print "Testing token issue condition using session token"
      AWSCredentialsProvider sessionCredsProvider = new AWSCredentialsProvider( ) {
        AWSCredentials awsCredentials = null

        @Override
        AWSCredentials getCredentials( ) {
          if ( awsCredentials == null ) {
            awsCredentials = (AWSCredentials)getStsClient( userCreds ).with {
              N4j.print "Getting session token"
              getSessionToken( ).with {
                new BasicSessionCredentials(
                    credentials.accessKeyId,
                    credentials.secretAccessKey,
                    credentials.sessionToken )
              }
            }
          }
          awsCredentials
        }

        @Override
        void refresh() {
          awsCredentials = null
        }
      }

      final String groupName = "${namePrefix}security-group-1"
      getEc2Client( sessionCredsProvider ).with {
        N4j.print "Verifying access by listing security groups using session token"
        N4j.print describeSecurityGroups( ).toString( )

        N4j.print "Adding user policy to expire existing session tokens"
        getIamClient( ).with {
          putUserPolicy(new PutUserPolicyRequest(
              userName: userName,
              policyName: 'expiry-policy',
              policyDocument: """\
              {
                "Version": "2012-10-17",
                "Statement": [{
                  "Effect": "Deny",
                  "Action": "*",
                  "Resource": "*",
                  "Condition": {"DateLessThan": {"aws:TokenIssueTime": "${
                  new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").with {
                    timeZone = TimeZone.getTimeZone("UTC"); format(new Date(System.currentTimeMillis()+(10000)))
                  }
                }"}}
                }]
              }
              """.stripIndent()
          ))
          cleanupTasks.add{
            N4j.print "Deleting user policy for token expiry"
            deleteUserPolicy( new DeleteUserPolicyRequest(
                userName: userName,
                policyName: 'expiry-policy'
            ))
          }
        }

        N4j.print "Waiting ${sleepSeconds} seconds for token expiry policy to be in use"
        sleep sleepSeconds * 1000

        cleanupTasks.add{
          N4j.print "Deleting security group ${groupName}"
          deleteSecurityGroup( new DeleteSecurityGroupRequest( groupName: groupName ) )
        }
        try {
          N4j.print "Attempting to create security group ${groupName} using invalidated session token"
          N4j.print createSecurityGroup( new CreateSecurityGroupRequest( groupName: groupName, description: 'Test group' ) ).toString( )
          assertThat( false, 'Expected request failure due to token issue time condition' )
        } catch( AmazonServiceException e ) {
          N4j.print e.toString( )
          assertThat( e.statusCode >= 403, "Expected status code >=403, but was: ${e.statusCode}")
        }

        N4j.print( "Refreshing credentials" )
        sessionCredsProvider.refresh( )

        N4j.print "Verifying create group successful using new session token"
        N4j.print "Creating security group ${groupName} using session token"
        N4j.print createSecurityGroup( new CreateSecurityGroupRequest( groupName: groupName, description: 'Test group' ) ).toString( )

        N4j.print "Deleting security group ${groupName}"
        deleteSecurityGroup( new DeleteSecurityGroupRequest( groupName: groupName ) )
      }

      getEc2Client( userCreds ).with {
        N4j.print "Verifying create group successful using regular user creds"
        N4j.print "Creating security group ${groupName} using regular user creds"
        N4j.print createSecurityGroup( new CreateSecurityGroupRequest( groupName: groupName, description: 'Test group' ) ).toString( )

        N4j.print "Deleting security group ${groupName}"
        deleteSecurityGroup( new DeleteSecurityGroupRequest( groupName: groupName ) )
      }

      N4j.print "Test complete"
    } finally {
      // Attempt to clean up anything we created
      cleanupTasks.reverseEach { Runnable cleanupTask ->
        try {
          cleanupTask.run()
        } catch ( NoSuchEntityException e ) {
          N4j.print "Entity not found during cleanup."
        } catch ( AmazonServiceException e ) {
          N4j.print "Service error during cleanup; code: ${e.errorCode}, message: ${e.message}"
        } catch ( Exception e ) {
          e.printStackTrace()
        }
      }
    }
  }  
}
